"""SQLite storage. All timestamps are UTC ISO strings ('2026-10-25T14:16:55Z'), so they sort as text."""
import datetime
import os
import sqlite3

SCHEMA = """
create table if not exists events (
  ray text primary key, ts text not null, action text, source text, ip text, entry text,
  host text, path text, method text, status integer, country text, asn text, asn_name text,
  ua text, rule_id text
);
create index if not exists events_ts on events(ts);
create index if not exists events_entry on events(entry, ts);

create table if not exists allowlist (
  entry text primary key, cf_id text, kind text not null, label text default '',
  approved_by text default '', approved_at text, last_seen text,
  active integer not null default 1, removed_at text, removed_reason text
);

create table if not exists alerts (
  id integer primary key, ts text not null, entry text, reason text, detail text
);

create table if not exists activity (
  id integer primary key, ts text not null, kind text not null, entry text, detail text
);

create table if not exists state (key text primary key, value text);
"""

# Kinds that are never removed by expiry
PINNED_KINDS = ("home", "pinned")


def iso(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(s: str) -> datetime.datetime:
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


class DB:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("pragma journal_mode=wal")
        self.conn.executescript(SCHEMA)

    # --- state -------------------------------------------------------------------------------
    def get_state(self, key, default=None):
        row = self.conn.execute("select value from state where key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_state(self, key, value):
        with self.conn:
            self.conn.execute("insert into state(key, value) values(?, ?) "
                              "on conflict(key) do update set value=excluded.value", (key, value))

    # --- events ------------------------------------------------------------------------------
    def add_events(self, events) -> int:
        """Insert events, skipping ones already stored (same Ray ID). Returns how many were new."""
        cols = ("ray", "ts", "action", "source", "ip", "entry", "host", "path", "method", "status",
                "country", "asn", "asn_name", "ua", "rule_id")
        before = self.conn.total_changes
        with self.conn:
            self.conn.executemany(
                f"insert or ignore into events({','.join(cols)}) values({','.join('?' * len(cols))})",
                [tuple(e.get(c) for c in cols) for e in events])
        return self.conn.total_changes - before

    def blocked_summary(self, since: str, limit: int = 25):
        """Blocked traffic grouped by entry (IPv4 address or IPv6 /64), busiest first."""
        return self.conn.execute(
            """select entry, count(*) hits, min(ts) first, max(ts) last,
                      group_concat(distinct host) hosts, max(country) country, max(asn_name) asn_name,
                      max(asn) asn, count(distinct path) paths
               from events where ts >= ? and action = 'block'
               group by entry order by hits desc, last desc limit ?""", (since, limit)).fetchall()

    def events_for(self, entry: str, since: str):
        return self.conn.execute("select * from events where entry=? and ts>=? order by ts",
                                 (entry, since)).fetchall()

    def recent_events(self, limit=100):
        return self.conn.execute("select * from events order by ts desc limit ?", (limit,)).fetchall()

    def count_events(self, since: str) -> int:
        return self.conn.execute("select count(*) from events where ts>=?", (since,)).fetchone()[0]

    def prune_events(self, before: str) -> int:
        with self.conn:
            return self.conn.execute("delete from events where ts < ?", (before,)).rowcount

    # --- allowlist ---------------------------------------------------------------------------
    def entry(self, entry: str):
        return self.conn.execute("select * from allowlist where entry=?", (entry,)).fetchone()

    def active_entries(self):
        return self.conn.execute("select * from allowlist where active=1 order by entry").fetchall()

    def upsert_entry(self, entry, cf_id, kind, label="", approved_by="", approved_at=None):
        approved_at = approved_at or iso(utcnow())
        with self.conn:
            self.conn.execute(
                """insert into allowlist(entry, cf_id, kind, label, approved_by, approved_at, active)
                   values(?, ?, ?, ?, ?, ?, 1)
                   on conflict(entry) do update set cf_id=excluded.cf_id, kind=excluded.kind,
                     label=excluded.label, approved_by=excluded.approved_by,
                     approved_at=excluded.approved_at, last_seen=null, active=1,
                     removed_at=null, removed_reason=null""",
                (entry, cf_id, kind, label, approved_by, approved_at))

    def set_cf_id(self, entry, cf_id):
        with self.conn:
            self.conn.execute("update allowlist set cf_id=? where entry=?", (cf_id, entry))

    def set_kind(self, entry, kind):
        with self.conn:
            self.conn.execute("update allowlist set kind=? where entry=?", (kind, entry))

    def mark_removed(self, entry, reason):
        with self.conn:
            self.conn.execute("update allowlist set active=0, removed_at=?, removed_reason=? where entry=?",
                              (iso(utcnow()), reason, entry))

    def touch(self, entry, when: str):
        """Record that an entry was used, keeping the latest time."""
        with self.conn:
            self.conn.execute("update allowlist set last_seen=? where entry=? and (last_seen is null or last_seen<?)",
                              (when, entry, when))

    def expired_entries(self, cutoff: str):
        """Active, non-pinned entries not used (or approved) since cutoff."""
        marks = ",".join("?" * len(PINNED_KINDS))
        return self.conn.execute(
            f"""select * from allowlist where active=1 and kind not in ({marks})
                and coalesce(last_seen, approved_at) < ?""", (*PINNED_KINDS, cutoff)).fetchall()

    # --- alerts / activity -------------------------------------------------------------------
    def add_alert(self, entry, reason, detail):
        with self.conn:
            self.conn.execute("insert into alerts(ts, entry, reason, detail) values(?, ?, ?, ?)",
                              (iso(utcnow()), entry, reason, detail))

    def last_alert(self, entry):
        row = self.conn.execute("select max(ts) from alerts where entry=?", (entry,)).fetchone()
        return row[0]

    def alerts_since(self, since):
        return self.conn.execute("select * from alerts where ts>=? order by ts", (since,)).fetchall()

    def log(self, kind, entry="", detail=""):
        with self.conn:
            self.conn.execute("insert into activity(ts, kind, entry, detail) values(?, ?, ?, ?)",
                              (iso(utcnow()), kind, entry, detail))

    def activity_since(self, since):
        return self.conn.execute("select * from activity where ts>=? order by ts", (since,)).fetchall()
