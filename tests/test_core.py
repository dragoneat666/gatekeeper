import asyncio
import datetime

from fakes import event, make

from gatekeeper.db import iso, utcnow


def run(coro):
    return asyncio.run(coro)


def ago(**kw):
    return iso(utcnow() - datetime.timedelta(**kw))


SEED = [("203.0.113.10", "seed 2026-10-25 import: alice"),
        ("2001:db8:1:2::/64", "seed 2026-10-25 auth: bob"),
        ("198.51.100.1", "home WAN (pinned) 2026-10-25")]


# --- list sync -----------------------------------------------------------------------------
def test_sync_imports_existing_items_with_kinds_and_seed_dates():
    gk, cf, _ = make(SEED + [("5.6.7.8", "added by hand")])
    res = run(gk.sync_list())
    assert res == {"total": 4, "added": 4, "removed": 0}
    rows = {r["entry"]: r for r in gk.db.active_entries()}
    assert rows["203.0.113.10"]["kind"] == "seed"
    assert rows["203.0.113.10"]["approved_at"] == "2026-10-25T00:00:00Z"
    assert rows["198.51.100.1"]["kind"] == "home"
    assert rows["5.6.7.8"]["kind"] == "manual"
    assert [a["kind"] for a in gk.db.activity_since("2000-01-01T00:00:00Z")] == ["imported"]


def test_sync_marks_entries_deleted_in_dashboard_as_removed():
    gk, cf, _ = make(SEED)
    run(gk.sync_list())
    cf.items = [i for i in cf.items if i["ip"] != "203.0.113.10"]
    assert run(gk.sync_list())["removed"] == 1
    row = gk.db.entry("203.0.113.10")
    assert row["active"] == 0 and row["removed_reason"] == "removed in Cloudflare"


def test_pinned_setting_overrides_kind():
    gk, cf, _ = make(SEED, pinned=["2001:db8:1:2::/64"])
    run(gk.sync_list())
    assert gk.db.entry("2001:db8:1:2::/64")["kind"] == "pinned"


# --- approve / revoke ----------------------------------------------------------------------
def test_approve_ipv6_adds_its_64_with_comment():
    gk, cf, _ = make()
    entry, already = run(gk.approve("2607:fb90:1:2:3:4:5:6", by="admin", label="Alice phone"))
    assert entry == "2607:fb90:1:2::/64" and not already
    item = cf.items[0]
    assert item["ip"] == entry and item["comment"].startswith("approved ") and item["comment"].endswith("by admin: Alice phone")
    row = gk.db.entry(entry)
    assert row["kind"] == "approved" and row["cf_id"] == item["id"] and row["approved_by"] == "admin"


def test_approve_twice_is_a_no_op():
    gk, cf, _ = make()
    run(gk.approve("8.8.8.8", by="x"))
    _, already = run(gk.approve("8.8.8.8", by="x"))
    assert already and len([c for c in cf.calls if c[0] == "add"]) == 1


def test_revoke_deletes_from_cloudflare_by_item_id():
    gk, cf, _ = make(SEED)
    run(gk.sync_list())
    assert run(gk.revoke("203.0.113.10/32", "test")) is True
    assert ("delete", ["id1"]) in cf.calls
    assert not any(i["ip"] == "203.0.113.10" for i in cf.items)
    assert run(gk.revoke("203.0.113.10", "again")) is False


def test_dry_run_records_locally_without_cloudflare_id():
    gk, cf, _ = make()
    cf.dry_run = True
    entry, _ = run(gk.approve("9.9.9.9", by="x"))
    assert gk.db.entry(entry)["cf_id"] is None


# --- expiry --------------------------------------------------------------------------------
def test_expire_removes_only_unused_non_pinned_entries():
    gk, cf, _ = make(SEED, expire_days=60, pinned=["2001:db8:1:2::/64"])
    run(gk.sync_list())
    gk.db.upsert_entry("1.1.1.1", None, "approved", approved_at=ago(days=61))       # stale, never used
    gk.db.upsert_entry("2.2.2.2", None, "approved", approved_at=ago(days=90))
    gk.db.touch("2.2.2.2", ago(days=3))                                            # old but used recently
    gk.db.upsert_entry("3.3.3.3", None, "home", approved_at=ago(days=400))          # home never expires
    gk.db.conn.execute("update allowlist set approved_at=? where entry like '%:%'", (ago(days=200),))
    gone = run(gk.expire())
    assert gone == ["1.1.1.1"]
    assert gk.db.entry("2001:db8:1:2::/64")["active"] == 1


def test_seed_entries_get_the_full_60_days_from_seed_date():
    gk, cf, _ = make([("4.4.4.4", f"seed {utcnow():%Y-%m-%d} import: x")])
    run(gk.sync_list())
    assert run(gk.expire()) == []


# --- home IP -------------------------------------------------------------------------------
def test_home_ip_change_adds_new_before_removing_old_and_alerts():
    gk, cf, n = make(SEED)
    run(gk.sync_list())
    assert run(gk.check_home_ip()) is None            # unchanged: nothing to do
    cf.ip = "198.51.100.9"
    assert run(gk.check_home_ip()) == "198.51.100.9"
    writes = [c for c in cf.calls if c[0] in ("add", "delete")]
    assert writes[0] == ("add", ["198.51.100.9"]) and writes[1][0] == "delete"
    assert gk.db.entry("198.51.100.9")["kind"] == "home"
    assert gk.db.entry("198.51.100.1")["active"] == 0
    assert n.alerts and "198.51.100.9" in n.alerts[0][1]


def test_home_ip_already_listed_as_seed_is_just_pinned():
    gk, cf, _ = make([("50.50.50.50", "seed 2026-10-25 import: x")])
    cf.ip = "50.50.50.50"
    run(gk.sync_list())
    run(gk.check_home_ip())
    assert gk.db.entry("50.50.50.50")["kind"] == "home"
    assert not [c for c in cf.calls if c[0] == "add"]


# --- events and alerts ---------------------------------------------------------------------
def test_poll_stores_new_events_once_and_overlaps_previous_window():
    gk, cf, _ = make()
    cf.events = [event("6.6.6.6", ago(minutes=2)), event("2607:fb90::1", ago(minutes=1))]
    new = run(gk.poll_events())
    assert len(new) == 2 and {e["entry"] for e in new} == {"6.6.6.6", "2607:fb90::/64"}
    assert run(gk.poll_events()) == []                 # same events again: deduped by Ray ID
    first_until = cf.calls[0][2]
    second_since = cf.calls[1][1]
    assert second_since < first_until                  # late-arriving events are re-read


def test_login_probing_on_real_hostname_alerts_once_per_cooldown():
    gk, cf, n = make(protected_hosts=["auth.example.com", "jellyfin.example.com"], alert_login_hits=3)
    cf.events = [event("6.6.6.6", ago(minutes=m), host="auth.example.com", path="/if/flow/default-authentication-flow/")
                 for m in (1, 2, 3)]
    new = run(gk.poll_events())
    assert run(gk.detect(new)) == ["6.6.6.6"]
    assert "login probing" in n.alerts[0][0]
    cf.events.append(event("6.6.6.6", ago(minutes=0), host="auth.example.com", path="/if/flow/x/"))
    assert run(gk.detect(run(gk.poll_events()))) == []   # cooldown


def test_scanner_noise_on_unknown_hosts_does_not_alert():
    gk, cf, n = make(protected_hosts=["jellyfin.example.com"], alert_host_hits=5)
    cf.events = [event("7.7.7.7", ago(minutes=1), host="example.com", path=f"/wp-login.php?{i}", ray=f"r{i}")
                 for i in range(30)]
    assert run(gk.detect(run(gk.poll_events()))) == []
    assert n.alerts == []


def test_many_hits_on_real_hostname_alerts():
    gk, cf, n = make(protected_hosts=["jellyfin.example.com"], alert_host_hits=5)
    cf.events = [event("8.8.4.4", ago(minutes=1), path=f"/web/{i}", ray=f"r{i}") for i in range(6)]
    assert run(gk.detect(run(gk.poll_events()))) == ["8.8.4.4"]
    assert "hostname probing" in n.alerts[0][0]


# --- last seen -----------------------------------------------------------------------------
def test_last_seen_matches_ipv6_clients_to_their_64():
    gk, cf, _ = make(SEED)
    run(gk.sync_list())
    cf.requests = {"2001:db8:1:2:aaaa:bbbb::1": 39, "203.0.113.10": 4, "203.0.113.9": 100}
    assert run(gk.update_last_seen()) == 2
    assert gk.db.entry("2001:db8:1:2::/64")["last_seen"] is not None
    assert gk.db.entry("198.51.100.1")["last_seen"] is None
    assert gk.db.entry("203.0.113.9") is None


def test_summary_mentions_blocks_alerts_and_approvals():
    gk, cf, _ = make(SEED)
    run(gk.sync_list())
    cf.events = [event("6.6.6.6", ago(minutes=5))]
    run(gk.poll_events())
    run(gk.approve("9.9.9.9", by="admin"))
    text = gk.summary_text()
    assert "Blocked requests: **1**" in text and "6.6.6.6" in text and "Approved: `9.9.9.9`" in text
    assert "Allowlist: 4 entries" in text


# --- /letmein ------------------------------------------------------------------------------
from gatekeeper.core import parse_ray


def test_parse_ray_accepts_the_forms_people_paste():
    assert parse_ray("8f2a1b3c4d5e6f70") == "8f2a1b3c4d5e6f70"
    assert parse_ray("Cloudflare Ray ID: 8F2A1B3C4D5E6F70") == "8f2a1b3c4d5e6f70"
    assert parse_ray("8f2a1b3c4d5e6f70-ORD") == "8f2a1b3c4d5e6f70"
    assert parse_ray("hello") is None and parse_ray("8f2a1b3c") is None


def test_letmein_by_ray_id_approves_that_requests_ipv6_64():
    gk, cf, _ = make()
    cf.events = [event("2001:db8:5:6:7:8:9:10", ago(minutes=4), ray="8f2a1b3c4d5e6f70")]
    status, entry = run(gk.letmein(" Ray ID: 8f2a1b3c4d5e6f70-ORD ", user_id=111, user_name="alice"))
    assert (status, entry) == ("approved", "2001:db8:5:6::/64")
    row = gk.db.entry(entry)
    assert row["kind"] == "member" and row["approved_by"] == "alice" and row["approved_by_id"] == "111"
    assert run(gk.letmein("8f2a1b3c4d5e6f70", 111, "alice"))[0] == "already"


def test_letmein_by_ip_needs_a_recent_block_from_it():
    gk, cf, _ = make()
    cf.events = [event("203.0.113.50", ago(minutes=10))]
    assert run(gk.letmein("203.0.113.51", 1, "bob")) == ("not_found", "203.0.113.51")
    assert run(gk.letmein("203.0.113.50", 1, "bob")) == ("approved", "203.0.113.50")
    cf.events = [event("2001:db8:9:9::1", ago(minutes=5))]
    assert run(gk.letmein("2001:db8:9:9:abcd::2", 1, "bob")) == ("approved", "2001:db8:9:9::/64")


def test_letmein_ignores_blocks_older_than_the_lookback():
    gk, cf, _ = make(letmein_lookback_hours=24)
    old = event("203.0.113.60", ago(hours=30), ray="aaaaaaaaaaaaaaaa")
    gk.db.add_events([gk._to_event(old)])
    assert run(gk.letmein("aaaaaaaaaaaaaaaa", 1, "x"))[0] == "not_found"
    assert run(gk.letmein("203.0.113.60", 1, "x"))[0] == "not_found"


def test_letmein_limit_per_member_but_not_for_admins():
    gk, cf, _ = make(letmein_max_active=2)
    cf.events = [event(f"203.0.113.{i}", ago(minutes=5)) for i in (1, 2, 3)]
    assert run(gk.letmein("203.0.113.1", 7, "carol"))[0] == "approved"
    assert run(gk.letmein("203.0.113.2", 7, "carol"))[0] == "approved"
    assert run(gk.letmein("203.0.113.3", 7, "carol")) == ("limit", "203.0.113.3")
    assert run(gk.letmein("203.0.113.3", 8, "dave"))[0] == "approved"          # limits are per member
    run(gk.revoke("203.0.113.1", "test"))
    cf.events.append(event("203.0.113.4", ago(minutes=1)))
    assert run(gk.letmein("203.0.113.4", 7, "carol"))[0] == "approved"         # revoked ones free a slot
    cf.events.append(event("203.0.113.5", ago(minutes=1)))
    assert run(gk.letmein("203.0.113.5", 7, "carol", is_admin=True))[0] == "approved"


def test_letmein_rejects_junk():
    gk, _, _ = make()
    assert run(gk.letmein("please let me in", 1, "x")) == ("invalid", None)


def test_existing_database_gets_new_column(tmp_path):
    import sqlite3
    from gatekeeper.db import DB
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.executescript("""create table allowlist (entry text primary key, cf_id text, kind text not null,
        label text default '', approved_by text default '', approved_at text, last_seen text,
        active integer not null default 1, removed_at text, removed_reason text);
        insert into allowlist(entry, kind, approved_at) values('203.0.113.9', 'seed', '2026-10-25T00:00:00Z');""")
    old.commit(); old.close()
    db = DB(path)
    assert db.entry("203.0.113.9")["approved_by_id"] == ""
    assert db.count_active_by("1", "member") == 0


def test_letmein_is_unlimited_by_default_and_labels_nickname():
    gk, cf, _ = make()
    cf.events = [event(f"203.0.113.{i}", ago(minutes=5)) for i in range(1, 6)]
    for i in range(1, 6):
        assert run(gk.letmein(f"203.0.113.{i}", 7, "carol_99", nickname="Carol (Smith family)"))[0] == "approved"
    row = gk.db.entry("203.0.113.1")
    assert row["approved_by"] == "carol_99" and row["label"] == "via /letmein (Carol (Smith family))"
