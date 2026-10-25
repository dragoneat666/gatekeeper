"""The gatekeeper's jobs. Cloudflare's list decides who gets in; SQLite remembers why and when."""
import datetime
import logging
import re

from . import ipnet
from .db import PINNED_KINDS, iso, parse, utcnow

log = logging.getLogger("gatekeeper")

# Cloudflare events can show up in GraphQL a few minutes after they happen, stamped with their
# original time. Each poll re-reads this much of the previous window; Ray IDs drop the duplicates.
EVENT_OVERLAP = datetime.timedelta(minutes=15)
# Request analytics lag a little too, so last-seen windows stop this far before "now".
REQUEST_LAG = datetime.timedelta(minutes=5)

# A Ray ID is 16 hex characters. Block pages and headers may add a data-center suffix ("-ORD")
# or a label ("Cloudflare Ray ID: ..."), so search for the hex part.
RAY_RE = re.compile(r"\b([0-9a-f]{16})(?:-[a-z]{3})?\b", re.IGNORECASE)


def parse_ray(text):
    m = RAY_RE.search(text or "")
    return m.group(1).lower() if m else None


class Gatekeeper:
    def __init__(self, settings, db, cf, notifier):
        self.s = settings
        self.db = db
        self.cf = cf
        self.notify = notifier
        self.login_re = re.compile(settings.login_paths)
        self.pinned = {ipnet.normalize_entry(p) for p in settings.pinned}

    # --- list sync ---------------------------------------------------------------------------
    def _kind_from_comment(self, entry, comment):
        if entry in self.pinned:
            return "pinned"
        c = (comment or "").lower()
        if c.startswith("home wan"):
            return "home"
        if c.startswith("seed"):
            return "seed"
        if c.startswith("approved"):
            return "approved"
        return "manual"

    @staticmethod
    def _date_from_comment(comment):
        m = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", comment or "")
        return f"{m.group(1)}T00:00:00Z" if m else None

    async def sync_list(self):
        """Make SQLite agree with Cloudflare's list (entries added or removed in the dashboard count too)."""
        items = await self.cf.list_items()
        in_cf = {}
        for it in items:
            in_cf[ipnet.normalize_entry(it["ip"])] = it
        added = removed = 0
        for entry, it in in_cf.items():
            row = self.db.entry(entry)
            if row is None or not row["active"]:
                kind = self._kind_from_comment(entry, it["comment"])
                self.db.upsert_entry(entry, it["id"], kind, label=it["comment"] or "",
                                     approved_by="cloudflare", approved_at=self._date_from_comment(it["comment"]))
                if row is not None or kind == "manual":
                    self.db.log("imported", entry, it["comment"] or "")
                added += 1
            else:
                if row["cf_id"] != it["id"]:
                    self.db.set_cf_id(entry, it["id"])
                if entry in self.pinned and row["kind"] != "pinned":
                    self.db.set_kind(entry, "pinned")
        for row in self.db.active_entries():
            if row["entry"] not in in_cf:
                self.db.mark_removed(row["entry"], "removed in Cloudflare")
                self.db.log("removed", row["entry"], "removed in Cloudflare")
                removed += 1
        log.info("list sync: %d items in Cloudflare, %d new here, %d gone", len(in_cf), added, removed)
        return {"total": len(in_cf), "added": added, "removed": removed}

    async def _find_item_id(self, entry):
        for it in await self.cf.list_items():
            if ipnet.normalize_entry(it["ip"]) == entry:
                return it["id"]
        return None

    # --- approve / revoke --------------------------------------------------------------------
    async def letmein(self, query, user_id, user_name, is_admin=False, nickname=""):
        """Self-service approval from a Ray ID or IP that Cloudflare actually blocked recently.

        Returns (status, entry): status is 'approved', 'already', 'not_found', 'limit' or 'invalid'.
        """
        try:
            await self.poll_events()  # pick up blocks that happened since the last scheduled poll
        except Exception:
            log.exception("poll before /letmein failed; using stored events")
        since = iso(utcnow() - datetime.timedelta(hours=self.s.letmein_lookback_hours))
        q = (query or "").strip()
        try:
            entry = ipnet.entry_for(q, self.s.ipv6_prefix)
            ev = self.db.latest_event_for(entry, since)
        except ValueError:
            ray = parse_ray(q)
            if not ray:
                return "invalid", None
            ev = self.db.event_by_ray(ray)
            if ev is not None and ev["ts"] < since:
                ev = None
            entry = ev["entry"] if ev is not None else None
        if ev is None:
            return "not_found", entry
        row = self.db.entry(entry)
        if row is not None and row["active"]:
            return "already", entry
        limit = self.s.letmein_max_active
        if limit and not is_admin and self.db.count_active_by(str(user_id), "member") >= limit:
            return "limit", entry
        label = f"via /letmein ({nickname})" if nickname and nickname != user_name else "via /letmein"
        await self.approve(entry, by=user_name, label=label, kind="member", by_id=str(user_id))
        return "approved", entry

    async def approve(self, ip_or_entry, by, label="", kind="approved", by_id=""):
        """Add an IP (IPv6 is widened to its /64) to the list. Returns (entry, already_present)."""
        raw = ip_or_entry.strip()
        entry = ipnet.normalize_entry(raw) if "/" in raw else ipnet.entry_for(raw, self.s.ipv6_prefix)
        row = self.db.entry(entry)
        if row is not None and row["active"]:
            return entry, True
        today = utcnow().strftime("%Y-%m-%d")
        comment = f"approved {today} by {by}" + (f": {label}" if label else "")
        if kind == "home":
            comment = f"home WAN (pinned) {today}"
        await self.cf.add_items([{"ip": entry, "comment": comment[:500]}])
        cf_id = None if self.cf.dry_run else await self._find_item_id(entry)
        self.db.upsert_entry(entry, cf_id, kind, label=label, approved_by=by, approved_by_id=by_id)
        self.db.log("approved" if kind != "home" else "home_added", entry, comment)
        log.info("approved %s (%s)", entry, comment)
        return entry, False

    async def revoke(self, entry, reason):
        entry = ipnet.normalize_entry(entry)
        row = self.db.entry(entry)
        if row is None or not row["active"]:
            return False
        cf_id = row["cf_id"] or await self._find_item_id(entry)
        if cf_id:
            await self.cf.delete_items([cf_id])
        self.db.mark_removed(entry, reason)
        self.db.log("removed", entry, reason)
        log.info("removed %s (%s)", entry, reason)
        return True

    # --- expiry ------------------------------------------------------------------------------
    async def expire(self):
        """Remove entries unused for expire_days. Pinned and home entries never expire."""
        cutoff = iso(utcnow() - datetime.timedelta(days=self.s.expire_days))
        gone = []
        for row in self.db.expired_entries(cutoff):
            if row["entry"] in self.pinned:
                continue
            if await self.revoke(row["entry"], f"unused for {self.s.expire_days} days"):
                gone.append(row["entry"])
        return gone

    # --- home IP -----------------------------------------------------------------------------
    async def check_home_ip(self):
        """Keep this server's public IP on the list. Adds the new IP before removing the old one."""
        ip = await self.cf.public_ip()
        entry = ipnet.entry_for(ip, self.s.ipv6_prefix)
        homes = [r for r in self.db.active_entries() if r["kind"] == "home"]
        if any(r["entry"] == entry for r in homes):
            return None
        row = self.db.entry(entry)
        if row is not None and row["active"]:
            self.db.set_kind(entry, "home")  # already listed (e.g. as a seed): just pin it
        else:
            await self.approve(entry, by="gatekeeper", kind="home")
        for r in homes:
            await self.revoke(r["entry"], f"home IP changed to {entry}")
        self.db.log("home_changed", entry, "was " + ", ".join(r["entry"] for r in homes) if homes else "first seen")
        if homes:
            await self.notify.alert("Home IP changed", f"New home IP {entry} added to the allowlist; "
                                    f"removed {', '.join(r['entry'] for r in homes)}.", priority=3, tags="house")
        return entry

    # --- blocked events ----------------------------------------------------------------------
    def _to_event(self, e):
        try:
            entry = ipnet.entry_for(e["clientIP"], self.s.ipv6_prefix)
        except ValueError:
            entry = e["clientIP"]
        return {
            "ray": e["rayName"], "ts": e["datetime"], "action": e["action"], "source": e.get("source"),
            "ip": e["clientIP"], "entry": entry, "host": (e.get("clientRequestHTTPHost") or "").lower(),
            "path": e.get("clientRequestPath") or "", "method": e.get("clientRequestHTTPMethodName"),
            "status": e.get("edgeResponseStatus"), "country": e.get("clientCountryName"),
            "asn": str(e.get("clientAsn") or ""), "asn_name": e.get("clientASNDescription") or "",
            "ua": (e.get("userAgent") or "")[:300], "rule_id": e.get("ruleId"),
        }

    async def poll_events(self):
        """Fetch new blocked events into SQLite. Returns the newly stored events."""
        now = utcnow()
        cursor = self.db.get_state("events_cursor")
        since = parse(cursor) - EVENT_OVERLAP if cursor else now - datetime.timedelta(hours=24)
        raw = await self.cf.blocked_events(iso(since), iso(now))
        events = [self._to_event(e) for e in raw]
        known = {r["ray"] for r in self.db.conn.execute(
            "select ray from events where ts >= ?", (iso(since),))}
        new = [e for e in events if e["ray"] not in known]
        self.db.add_events(new)
        self.db.set_state("events_cursor", iso(now))
        if new:
            log.info("stored %d new blocked events", len(new))
        return new

    # --- alerts ------------------------------------------------------------------------------
    def _is_real_host(self, host):
        return not self.s.protected_hosts or host in self.s.protected_hosts

    def assess(self, entry):
        """Score one entry's recent blocked traffic. Returns (reason, detail) or None."""
        since = iso(utcnow() - datetime.timedelta(minutes=self.s.alert_window_minutes))
        evs = self.db.events_for(entry, since)
        real = [e for e in evs if self._is_real_host(e["host"])]
        logins = [e for e in real if self.login_re.search(e["path"] or "")]
        hosts = sorted({e["host"] for e in real})
        where = evs[-1] if evs else None
        place = f"{where['country']} / {where['asn_name'] or 'AS' + where['asn']}" if where else ""
        if len(logins) >= self.s.alert_login_hits:
            paths = sorted({e["path"] for e in logins})[:5]
            return "login probing", (f"{entry} ({place}) hit login paths {len(logins)}x in "
                                     f"{self.s.alert_window_minutes} min on {', '.join(hosts)}: {', '.join(paths)}")
        if len(real) >= self.s.alert_host_hits:
            return "hostname probing", (f"{entry} ({place}) made {len(real)} blocked requests in "
                                        f"{self.s.alert_window_minutes} min to {', '.join(hosts)}")
        return None

    async def detect(self, new_events):
        """Alert (ntfy) on targeted probing by entries that just showed up. Cooldown per entry."""
        sent = []
        cooldown = iso(utcnow() - datetime.timedelta(hours=self.s.alert_cooldown_hours))
        for entry in sorted({e["entry"] for e in new_events}):
            verdict = self.assess(entry)
            if not verdict:
                continue
            last = self.db.last_alert(entry)
            if last and last >= cooldown:
                continue
            reason, detail = verdict
            self.db.add_alert(entry, reason, detail)
            await self.notify.alert(f"Gatekeeper: {reason}", detail, priority=4, tags="warning")
            sent.append(entry)
        return sent

    # --- last seen ---------------------------------------------------------------------------
    async def update_last_seen(self):
        """Mark allowlist entries as used if Cloudflare saw requests from them since the last run."""
        until = utcnow() - REQUEST_LAG
        cursor = self.db.get_state("lastseen_cursor")
        since = parse(cursor) if cursor else until - datetime.timedelta(seconds=self.s.lastseen_seconds)
        if since >= until:
            return 0
        counts = await self.cf.requests_by_ip(iso(since), iso(until))
        matcher = ipnet.EntryMatcher([r["entry"] for r in self.db.active_entries()])
        touched = set()
        for ip in counts:
            entry = matcher.match(ip)
            if entry:
                self.db.touch(entry, iso(until))
                touched.add(entry)
        self.db.set_state("lastseen_cursor", iso(until))
        log.info("last seen: %d client IPs, %d allowlist entries used", len(counts), len(touched))
        return len(touched)

    # --- daily summary -----------------------------------------------------------------------
    def summary_text(self, hours=24):
        since = iso(utcnow() - datetime.timedelta(hours=hours))
        top = self.db.blocked_summary(since, limit=8)
        total = self.db.count_events(since)
        alerts = self.db.alerts_since(since)
        acts = self.db.activity_since(since)
        active = self.db.active_entries()
        kinds = {}
        for r in active:
            kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
        lines = [f"**Gatekeeper - last {hours}h**",
                 f"Blocked requests: **{total}** from **{len(self.db.blocked_summary(since, limit=100000))}** IPs/networks"]
        if top:
            lines.append("Top blocked:")
            for r in top:
                lines.append(f"- `{r['entry']}` {r['hits']}x - {r['country'] or '?'} {r['asn_name'] or ''} - "
                             f"{(r['hosts'] or '')[:80]}")
        lines.append(f"Probing alerts sent: {len(alerts)}")
        for a in alerts:
            lines.append(f"- {a['reason']}: {a['detail'][:150]}")
        for kind, label in (("approved", "Approved"), ("removed", "Removed"), ("imported", "Added in Cloudflare"),
                            ("home_changed", "Home IP change")):
            items = [a for a in acts if a["kind"] == kind]
            if items:
                lines.append(f"{label}: " + ", ".join(f"`{a['entry']}` ({a['detail'][:60]})" for a in items))
        lines.append(f"Allowlist: {len(active)} entries ("
                     + ", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) + ") of 10,000")
        return "\n".join(lines)

    def is_pinned(self, row):
        return row["kind"] in PINNED_KINDS or row["entry"] in self.pinned
