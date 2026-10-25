"""Dashboard (basic auth): blocked traffic, alerts, and the allowlist. Removing is the only action here; approvals happen in Discord."""
import base64
import datetime
import hmac
import secrets
from html import escape
from urllib.parse import urlencode

from aiohttp import web

from .db import iso, parse, utcnow

CSS = """
:root { --bg:#f7f7f5; --fg:#1d1d1b; --muted:#6b6b66; --card:#fff; --line:#e3e3de; --accent:#2f6f4f; --warn:#a4462b; }
@media (prefers-color-scheme: dark) { :root { --bg:#161615; --fg:#ebebe6; --muted:#9a9a93; --card:#1f1f1d; --line:#33332f; --accent:#7cc39b; --warn:#e58b6f; } }
* { box-sizing:border-box } body { margin:0; font:14px/1.45 system-ui,sans-serif; background:var(--bg); color:var(--fg) }
header { padding:14px 16px; border-bottom:1px solid var(--line); display:flex; gap:16px; align-items:baseline; flex-wrap:wrap }
header b { font-size:16px } nav a { color:var(--accent); margin-right:12px; text-decoration:none }
main { padding:16px; max-width:1200px } .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:10px; margin-bottom:18px }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px 12px } .card .n { font-size:22px; font-weight:600 }
.muted { color:var(--muted) } h2 { font-size:15px; margin:18px 0 8px } .warn { color:var(--warn) }
.wrap { overflow-x:auto } table { border-collapse:collapse; width:100%; background:var(--card); border:1px solid var(--line) }
th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); white-space:nowrap; font-variant-numeric:tabular-nums }
td.wide { white-space:normal; min-width:220px } code { font-size:12.5px }
form { margin:0 } button { font:inherit; padding:3px 10px; border:1px solid var(--warn); color:var(--warn); background:transparent; border-radius:5px; cursor:pointer }
button:hover { background:var(--warn); color:var(--card) } .notice { padding:8px 12px; border:1px solid var(--line); background:var(--card); border-radius:6px }
"""


def _local(ts):
    return parse(ts).astimezone().strftime("%Y-%m-%d %H:%M") if ts else "-"


def _page(title, body):
    return web.Response(content_type="text/html", text=f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(title)}</title><style>{CSS}</style></head>
<body><header><b>Gatekeeper</b><nav><a href="/">Overview</a><a href="/allowlist">Allowlist</a>
<a href="/events">Events</a></nav></header><main>{body}</main></body></html>""")


def _table(headers, rows):
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    return f"<div class='wrap'><table><tr>{head}</tr>{''.join(rows) or '<tr><td>None</td></tr>'}</table></div>"


def build_app(gk, settings):
    # Per-process token for the Remove form, so another site can't submit it using the browser's saved login
    csrf_token = secrets.token_urlsafe(24)

    @web.middleware
    async def auth(request, handler):
        if request.path == "/healthz":
            return await handler(request)
        expected = base64.b64encode(f"{settings.dashboard_user}:{settings.dashboard_password}".encode()).decode()
        got = request.headers.get("Authorization", "").removeprefix("Basic ").strip()
        if not settings.dashboard_password or not hmac.compare_digest(got, expected):
            return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="gatekeeper"'})
        return await handler(request)

    async def overview(request):
        db = gk.db
        day = iso(utcnow() - datetime.timedelta(hours=24))
        week = iso(utcnow() - datetime.timedelta(days=7))
        active = db.active_entries()
        cutoff = utcnow() - datetime.timedelta(days=settings.expire_days - 7)
        soon = [r for r in active if not gk.is_pinned(r) and parse(r["last_seen"] or r["approved_at"]) < cutoff]
        cards = [("Blocked, 24h", db.count_events(day)), ("Blocked, 7 days", db.count_events(week)),
                 ("Allowlist entries", f"{len(active)} / 10,000"), ("Expiring within 7 days", len(soon)),
                 ("Alerts, 7 days", len(db.alerts_since(week)))]
        html = "<div class='cards'>" + "".join(
            f"<div class='card'><div class='muted'>{escape(k)}</div><div class='n'>{escape(str(v))}</div></div>"
            for k, v in cards) + "</div>"
        rows = [f"<tr><td><code>{escape(r['entry'])}</code></td><td>{r['hits']}</td><td>{escape(r['country'] or '')}</td>"
                f"<td>{escape(r['asn_name'] or '')}</td><td class='wide'>{escape((r['hosts'] or '').replace(',', ', '))}</td>"
                f"<td>{_local(r['last'])}</td></tr>" for r in db.blocked_summary(day, 25)]
        html += "<h2>Top blocked, last 24 hours</h2>" + _table(["Entry", "Hits", "Country", "Network", "Hosts", "Last"], rows)
        rows = [f"<tr><td>{_local(a['ts'])}</td><td class='warn'>{escape(a['reason'])}</td>"
                f"<td class='wide'>{escape(a['detail'])}</td></tr>" for a in reversed(db.alerts_since(week))]
        html += "<h2>Alerts, last 7 days</h2>" + _table(["When", "Reason", "Detail"], rows)
        rows = [f"<tr><td>{_local(a['ts'])}</td><td>{escape(a['kind'])}</td><td><code>{escape(a['entry'] or '')}</code></td>"
                f"<td class='wide'>{escape(a['detail'] or '')}</td></tr>" for a in reversed(db.activity_since(week))]
        html += "<h2>Allowlist changes, last 7 days</h2>" + _table(["When", "What", "Entry", "Detail"], rows)
        return _page("Gatekeeper", html)

    async def allowlist(request):
        now = utcnow()
        rows = []
        for r in sorted(gk.db.active_entries(), key=lambda r: r["last_seen"] or r["approved_at"] or "", reverse=True):
            if gk.is_pinned(r):
                expires, action = "never (pinned)", "<span class='muted'>pinned</span>"
            else:
                exp = parse(r["last_seen"] or r["approved_at"]) + datetime.timedelta(days=settings.expire_days)
                expires = f"{exp.astimezone():%Y-%m-%d} ({(exp - now).days} d)"
                action = (f"<form method='post' action='/allowlist/remove' "
                          f"onsubmit=\"return confirm('Remove {escape(r['entry'])} from the allowlist?')\">"
                          f"<input type='hidden' name='entry' value='{escape(r['entry'])}'>"
                          f"<input type='hidden' name='token' value='{csrf_token}'>"
                          f"<button type='submit'>Remove</button></form>")
            rows.append(f"<tr><td><code>{escape(r['entry'])}</code></td><td>{escape(r['kind'])}</td>"
                        f"<td class='wide'>{escape(r['label'] or '')}</td><td>{escape(r['approved_by'] or '')}</td>"
                        f"<td>{_local(r['approved_at'])}</td><td>{_local(r['last_seen'])}</td><td>{expires}</td>"
                        f"<td>{action}</td></tr>")
        notice = request.query.get("msg", "")
        notice = f"<p class='notice'>{escape(notice)}</p>" if notice else ""
        return _page("Allowlist", f"<h2>Allowlist ({len(rows)})</h2>{notice}" + _table(
            ["Entry", "Kind", "Label / comment", "By", "Approved", "Last used", "Expires", ""], rows))

    async def remove(request):
        form = await request.post()
        if not hmac.compare_digest(str(form.get("token", "")), csrf_token):
            return web.Response(status=403, text="Invalid or expired form. Reload the page and try again.")
        entry = str(form.get("entry", "")).strip()
        row = gk.db.entry(entry)
        if row is None or not row["active"]:
            msg = f"{entry} is not on the allowlist."
        elif gk.is_pinned(row):
            msg = f"{entry} is pinned (home) and can't be removed here."
        else:
            try:
                await gk.revoke(entry, f"removed on dashboard by {settings.dashboard_user}")
                msg = f"Removed {entry}. Cloudflare applies it within about a minute."
            except Exception as e:
                msg = f"Couldn't remove {entry}: {e}"
        raise web.HTTPSeeOther(f"/allowlist?{urlencode({'msg': msg})}")

    async def events(request):
        rows = [f"<tr><td>{_local(e['ts'])}</td><td><code>{escape(e['ip'])}</code></td><td>{escape(e['country'] or '')}</td>"
                f"<td>{escape(e['asn_name'] or '')}</td><td>{escape(e['host'] or '')}</td>"
                f"<td class='wide'>{escape((e['method'] or '') + ' ' + (e['path'] or ''))}</td>"
                f"<td class='wide muted'>{escape((e['ua'] or '')[:120])}</td></tr>" for e in gk.db.recent_events(300)]
        return _page("Events", "<h2>Latest 300 blocked requests</h2>" + _table(
            ["When", "IP", "Country", "Network", "Host", "Request", "User agent"], rows))

    async def healthz(request):
        return web.Response(text="ok")

    app = web.Application(middlewares=[auth])
    app.add_routes([web.get("/", overview), web.get("/allowlist", allowlist), web.get("/events", events),
                    web.post("/allowlist/remove", remove), web.get("/healthz", healthz)])
    return app
