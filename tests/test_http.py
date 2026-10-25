"""HTTP-level tests: the Cloudflare client against a fake API server, the dashboard's auth, the bot text."""
import asyncio

import aiohttp
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from fakes import make

from gatekeeper.cloudflare import Cloudflare, CloudflareError


def fake_api():
    state = {"op_checks": 0, "posted": [], "deleted": [], "graphql_pages": 0}
    items = [{"id": f"i{n}", "ip": f"10.0.0.{n}", "comment": ""} for n in range(3)]

    async def list_items(request):
        cursor = request.query.get("cursor")
        page = items[2:] if cursor == "next" else items[:2]
        info = {} if cursor == "next" else {"cursors": {"after": "next"}}
        return web.json_response({"success": True, "result": page, "result_info": info})

    async def add(request):
        state["posted"].append(await request.json())
        return web.json_response({"success": True, "result": {"operation_id": "op1"}})

    async def delete(request):
        state["deleted"].append(await request.json())
        return web.json_response({"success": True, "result": {"operation_id": "op1"}})

    async def op(request):
        state["op_checks"] += 1
        status = "completed" if state["op_checks"] >= 2 else "running"
        return web.json_response({"success": True, "result": {"id": "op1", "status": status}})

    async def graphql(request):
        q = (await request.json())["query"]
        if "broken" in q:
            return web.json_response({"data": None, "errors": [{"message": "bad field"}]})
        if "firewallEventsAdaptive" in q:
            state["graphql_pages"] += 1
            rows = [{"datetime": "2026-10-25T00:00:01Z", "rayName": "a"}]
            return web.json_response({"data": {"viewer": {"accounts": [{"firewallEventsAdaptive": rows}]}}})
        rows = [{"count": 5, "dimensions": {"clientIP": "1.2.3.4"}}]
        return web.json_response({"data": {"viewer": {"accounts": [{"httpRequestsAdaptiveGroups": rows}]}}})

    async def denied(request):
        return web.json_response({"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]},
                                 status=403)

    app = web.Application()
    app.add_routes([
        web.get("/accounts/a/rules/lists/l/items", list_items),
        web.post("/accounts/a/rules/lists/l/items", add),
        web.delete("/accounts/a/rules/lists/l/items", delete),
        web.get("/accounts/a/rules/lists/bulk_operations/op1", op),
        web.post("/graphql", graphql),
        web.get("/accounts/bad/rules/lists/l/items", denied),
    ])
    return app, state


async def _with_client(fn):
    app, state = fake_api()
    async with TestServer(app) as server, aiohttp.ClientSession() as session:
        base = str(server.make_url(""))
        await fn(Cloudflare(session, "t", "a", "l", base=base, op_poll_seconds=0), state, session, base)


def test_list_items_follows_cursor_pages():
    async def go(cf, state, *_):
        items = await cf.list_items()
        assert [i["ip"] for i in items] == ["10.0.0.0", "10.0.0.1", "10.0.0.2"]
    asyncio.run(_with_client(go))


def test_writes_wait_for_bulk_operation_to_complete():
    async def go(cf, state, *_):
        await cf.add_items([{"ip": "9.9.9.9", "comment": "x"}])
        assert state["posted"] == [[{"ip": "9.9.9.9", "comment": "x"}]] and state["op_checks"] == 2
        await cf.delete_items(["i1"])
        assert state["deleted"] == [{"items": [{"id": "i1"}]}]
    asyncio.run(_with_client(go))


def test_dry_run_sends_no_writes():
    async def go(cf, state, *_):
        cf.dry_run = True
        await cf.add_items([{"ip": "9.9.9.9"}])
        await cf.delete_items(["i1"])
        assert state["posted"] == [] and state["deleted"] == []
    asyncio.run(_with_client(go))


def test_graphql_errors_and_api_errors_raise():
    async def go(cf, state, session, base):
        try:
            await cf.graphql("{ broken }")
            assert False
        except CloudflareError as e:
            assert "bad field" in str(e)
        bad = Cloudflare(session, "t", "bad", "l", base=base)
        try:
            await bad.list_items()
            assert False
        except CloudflareError as e:
            assert "403" in str(e) and "Authentication error" in str(e)
    asyncio.run(_with_client(go))


def test_analytics_queries_parse_results():
    async def go(cf, state, *_):
        ev = await cf.blocked_events("2026-10-25T00:00:00Z", "2026-10-25T01:00:00Z")
        assert ev[0]["rayName"] == "a" and state["graphql_pages"] == 1
        assert await cf.requests_by_ip("2026-10-25T00:00:00Z", "2026-10-25T01:00:00Z") == {"1.2.3.4": 5}
    asyncio.run(_with_client(go))


def test_dashboard_requires_password():
    from gatekeeper.web import build_app
    gk, _, _ = make()
    gk.s.dashboard_password = "secret"

    async def go():
        async with TestClient(TestServer(build_app(gk, gk.s))) as client:
            assert (await client.get("/healthz")).status == 200
            assert (await client.get("/")).status == 401
            assert (await client.get("/", auth=aiohttp.BasicAuth("admin", "wrong"))).status == 401
            r = await client.get("/allowlist", auth=aiohttp.BasicAuth("admin", "secret"))
            assert r.status == 200 and "Allowlist" in await r.text()
    asyncio.run(go())


def test_dashboard_refuses_everyone_when_no_password_set():
    from gatekeeper.web import build_app
    gk, _, _ = make()

    async def go():
        async with TestClient(TestServer(build_app(gk, gk.s))) as client:
            assert (await client.get("/", auth=aiohttp.BasicAuth("admin", ""))).status == 401
    asyncio.run(go())


def test_blocked_reply_text():
    from gatekeeper.bot import ApproveButton, render_blocked
    rows = [{"entry": "2607:fb90::/64", "hits": 12, "last": "2026-10-25T14:16:55Z", "country": "US",
             "asn_name": "T-MOBILE", "hosts": "jellyfin.example.com,auth.example.com"},
            {"entry": "9.9.9.9", "hits": 1, "last": "2026-10-25T14:00:00Z", "country": "CA", "asn_name": "",
             "hosts": "wiki.example.com"}]
    text = render_blocked(rows, 60, approved={"9.9.9.9"})
    assert "#1** `2607:fb90::/64` - 12 hits" in text and "jellyfin.example.com, auth.example.com" in text
    assert "already approved" in text.split("#2")[1]
    assert render_blocked([], 30, set()).startswith("No blocked requests in the last 30 min")
    btn = ApproveButton("2607:fb90::/64", label="Approve #1")
    assert btn.item.custom_id == "gk:ok:2607:fb90::/64"
    assert ApproveButton.__discord_ui_compiled_template__.fullmatch(btn.item.custom_id)["entry"] == "2607:fb90::/64"


def test_dashboard_remove_needs_token_and_skips_pinned():
    import re
    from gatekeeper.web import build_app
    gk, cf, _ = make([("203.0.113.10", "seed 2026-10-25 import: alice"),
                      ("198.51.100.1", "home WAN (pinned) 2026-10-25")])
    gk.s.dashboard_password = "secret"
    asyncio.run(gk.sync_list())
    auth = aiohttp.BasicAuth("admin", "secret")

    async def go():
        async with TestClient(TestServer(build_app(gk, gk.s))) as client:
            page = await (await client.get("/allowlist", auth=auth)).text()
            assert page.count("<button") == 1                      # no Remove button on the pinned home entry
            token = re.search(r"name='token' value='([^']+)'", page).group(1)
            r = await client.post("/allowlist/remove", data={"entry": "203.0.113.10", "token": "wrong"}, auth=auth)
            assert r.status == 403 and gk.db.entry("203.0.113.10")["active"] == 1
            r = await client.post("/allowlist/remove", data={"entry": "198.51.100.1", "token": token}, auth=auth)
            assert "pinned" in await r.text() and gk.db.entry("198.51.100.1")["active"] == 1
            r = await client.post("/allowlist/remove", data={"entry": "203.0.113.10", "token": token}, auth=auth)
            assert "Removed 203.0.113.10" in await r.text()
            assert gk.db.entry("203.0.113.10")["active"] == 0
            assert not any(i["ip"] == "203.0.113.10" for i in cf.items)
            r = await client.post("/allowlist/remove", data={"entry": "203.0.113.10", "token": token})
            assert r.status == 401                                   # still needs the dashboard login
    asyncio.run(go())


def test_commands_page_lists_every_registered_command():
    from gatekeeper.bot import COMMANDS
    from gatekeeper.web import build_app
    gk, _, _ = make()
    gk.s.dashboard_password = "secret"

    async def go():
        async with TestClient(TestServer(build_app(gk, gk.s))) as client:
            page = await (await client.get("/commands", auth=aiohttp.BasicAuth("admin", "secret"))).text()
            for cmd, who in COMMANDS:
                assert f"/{cmd.name}" in page and cmd.description[:30] in page
            assert "/blocked [minutes]" in page and "/approve &lt;ip&gt; [label]" in page
    asyncio.run(go())
