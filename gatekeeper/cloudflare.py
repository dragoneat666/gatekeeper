"""Cloudflare API client: GraphQL analytics (read) and the account IP list (read/write).

List writes are asynchronous on Cloudflare's side (they return an operation id to poll) and only
one may run at a time, so every write goes through a lock and waits for its operation to finish.
"""
import asyncio
import logging

import aiohttp

log = logging.getLogger("gatekeeper.cloudflare")

API = "https://api.cloudflare.com/client/v4"
EVENT_FIELDS = ("datetime action source clientIP clientRequestHTTPHost clientRequestPath "
                "clientRequestHTTPMethodName edgeResponseStatus clientCountryName clientAsn "
                "clientASNDescription userAgent rayName ruleId")
PAGE = 10000


class CloudflareError(Exception):
    pass


class Cloudflare:
    def __init__(self, session: aiohttp.ClientSession, token: str, account: str, list_id: str,
                 base: str = API, dry_run: bool = False, op_poll_seconds: float = 2.0):
        self.session = session
        self.account = account
        self.list_id = list_id
        self.base = base.rstrip("/")
        self.dry_run = dry_run
        self.op_poll_seconds = op_poll_seconds
        self._headers = {"Authorization": f"Bearer {token}"}
        self._write_lock = asyncio.Lock()

    async def _request(self, method, path, **kw):
        async with self.session.request(method, self.base + path, headers=self._headers,
                                        timeout=aiohttp.ClientTimeout(total=60), **kw) as r:
            try:
                body = await r.json(content_type=None)
            except Exception:
                body = {}
            if r.status >= 400 or body.get("success") is False:
                errors = [e.get("message") for e in body.get("errors") or []]
                raise CloudflareError(f"{method} {path.split('?')[0]} -> {r.status} {errors}")
            return body

    # --- analytics (GraphQL) -----------------------------------------------------------------
    async def graphql(self, query: str):
        body = await self._request("POST", "/graphql", json={"query": query})
        if body.get("errors"):
            raise CloudflareError(f"graphql: {[e.get('message') for e in body['errors']]}")
        return body["data"]["viewer"]["accounts"][0]

    async def blocked_events(self, since: str, until: str):
        """All 'block' events between since (inclusive) and until, oldest first, paging past 10k rows."""
        out, cursor = [], since
        while True:
            q = ('{ viewer { accounts(filter:{accountTag:"%s"}) { firewallEventsAdaptive(limit:%d, '
                 'filter:{datetime_geq:"%s", datetime_leq:"%s", action:"block"}, orderBy:[datetime_ASC]) '
                 '{ %s } } } }') % (self.account, PAGE, cursor, until, EVENT_FIELDS)
            rows = (await self.graphql(q))["firewallEventsAdaptive"]
            out.extend(rows)
            if len(rows) < PAGE or rows[-1]["datetime"] == cursor:
                return out
            cursor = rows[-1]["datetime"]  # duplicates at the boundary are dropped by Ray ID later

    async def requests_by_ip(self, since: str, until: str):
        """{client_ip: request_count} for all traffic in the window (allowed and blocked)."""
        q = ('{ viewer { accounts(filter:{accountTag:"%s"}) { httpRequestsAdaptiveGroups(limit:%d, '
             'filter:{datetime_geq:"%s", datetime_lt:"%s"}, orderBy:[count_DESC]) '
             '{ count dimensions { clientIP } } } } }') % (self.account, PAGE, since, until)
        rows = (await self.graphql(q))["httpRequestsAdaptiveGroups"]
        return {r["dimensions"]["clientIP"]: r["count"] for r in rows}

    # --- IP list -----------------------------------------------------------------------------
    def _list_path(self, suffix=""):
        return f"/accounts/{self.account}/rules/lists/{self.list_id}{suffix}"

    async def list_items(self):
        """[{'id', 'ip', 'comment'}] for every item in the list."""
        items, cursor = [], None
        while True:
            path = self._list_path("/items?per_page=500") + (f"&cursor={cursor}" if cursor else "")
            body = await self._request("GET", path)
            items.extend({"id": i["id"], "ip": i["ip"], "comment": i.get("comment", "")}
                         for i in body.get("result") or [])
            cursor = ((body.get("result_info") or {}).get("cursors") or {}).get("after")
            if not cursor:
                return items

    async def _wait(self, op_id):
        for _ in range(90):
            body = await self._request("GET", f"/accounts/{self.account}/rules/lists/bulk_operations/{op_id}")
            status = body["result"]["status"]
            if status == "completed":
                return
            if status == "failed":
                raise CloudflareError(f"list operation failed: {body['result'].get('error')}")
            await asyncio.sleep(self.op_poll_seconds)
        raise CloudflareError("list operation timed out")

    async def add_items(self, items):
        """items: [{'ip': entry, 'comment': text}]. Appends; an existing value just gets the new comment."""
        if self.dry_run:
            log.info("DRY RUN: would add %s", [i["ip"] for i in items])
            return
        async with self._write_lock:
            body = await self._request("POST", self._list_path("/items"), json=items)
            await self._wait(body["result"]["operation_id"])

    async def delete_items(self, ids):
        if self.dry_run:
            log.info("DRY RUN: would delete item ids %s", ids)
            return
        async with self._write_lock:
            body = await self._request("DELETE", self._list_path("/items"),
                                       json={"items": [{"id": i} for i in ids]})
            await self._wait(body["result"]["operation_id"])

    # --- this server's public IP -------------------------------------------------------------
    async def public_ip(self, url="https://1.1.1.1/cdn-cgi/trace"):
        async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
            text = await r.text()
        for line in text.splitlines():
            if line.startswith("ip="):
                return line[3:].strip()
        raise CloudflareError("no ip= line in trace response")
