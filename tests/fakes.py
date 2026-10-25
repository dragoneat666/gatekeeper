"""Test doubles: an in-memory Cloudflare and a notifier that records what it was asked to send."""
import itertools

from gatekeeper.config import Settings
from gatekeeper.core import Gatekeeper
from gatekeeper.db import DB


class FakeCloudflare:
    def __init__(self, items=(), public_ip="198.51.100.1"):
        self._ids = itertools.count(1)
        self.items = [{"id": f"id{next(self._ids)}", "ip": i, "comment": c} for i, c in items]
        self.events = []
        self.requests = {}
        self.ip = public_ip
        self.calls = []
        self.dry_run = False

    async def list_items(self):
        return [dict(i) for i in self.items]

    async def add_items(self, items):
        self.calls.append(("add", [i["ip"] for i in items]))
        for i in items:
            existing = [x for x in self.items if x["ip"] == i["ip"]]
            if existing:
                existing[0]["comment"] = i.get("comment", "")
            else:
                self.items.append({"id": f"id{next(self._ids)}", "ip": i["ip"], "comment": i.get("comment", "")})

    async def delete_items(self, ids):
        self.calls.append(("delete", list(ids)))
        self.items = [x for x in self.items if x["id"] not in ids]

    async def blocked_events(self, since, until):
        self.calls.append(("events", since, until))
        return [e for e in self.events if since <= e["datetime"] <= until]

    async def requests_by_ip(self, since, until):
        self.calls.append(("requests", since, until))
        return dict(self.requests)

    async def public_ip(self):
        return self.ip


class FakeNotifier:
    def __init__(self):
        self.alerts = []
        self.webhooks = []

    async def alert(self, title, message, priority=3, tags=""):
        self.alerts.append((title, message))
        return True

    async def webhook(self, content):
        self.webhooks.append(content)
        return True


def make(items=(), **settings):
    s = Settings(cf_token="t", cf_account="a", cf_list="l", db_path=":memory:", **settings)
    cf = FakeCloudflare(items)
    n = FakeNotifier()
    return Gatekeeper(s, DB(":memory:"), cf, n), cf, n


def event(ip, ts, host="jellyfin.example.com", path="/", ray=None):
    return {"rayName": ray or f"ray-{ip}-{ts}-{path}", "datetime": ts, "action": "block", "source": "firewallCustom",
            "clientIP": ip, "clientRequestHTTPHost": host, "clientRequestPath": path,
            "clientRequestHTTPMethodName": "GET", "edgeResponseStatus": 403, "clientCountryName": "US",
            "clientAsn": 7922, "clientASNDescription": "COMCAST", "userAgent": "test", "ruleId": "r1"}
