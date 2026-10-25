"""Outgoing notifications: ntfy for phone alerts, a Discord webhook for the daily summary."""
import logging

import aiohttp

log = logging.getLogger("gatekeeper.notify")


class Notifier:
    def __init__(self, session: aiohttp.ClientSession, settings):
        self.session = session
        self.s = settings

    async def alert(self, title, message, priority=3, tags=""):
        """Phone alert via ntfy. Logged instead when ntfy isn't configured."""
        if not self.s.ntfy_url:
            log.warning("ALERT (ntfy not configured): %s - %s", title, message)
            return False
        headers = {"Title": title, "Priority": str(priority)}
        if tags:
            headers["Tags"] = tags
        if self.s.ntfy_token:
            headers["Authorization"] = f"Bearer {self.s.ntfy_token}"
        try:
            async with self.session.post(f"{self.s.ntfy_url}/{self.s.ntfy_topic}", data=message.encode(),
                                         headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status >= 400:
                    log.error("ntfy returned %s", r.status)
                    return False
            return True
        except aiohttp.ClientError as e:
            log.error("ntfy failed: %s", e)
            return False

    async def webhook(self, content):
        """Post to the private admin channel. Discord caps a message at 2000 characters."""
        if not self.s.discord_webhook:
            log.info("webhook not configured; summary:\n%s", content)
            return False
        chunks, cur = [], ""
        for line in content.splitlines():
            if len(cur) + len(line) + 1 > 1900:
                chunks.append(cur)
                cur = ""
            cur += line + "\n"
        chunks.append(cur)
        ok = True
        for chunk in chunks:
            async with self.session.post(self.s.discord_webhook, json={"content": chunk},
                                         timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status >= 400:
                    log.error("Discord webhook returned %s", r.status)
                    ok = False
        return ok
