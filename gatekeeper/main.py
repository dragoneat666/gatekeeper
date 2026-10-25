"""Entry point: scheduled jobs + Discord bot + dashboard in one asyncio process."""
import asyncio
import datetime
import logging
import sys

import aiohttp
from aiohttp import web

from .cloudflare import Cloudflare
from .config import Settings
from .core import Gatekeeper
from .db import DB, iso, utcnow
from .notify import Notifier
from .web import build_app

log = logging.getLogger("gatekeeper")
EVENT_RETENTION_DAYS = 365


async def every(seconds, name, job, first_delay=0):
    await asyncio.sleep(first_delay)
    while True:
        try:
            await job()
        except Exception:
            log.exception("job %s failed", name)
        await asyncio.sleep(seconds)


def seconds_until(hour):
    now = datetime.datetime.now().astimezone()
    nxt = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if nxt <= now:
        nxt += datetime.timedelta(days=1)
    return (nxt - now).total_seconds()


async def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    s = Settings.from_env()
    missing = [k for k, v in (("CF_API_TOKEN", s.cf_token), ("CF_ACCOUNT_ID", s.cf_account),
                              ("CF_LIST_ID", s.cf_list)) if not v]
    if missing:
        sys.exit(f"missing settings: {', '.join(missing)}")
    if s.dry_run:
        log.warning("DRY_RUN is on: the Cloudflare list will not be changed")

    db = DB(s.db_path)
    async with aiohttp.ClientSession() as session:
        cf = Cloudflare(session, s.cf_token, s.cf_account, s.cf_list, dry_run=s.dry_run)
        notifier = Notifier(session, s)
        gk = Gatekeeper(s, db, cf, notifier)

        await gk.sync_list()

        async def poll_job():
            new = await gk.poll_events()
            await gk.detect(new)
            if s.home_ip_check:
                await gk.check_home_ip()

        async def daily_job():
            while True:
                await asyncio.sleep(seconds_until(s.summary_hour))
                try:
                    gone = await gk.expire()
                    if gone:
                        log.info("expired %d entries", len(gone))
                    db.prune_events(iso(utcnow() - datetime.timedelta(days=EVENT_RETENTION_DAYS)))
                    await notifier.webhook(gk.summary_text())
                except Exception:
                    log.exception("daily job failed")

        tasks = [
            asyncio.create_task(every(s.poll_seconds, "poll", poll_job)),
            asyncio.create_task(every(s.lastseen_seconds, "last_seen", gk.update_last_seen, first_delay=60)),
            asyncio.create_task(every(3600, "sync", gk.sync_list, first_delay=3600)),
            asyncio.create_task(daily_job()),
        ]

        runner = web.AppRunner(build_app(gk, s))
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", s.dashboard_port).start()
        log.info("dashboard on port %s", s.dashboard_port)

        if s.discord_token:
            from .bot import GateBot
            bot = GateBot(gk, s)
            tasks.append(asyncio.create_task(bot.start(s.discord_token)))
        else:
            log.warning("DISCORD_BOT_TOKEN not set: bot disabled")

        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
