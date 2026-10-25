# gatekeeper

Companion app for a default-deny Cloudflare IP allowlist (WAF custom rule `not ip.src in $gatekeeper_allow` → Block).

- **Polls** Cloudflare's GraphQL API every 5 minutes for blocked requests and keeps them in SQLite (Cloudflare keeps 31 days).
- **Alerts** to ntfy only on targeted probing: repeated hits on real hostnames or login paths. Scanner noise goes into the daily summary.
- **Discord bot** (on demand, ephemeral replies, admin user IDs only):
  - `/blocked [minutes]` lists recent blocked IPs with Approve buttons. It refreshes from Cloudflare first.
  - `/approve <ip> [label]` approves an IP someone sent you from Cloudflare's block page.
  - `/revoke <entry>` removes an entry.
- **`/letmein` for members (self-service)**: opens a box for the Ray ID from Cloudflare's block page, or an IP address. The entry is approved only if Cloudflare actually blocked that request or IP recently (default 24 h). Optionally, each member can be limited to a number of active approvals (default: unlimited). An optional role can be required.
- **Daily summary** to a private admin channel via webhook.
- **Expiry**: entries unused for 60 days (configurable) are removed. "Used" comes from Cloudflare's per-IP request analytics, so TV and phone apps count.
- **Home IP**: the server's public IP is kept on the list and replaced automatically when it changes (new one added before the old one is removed).
- IPv6 clients are approved as their /64, because devices rotate addresses within it.
- **Dashboard** (basic auth) on port 8080: blocked traffic, alerts, and the allowlist with a Remove button (pinned entries excepted).

Cloudflare's list is the source of truth for who gets in; entries added or removed in the Cloudflare dashboard are picked up hourly.

## Settings

See `.env.example`. The Cloudflare token needs only **Account Rule Lists: Edit** and **Account Analytics: Read**. It cannot change WAF rules or DNS.

## Tests

```bash
docker build --target test .
```

The GitHub workflow runs the same tests before building and pushing `ghcr.io/dragoneat666/gatekeeper:latest`.
