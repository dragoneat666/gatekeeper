"""Discord bot: on-demand only. Every reply is ephemeral (only the admin who asked sees it)."""
import datetime
import logging

import discord
from discord import app_commands

from .db import iso, parse, utcnow
from .ipnet import normalize_entry

log = logging.getLogger("gatekeeper.bot")


def _local(ts: str) -> str:
    return parse(ts).astimezone().strftime("%b %d %H:%M")


def _is_admin(interaction: discord.Interaction) -> bool:
    return interaction.user.id in interaction.client.settings.discord_admins


async def _deny(interaction: discord.Interaction):
    await interaction.response.send_message("Not allowed.", ephemeral=True)


class ApproveButton(discord.ui.DynamicItem[discord.ui.Button], template=r"gk:ok:(?P<entry>[0-9a-fA-F:./]+)"):
    """Approve button. Its custom_id carries the entry, so it keeps working after a bot restart."""

    def __init__(self, entry: str, label: str = "Approve"):
        super().__init__(discord.ui.Button(label=label, style=discord.ButtonStyle.success,
                                           custom_id=f"gk:ok:{entry}"))
        self.entry = entry

    @classmethod
    async def from_custom_id(cls, interaction, item, match):
        return cls(match["entry"])

    async def callback(self, interaction: discord.Interaction):
        if not _is_admin(interaction):
            return await _deny(interaction)
        await interaction.response.defer(ephemeral=True, thinking=True)
        gk = interaction.client.gk
        try:
            entry, already = await gk.approve(self.entry, by=interaction.user.name, label="via /blocked")
        except Exception as e:
            log.exception("approve failed")
            return await interaction.followup.send(f"Approve failed: {e}", ephemeral=True)
        msg = (f"`{entry}` was already on the allowlist." if already else
               f"Approved `{entry}`. Cloudflare applies it within about a minute.")
        await interaction.followup.send(msg, ephemeral=True)


def render_blocked(rows, minutes, approved):
    if not rows:
        return f"No blocked requests in the last {minutes} min. (Cloudflare can take ~3 min to report a block.)"
    lines = [f"**Blocked in the last {minutes} min** (busiest first; Cloudflare reports blocks ~3 min late)"]
    for i, r in enumerate(rows, 1):
        tag = " - already approved" if r["entry"] in approved else ""
        where = " ".join(x for x in (r["country"], r["asn_name"]) if x) or "?"
        hosts = (r["hosts"] or "").replace(",", ", ")
        lines.append(f"**#{i}** `{r['entry']}` - {r['hits']} hits, last {_local(r['last'])} - {where}{tag}\n"
                     f"    {hosts[:120]}")
    text = "\n".join(lines)
    return text if len(text) <= 1990 else text[:1980] + "\n..."


class GateBot(discord.Client):
    def __init__(self, gk, settings):
        intents = discord.Intents.none()
        intents.guilds = True
        super().__init__(intents=intents)
        self.gk = gk
        self.settings = settings
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        self.add_dynamic_items(ApproveButton)
        guild = discord.Object(id=self.settings.discord_guild)
        for cmd in (blocked_cmd, approve_cmd, revoke_cmd):
            self.tree.add_command(cmd, guild=guild)
        await self.tree.sync(guild=guild)
        log.info("slash commands synced to guild %s", self.settings.discord_guild)

    async def on_ready(self):
        log.info("Discord bot logged in as %s", self.user)


@app_commands.command(name="blocked", description="Recently blocked IPs, with Approve buttons")
@app_commands.describe(minutes="How far back to look (default 60)")
@app_commands.default_permissions(administrator=True)
async def blocked_cmd(interaction: discord.Interaction, minutes: app_commands.Range[int, 1, 10080] = 60):
    if not _is_admin(interaction):
        return await _deny(interaction)
    await interaction.response.defer(ephemeral=True, thinking=True)
    gk = interaction.client.gk
    note = ""
    try:
        await gk.poll_events()  # fresh data, not just the last scheduled poll
    except Exception as e:
        log.exception("poll from /blocked failed")
        note = f"\n(Couldn't refresh from Cloudflare: {e}. Showing stored events.)"
    since = iso(utcnow() - datetime.timedelta(minutes=minutes))
    rows = gk.db.blocked_summary(since, limit=10)
    approved = {r["entry"] for r in gk.db.active_entries()}
    view = discord.ui.View(timeout=None)
    for i, r in enumerate(rows, 1):
        if r["entry"] not in approved:
            view.add_item(ApproveButton(r["entry"], label=f"Approve #{i}"))
    await interaction.followup.send(render_blocked(rows, minutes, approved) + note, view=view, ephemeral=True)


@app_commands.command(name="approve", description="Add an IP to the allowlist (IPv6 is approved as its /64)")
@app_commands.describe(ip="IP address from the block page", label="Who it is, e.g. 'Alice phone'")
@app_commands.default_permissions(administrator=True)
async def approve_cmd(interaction: discord.Interaction, ip: str, label: str = ""):
    if not _is_admin(interaction):
        return await _deny(interaction)
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        entry, already = await interaction.client.gk.approve(ip, by=interaction.user.name, label=label)
    except ValueError:
        return await interaction.followup.send(f"`{ip}` isn't a valid IP address.", ephemeral=True)
    except Exception as e:
        log.exception("approve failed")
        return await interaction.followup.send(f"Approve failed: {e}", ephemeral=True)
    await interaction.followup.send(f"`{entry}` was already on the allowlist." if already else
                                    f"Approved `{entry}`. Cloudflare applies it within about a minute.",
                                    ephemeral=True)


@app_commands.command(name="revoke", description="Remove an entry from the allowlist")
@app_commands.describe(entry="IP address or IPv6 /64 exactly as listed")
@app_commands.default_permissions(administrator=True)
async def revoke_cmd(interaction: discord.Interaction, entry: str):
    if not _is_admin(interaction):
        return await _deny(interaction)
    await interaction.response.defer(ephemeral=True, thinking=True)
    gk = interaction.client.gk
    try:
        row = gk.db.entry(normalize_entry(entry))
        if row is not None and gk.is_pinned(row):
            return await interaction.followup.send(f"`{entry}` is pinned (home); not removing it.", ephemeral=True)
        ok = await gk.revoke(entry, f"revoked by {interaction.user.name}")
    except ValueError:
        return await interaction.followup.send(f"`{entry}` isn't a valid IP or network.", ephemeral=True)
    except Exception as e:
        log.exception("revoke failed")
        return await interaction.followup.send(f"Revoke failed: {e}", ephemeral=True)
    await interaction.followup.send(f"Removed `{entry}`." if ok else f"`{entry}` isn't on the allowlist.",
                                    ephemeral=True)
