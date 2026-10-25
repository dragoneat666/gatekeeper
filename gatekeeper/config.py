"""Settings, all read from environment variables (the stack's .env file)."""
import os
from dataclasses import dataclass, field

DEFAULT_LOGIN_PATHS = (
    r"(?i)(^/login|^/signin|^/auth|/if/flow/|/application/o/|/api/v\d+/auth|/Users/AuthenticateByName"
    r"|^/api/login|^/api/oauth|/oauth2?/|/sso/|/admin)"
)


def _list(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


def _int(name, default):
    return int(os.environ.get(name, default))


def _bool(name, default="false"):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    cf_token: str = ""
    cf_account: str = ""
    cf_list: str = ""
    db_path: str = "/data/gatekeeper.db"
    dry_run: bool = False

    poll_seconds: int = 300
    lastseen_seconds: int = 3600
    expire_days: int = 60
    ipv6_prefix: int = 64
    pinned: list = field(default_factory=list)
    home_ip_check: bool = True

    protected_hosts: list = field(default_factory=list)
    login_paths: str = DEFAULT_LOGIN_PATHS
    alert_window_minutes: int = 15
    alert_host_hits: int = 20
    alert_login_hits: int = 3
    alert_cooldown_hours: int = 6

    ntfy_url: str = ""
    ntfy_topic: str = "gatekeeper"
    ntfy_token: str = ""

    discord_token: str = ""
    discord_guild: int = 0
    discord_admins: list = field(default_factory=list)
    discord_webhook: str = ""
    summary_hour: int = 8
    letmein_max_active: int = 3
    letmein_role_id: int = 0
    letmein_lookback_hours: int = 24

    dashboard_port: int = 8080
    dashboard_user: str = "admin"
    dashboard_password: str = ""

    @classmethod
    def from_env(cls):
        return cls(
            cf_token=os.environ.get("CF_API_TOKEN", ""),
            cf_account=os.environ.get("CF_ACCOUNT_ID", ""),
            cf_list=os.environ.get("CF_LIST_ID", ""),
            db_path=os.environ.get("DB_PATH", "/data/gatekeeper.db"),
            dry_run=_bool("DRY_RUN"),
            poll_seconds=_int("POLL_SECONDS", 300),
            lastseen_seconds=_int("LASTSEEN_SECONDS", 3600),
            expire_days=_int("EXPIRE_DAYS", 60),
            ipv6_prefix=_int("IPV6_PREFIX", 64),
            pinned=_list("PINNED_ENTRIES"),
            home_ip_check=_bool("HOME_IP_CHECK", "true"),
            protected_hosts=[h.lower() for h in _list("PROTECTED_HOSTS")],
            login_paths=os.environ.get("LOGIN_PATH_REGEX", DEFAULT_LOGIN_PATHS),
            alert_window_minutes=_int("ALERT_WINDOW_MINUTES", 15),
            alert_host_hits=_int("ALERT_HOST_HITS", 20),
            alert_login_hits=_int("ALERT_LOGIN_HITS", 3),
            alert_cooldown_hours=_int("ALERT_COOLDOWN_HOURS", 6),
            ntfy_url=os.environ.get("NTFY_URL", "").rstrip("/"),
            ntfy_topic=os.environ.get("NTFY_TOPIC", "gatekeeper"),
            ntfy_token=os.environ.get("NTFY_TOKEN", ""),
            discord_token=os.environ.get("DISCORD_BOT_TOKEN", ""),
            discord_guild=_int("DISCORD_GUILD_ID", 0),
            discord_admins=[int(x) for x in _list("DISCORD_ADMIN_IDS")],
            discord_webhook=os.environ.get("DISCORD_WEBHOOK_URL", ""),
            summary_hour=_int("SUMMARY_HOUR", 8),
            letmein_max_active=_int("LETMEIN_MAX_ACTIVE", 3),
            letmein_role_id=_int("LETMEIN_ROLE_ID", 0),
            letmein_lookback_hours=_int("LETMEIN_LOOKBACK_HOURS", 24),
            dashboard_port=_int("DASHBOARD_PORT", 8080),
            dashboard_user=os.environ.get("DASHBOARD_USER", "admin"),
            dashboard_password=os.environ.get("DASHBOARD_PASSWORD", ""),
        )
