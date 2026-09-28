"""
config.py — Central configuration for the Telegram Security Userbot.

SECURITY MODEL
--------------
* Every sensitive value (bot token, API credentials, owner identity,
  session-encryption key) is read ONLY from environment variables.
* Nothing secret is ever hardcoded in this repository.
* Non-sensitive behavioural knobs (thresholds, intervals, toggles) may have
  safe defaults here but can always be overridden through the environment,
  so nothing behavioural is "hardcoded into the logic".

Python 3.12+ compatible.
"""

from __future__ import annotations

import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")


# ---------------------------------------------------------------------------
# Small typed environment helpers
# ---------------------------------------------------------------------------

def _str_env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        print(f"[config] WARNING: {name}={raw!r} is not an integer, using {default}")
        return default


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Required secrets / identity (NO defaults — must come from the environment)
# ---------------------------------------------------------------------------

API_ID: int = _int_env("API_ID", 0)                 # from https://my.telegram.org
API_HASH: str | None = _str_env("API_HASH")         # from https://my.telegram.org
BOT_TOKEN: str | None = _str_env("BOT_TOKEN")       # from @BotFather
OWNER_ID: int = _int_env("OWNER_ID", 0)             # numeric Telegram user id of the owner

# Optional: pre-shared Fernet key used to encrypt stored MTProto sessions.
# If absent, security.py generates a local key file with 0600 permissions and
# prints a one-time warning. On Render, set this so sessions survive redeploys.
SESSION_SECRET: str | None = _str_env("SESSION_SECRET")


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def _resolve_database_path() -> str:
    """Support DATABASE_URL (sqlite:///path or bare path) and DATABASE_PATH."""
    url = _str_env("DATABASE_URL")
    if url:
        if url.startswith("sqlite:///"):
            return url[len("sqlite:///"):]
        if "://" in url:
            # Non-SQLite URLs are not supported by the built-in driver yet;
            # fail loudly instead of silently writing somewhere unexpected.
            raise RuntimeError(
                "DATABASE_URL scheme not supported by the built-in storage "
                "driver. Use sqlite:///path/to/file.db or set DATABASE_PATH."
            )
        return url
    return _str_env("DATABASE_PATH", os.path.join(DATA_DIR, "security.db"))


DATABASE_PATH: str = _resolve_database_path()


# ---------------------------------------------------------------------------
# Flask / Render
# ---------------------------------------------------------------------------

PORT: int = _int_env("PORT", 10000)  # Render injects PORT automatically
HOST: str = _str_env("HOST", "0.0.0.0")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FILE: str = _str_env("SECURITY_LOG_FILE", os.path.join(DATA_DIR, "security.log"))
LOG_LEVEL: str = _str_env("LOG_LEVEL", "INFO")
# Alert timestamps: the spec renders alerts e.g. "2026-09-28 12:30:00 IST".
# Any IANA name works (zoneinfo). Override with ALERT_TZ.
ALERT_TZ: str = _str_env("ALERT_TZ", "Asia/Kolkata")


# ---------------------------------------------------------------------------
# Anti mass-ban / mass-delete thresholds (fully configurable — no magic
# numbers inside the detection logic itself)
# ---------------------------------------------------------------------------

BAN_LIMIT_1: int = _int_env("BAN_LIMIT_1", 5)        # bans/kicks …
BAN_WINDOW_1: int = _int_env("BAN_WINDOW_1", 60)     # … within 60 s  → suspicious
BAN_LIMIT_2: int = _int_env("BAN_LIMIT_2", 15)       # bans/kicks …
BAN_WINDOW_2: int = _int_env("BAN_WINDOW_2", 300)    # … within 5 min → suspicious

DELETE_LIMIT_1: int = _int_env("DELETE_LIMIT_1", 12)
DELETE_WINDOW_1: int = _int_env("DELETE_WINDOW_1", 60)
DELETE_LIMIT_2: int = _int_env("DELETE_LIMIT_2", 30)
DELETE_WINDOW_2: int = _int_env("DELETE_WINDOW_2", 300)

# Once an admin is flagged, alerts about them are rate-limited by this cooldown.
SUSPICION_COOLDOWN: int = _int_env("SUSPICION_COOLDOWN", 600)

# How quickly a suspicion flag expires if no further violations occur.
SUSPICION_TTL: int = _int_env("SUSPICION_TTL", 3600)


# ---------------------------------------------------------------------------
# Emergency response toggles
# ---------------------------------------------------------------------------

# If Telegram's admin hierarchy legally allows the connected account to demote
# the offending administrator, do it automatically on a confirmed mass-ban.
AUTO_DEMOTE_ON_MASS_BAN: bool = _bool_env("AUTO_DEMOTE_ON_MASS_BAN", True)
# If configured AND legally permitted, additionally ban/kick the offender.
AUTO_BAN_ON_MASS_BAN: bool = _bool_env("AUTO_BAN_ON_MASS_BAN", False)
# Mass-deletion response is notification-first by default.
AUTO_DEMOTE_ON_MASS_DELETE: bool = _bool_env("AUTO_DEMOTE_ON_MASS_DELETE", False)

# Automatically engage lockdown for the affected group on confirmed mass-ban.
AUTO_LOCKDOWN_ON_MASS_BAN: bool = _bool_env("AUTO_LOCKDOWN_ON_MASS_BAN", False)


# ---------------------------------------------------------------------------
# Lockdown behaviour
# ---------------------------------------------------------------------------

# While a group is locked down, new joiners are restricted from sending.
LOCKDOWN_RESTRICT_NEW_MEMBERS: bool = _bool_env("LOCKDOWN_RESTRICT_NEW_MEMBERS", True)
# During lockdown, thresholds are multiplied by this factor (stricter).
LOCKDOWN_THRESHOLD_FACTOR: float = float(_str_env("LOCKDOWN_THRESHOLD_FACTOR", "0.5") or 0.5)


# ---------------------------------------------------------------------------
# Anti-flood spam guard (per-group, per-user sliding window)
# ---------------------------------------------------------------------------

SPAM_LIMIT: int = _int_env("SPAM_LIMIT", 6)          # messages …
SPAM_WINDOW: int = _int_env("SPAM_WINDOW", 10)       # … within 10 seconds
SPAM_MUTE_SECONDS: int = _int_env("SPAM_MUTE_SECONDS", 600)

# Runtime feature toggles — defaults used when the settings table has no
# override yet; /settings in the management bot flips them live.
FEATURE_TOGGLES: dict[str, bool] = {
    "spam_protection": True,
    "admin_monitoring": True,
    "massban_detection": True,
    "massdelete_detection": True,
    "owner_alerts": True,
    "audit_logging": True,
}


# ---------------------------------------------------------------------------
# Warning system
# ---------------------------------------------------------------------------

WARN_LIMIT: int = _int_env("WARN_LIMIT", 3)          # warnings before action
WARN_ACTION: str = _str_env("WARN_ACTION", "mute")   # "mute" | "kick" | "none"
WARN_MUTE_SECONDS: int = _int_env("WARN_MUTE_SECONDS", 3600)


# ---------------------------------------------------------------------------
# Userbot runtime
# ---------------------------------------------------------------------------

ADMIN_LOG_POLL_INTERVAL: int = _int_env("ADMIN_LOG_POLL_INTERVAL", 10)  # seconds
ADMIN_LOG_PAGE: int = _int_env("ADMIN_LOG_PAGE", 50)
# Maximum FloodWait we will sleep through automatically; longer waits are
# reported instead of blocking the worker.
MAX_FLOODWAIT_SLEEP: int = _int_env("MAX_FLOODWAIT_SLEEP", 60)
DEVICE_MODEL: str = _str_env("DEVICE_MODEL", "Security Userbot")

# Login flow hardening
LOGIN_MAX_CODE_ATTEMPTS: int = _int_env("LOGIN_MAX_CODE_ATTEMPTS", 3)
LOGIN_STATE_TTL: int = _int_env("LOGIN_STATE_TTL", 600)


# ---------------------------------------------------------------------------
# Admin trust system — roles and their permission scopes
# ---------------------------------------------------------------------------
# Identity is ALWAYS the numeric Telegram user id, never a username
# (usernames change; ids do not).

ROLE_MODERATOR = "MODERATOR"
ROLE_TRUSTED = "TRUSTED_ADMIN"
ROLE_SECURITY = "SECURITY_ADMIN"
ROLE_OWNER = "OWNER"

ROLE_ORDER: dict[str, int] = {
    ROLE_MODERATOR: 1,
    ROLE_TRUSTED: 2,
    ROLE_SECURITY: 3,
    ROLE_OWNER: 4,
}

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    ROLE_MODERATOR: frozenset({
        "mute", "unmute", "warn", "warnings", "delete",
    }),
    ROLE_TRUSTED: frozenset({
        "mute", "unmute", "warn", "warnings", "delete",
        "ban", "unban", "kick",
    }),
    ROLE_SECURITY: frozenset({
        "mute", "unmute", "warn", "warnings", "delete",
        "ban", "unban", "kick",
        "promote", "demote", "gmute", "ungmute",
        "lockdown", "unlock", "trust", "untrust",
    }),
    # OWNER implicitly has every permission (guarded in security.py so the
    # owner can never become a *target* of a destructive command).
    ROLE_OWNER: frozenset({"*"}),
}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate(strict: bool = True) -> list[str]:
    """Return a list of configuration problems. Print them if `strict`."""
    problems: list[str] = []
    if not API_ID:
        problems.append("API_ID is missing (get it from https://my.telegram.org)")
    if not API_HASH:
        problems.append("API_HASH is missing (get it from https://my.telegram.org)")
    if not BOT_TOKEN:
        problems.append("BOT_TOKEN is missing (create a bot via @BotFather)")
    if not OWNER_ID:
        problems.append("OWNER_ID is missing (your numeric Telegram user id)")
    if BAN_LIMIT_1 < 1 or BAN_LIMIT_2 < 1:
        problems.append("Ban thresholds must be positive integers")
    if BAN_WINDOW_1 < 5 or BAN_WINDOW_2 < 5:
        problems.append("Ban windows must be at least 5 seconds")
    if problems and strict:
        for p in problems:
            print(f"[config] ERROR: {p}", file=sys.stderr)
    return problems


def require_valid() -> None:
    problems = validate(strict=True)
    if problems:
        raise SystemExit(
            "Configuration incomplete — set the environment variables above "
            "and restart. See README.md for step-by-step instructions."
        )
