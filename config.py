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
# Two-layer admin-abuse detection (human initiator attribution)
# ---------------------------------------------------------------------------
# Layer A: the Telegram admin audit log is the source of truth for REAL
# moderation actions. Layer B: message/command monitoring remembers WHO
# asked for a moderation verb (/ban @user sent to us OR to any other bot in
# the group — ANY bot, userbot or account). When an admin-log action matches
# a recent pending command (same group + same target + compatible action +
# within ADMIN_CORRELATION_WINDOW seconds), the action is attributed to the
# HUMAN initiator instead of whoever executed it.
#
# EXECUTOR-AGNOSTIC BY DESIGN: no bot name, username or ID is ever special-
# cased anywhere in this project. Executors are discovered dynamically from
# the admin log, and attribution is decided purely by evidence.

ADMIN_ABUSE_ENABLED: bool = _bool_env("ADMIN_ABUSE_ENABLED", True)

ADMIN_BAN_THRESHOLD: int = _int_env("ADMIN_BAN_THRESHOLD", 3)
ADMIN_BAN_WINDOW_SECONDS: int = _int_env("ADMIN_BAN_WINDOW_SECONDS", 60)
ADMIN_MUTE_THRESHOLD: int = _int_env("ADMIN_MUTE_THRESHOLD", 5)
ADMIN_MUTE_WINDOW_SECONDS: int = _int_env("ADMIN_MUTE_WINDOW_SECONDS", 60)

# Extra protection around promote/demote/rights-change events.
ADMIN_PERMISSION_CHANGE_PROTECTION: bool = _bool_env(
    "ADMIN_PERMISSION_CHANGE_PROTECTION", True)

# How long a pending command stays correlated with an admin-log event (5–10s).
ADMIN_CORRELATION_WINDOW: int = _int_env("ADMIN_CORRELATION_WINDOW", 8)

# Automatic response once an initiator crosses a threshold.
AUTO_DEMOTE_ABUSIVE_ADMIN: bool = _bool_env("AUTO_DEMOTE_ABUSIVE_ADMIN", True)
AUTO_BAN_ABUSIVE_ADMIN: bool = _bool_env("AUTO_BAN_ABUSIVE_ADMIN", False)

# Unbans are legitimate by default; count them only if explicitly enabled.
ADMIN_COUNT_UNBAN: bool = _bool_env("ADMIN_COUNT_UNBAN", False)

# --- Unattributed (UNKNOWN-initiator) executor handling --------------------
# When an action is executed by a bot/account and NO evidence links it to a
# human admin, the system records it, may alert the owner, and can apply
# separate *executor-based* rules. It NEVER guesses a human to punish.
UNKNOWN_EXECUTOR_ALERTS: bool = _bool_env("UNKNOWN_EXECUTOR_ALERTS", True)
EXECUTOR_ABUSE_THRESHOLD: int = _int_env("EXECUTOR_ABUSE_THRESHOLD",
                                         ADMIN_BAN_THRESHOLD)
EXECUTOR_ABUSE_WINDOW: int = _int_env("EXECUTOR_ABUSE_WINDOW",
                                      ADMIN_BAN_WINDOW_SECONDS)
# Demote an unattributed rogue executor (the actor itself — never a guessed
# human). Off by default: alert-first policy.
AUTO_DEMOTE_UNATTRIBUTED_EXECUTOR: bool = _bool_env(
    "AUTO_DEMOTE_UNATTRIBUTED_EXECUTOR", False)


# ---------------------------------------------------------------------------
# Moderation command patterns (executor-agnostic intent detection)
# ---------------------------------------------------------------------------
# Any admin may drive ANY bot. We therefore detect *requests* by shape, not by
# which bot they are addressed to. Only these exact configured tokens count as
# moderation commands — a message merely containing the word "ban" is ignored.
#
# A token matches when it is the FIRST word of the message, case-insensitively,
# optionally followed by "@anybotusername" (e.g. "/ban@SomeBot @user").
#
# Override entirely with MODERATION_COMMAND_PATTERNS_JSON, e.g.
#   {"ban": ["/ban", ".ban", "!ban", "/kill"], "mute": ["/mute", ".mute"]}
# or extend at runtime through the settings store (key: custom_mod_patterns).
#
# NOTE: bare words (e.g. "ban") are deliberately NOT enabled by default
# because ordinary chat would false-positive. Add them explicitly if your
# moderation bot uses prefix-less commands.

_DEFAULT_COMMAND_PATTERNS: dict[str, list[str]] = {
    "ban":        ["/ban", ".ban", "!ban", "#ban", "/gban", "/sban", "/dban"],
    "kick":       ["/kick", ".kick", "!kick", "#kick", "/punch", "/dkick"],
    "mute":       ["/mute", ".mute", "!mute", "#mute", "/tmute", "/dmute",
                   "/silence"],
    "restrict":   ["/restrict", ".restrict", "!restrict", "#restrict"],
    "unban":      ["/unban", ".unban", "!unban", "#unban", "/ungban"],
    "unmute":     ["/unmute", ".unmute", "!unmute", "#unmute", "/untmute"],
    "unrestrict": ["/unrestrict", ".unrestrict", "!unrestrict"],
    "promote":    ["/promote", ".promote", "!promote", "#promote"],
    "demote":     ["/demote", ".demote", "!demote", "#demote"],
}


def _load_command_patterns() -> dict[str, list[str]]:
    raw = _str_env("MODERATION_COMMAND_PATTERNS_JSON")
    if not raw:
        return {k: list(v) for k, v in _DEFAULT_COMMAND_PATTERNS.items()}
    try:
        import json
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("not a JSON object")
        cleaned: dict[str, list[str]] = {}
        for action, pats in parsed.items():
            if isinstance(pats, str):
                pats = [pats]
            cleaned[str(action).lower()] = [str(p).strip().lower()
                                            for p in pats if str(p).strip()]
        return cleaned or {k: list(v) for k, v
                           in _DEFAULT_COMMAND_PATTERNS.items()}
    except Exception as exc:
        print(f"[config] WARNING: MODERATION_COMMAND_PATTERNS_JSON invalid "
              f"({type(exc).__name__}); using defaults")
        return {k: list(v) for k, v in _DEFAULT_COMMAND_PATTERNS.items()}


MODERATION_COMMAND_PATTERNS: dict[str, list[str]] = _load_command_patterns()

# Requested action → admin-log action kind used for correlation.
COMMAND_ACTION_TO_KIND: dict[str, str] = {
    "ban": "ban", "kick": "ban",
    "mute": "restrict", "restrict": "restrict",
    "unban": "unban", "unmute": "unban", "unrestrict": "unban",
    "promote": "promote", "demote": "demote",
}


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
    "admin_abuse": True,          # live toggle for the abuse layer (/settings)
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
