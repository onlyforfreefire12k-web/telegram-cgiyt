"""
security.py — cryptographic storage, threat thresholds and guard rails.

This module centralises every security-sensitive primitive so the rest of
the codebase never re-implements them ad hoc:

1. SessionCipher   — Fernet (AES-128-CBC + HMAC) encryption for MTProto
                     session strings at rest.
2. Sliding windows — per-(group, admin) counters powering mass-ban and
                     mass-delete detection. Threshold values come from
                     config (environment), never hardcoded here.
3. Role gates      — the OWNER > SECURITY_ADMIN > TRUSTED_ADMIN > MODERATOR
                     hierarchy used before ANY privileged action.
4. Owner shield    — a single choke-point that makes the configured owner
                     untargetable by destructive commands.
5. Alert renderer  — human-readable SECURITY ALERT blocks for the audit
                     log. Secret material (codes/clicks) is structurally
                     unable to reach this function because it only accepts
                     typed event metadata — and a redaction helper is
                     provided for free-form strings.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet, InvalidToken

import config

log = logging.getLogger("security")

# Marker used in place of anything that must never be persisted or shown.
REDACTED = "<redacted>"
_SECRET_ENV_NAMES = {
    "api_hash", "session", "session_string", "password", "code", "otp",
    "2fa", "phone_code_hash", "bot_token",
}


def redact(text: str | None) -> str:
    """Best-effort scrubbing helper for free-form strings destined to logs.

    Secrets are never *expected* inside any logged string — the code simply
    never logs them. This helper is defence-in-depth for the rare case a
    Telegram error message echoes something sensitive back to us.
    """
    if not text:
        return ""
    scrubbed = str(text)
    for env_name in ("API_HASH", "BOT_TOKEN", "SESSION_SECRET"):
        value = os.getenv(env_name)
        if value and value in scrubbed:
            scrubbed = scrubbed.replace(value, REDACTED)
    return scrubbed


def mask_phone(phone: str | None) -> str | None:
    """Turn '+15551234567' into '+•••••••4567' for display purposes."""
    if not phone:
        return None
    digits = phone.strip()
    if len(digits) <= 5:
        return "+••••"
    return "+" + "•" * (len(digits) - 5) + digits[-4:]


# ---------------------------------------------------------------------------
# 1. Encrypted session storage
# ---------------------------------------------------------------------------

class SessionCipher:
    """Encrypts/decrypts MTProto session strings before they touch SQLite.

    Key resolution order:
      1. SESSION_SECRET environment variable (recommended on Render — set
         once, sessions survive redeploys).
      2. Auto-generated key file at data/.session_key with mode 0600.
         Works out of the box, but sessions become unreadable if the file
         is lost (the user simply logs in again — no security degradation).
    """

    def __init__(self) -> None:
        key = self._load_key()
        self._fernet = Fernet(key)

    @staticmethod
    def _load_key() -> bytes:
        env_key = config.SESSION_SECRET
        if env_key:
            # Accept either a ready Fernet key or raw passphrases (hashed).
            try:
                Fernet(env_key.encode())
                return env_key.encode()
            except Exception:
                digest = hashlib.sha256(env_key.encode()).digest()
                return base64.urlsafe_b64encode(digest)

        os.makedirs(config.DATA_DIR, exist_ok=True)
        key_path = os.path.join(config.DATA_DIR, ".session_key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as fh:
                return fh.read().strip()
        key = Fernet.generate_key()
        # Written with owner-only permissions; contains just a random key.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        log.warning(
            "SESSION_SECRET not set — generated a local key at %s. "
            "Set SESSION_SECRET in the environment so sessions survive "
            "container redeploys.", key_path)
        return key

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str | None:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            # Wrong key (e.g. SESSION_SECRET rotated). We deliberately return
            # None so the caller asks for a fresh login instead of crashing.
            log.error("Stored session could not be decrypted "
                      "(encryption key mismatch). A fresh /login is required.")
            return None


def generate_session_secret() -> str:
    """Helper for operators: print one via `python -c ...` (see README)."""
    return secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
# 2. Sliding-window counters + suspicion/lockdown state
# ---------------------------------------------------------------------------

class RateTracker:
    """In-memory sliding windows. Process restarts reset counters, which is
    acceptable: thresholds exist to catch *bursts*, not slow-burn behaviour
    (slow-burn is covered by the persistent audit log)."""

    def __init__(self, max_window: int) -> None:
        self._max_window = max_window
        self._hits: dict[tuple[int, int], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def record(self, group_id: int, admin_id: int, when: float | None = None) -> None:
        now = when or time.monotonic()
        key = (group_id, admin_id)
        with self._lock:
            dq = self._hits[key]
            dq.append(now)
            self._prune(dq, now)

    def count(self, group_id: int, admin_id: int, window: int) -> int:
        now = time.monotonic()
        with self._lock:
            dq = self._hits.get((group_id, admin_id))
            if not dq:
                return 0
            self._prune(dq, now)
            cutoff = now - window
            return sum(1 for ts in dq if ts >= cutoff)

    def reset(self, group_id: int, admin_id: int) -> None:
        with self._lock:
            self._hits.pop((group_id, admin_id), None)

    def _prune(self, dq: deque[float], now: float) -> None:
        cutoff = now - self._max_window
        while dq and dq[0] < cutoff:
            dq.popleft()


class SuspicionRegistry:
    """Tracks which administrators are currently flagged, with cooldowns so
    a flagged admin doesn't generate an alert storm."""

    def __init__(self) -> None:
        self._flagged: dict[tuple[int, int], float] = {}      # → flagged at
        self._last_alert: dict[tuple[int, int], float] = {}   # → last alert
        self._lock = threading.Lock()

    def flag(self, group_id: int, admin_id: int) -> bool:
        """Mark suspicious. Returns True if this is a NEW flag."""
        key = (group_id, admin_id)
        with self._lock:
            first = key not in self._flagged or self.is_expired(*key)
            self._flagged[key] = time.time()
            return first

    def is_flagged(self, group_id: int, admin_id: int) -> bool:
        with self._lock:
            ts = self._flagged.get((group_id, admin_id))
        return bool(ts) and not self.is_expired(group_id, admin_id)

    def is_expired(self, group_id: int, admin_id: int) -> bool:
        ts = self._flagged.get((group_id, admin_id))
        return not ts or (time.time() - ts) > config.SUSPICION_TTL

    def should_alert(self, group_id: int, admin_id: int,
                     cooldown: int | None = None) -> bool:
        key = (group_id, admin_id)
        cd = cooldown if cooldown is not None else config.SUSPICION_COOLDOWN
        with self._lock:
            last = self._last_alert.get(key, 0.0)
            if time.time() - last < cd:
                return False
            self._last_alert[key] = time.time()
            return True

    def clear(self, group_id: int, admin_id: int) -> None:
        with self._lock:
            self._flagged.pop((group_id, admin_id), None)


class ThresholdResult:
    def __init__(self, triggered: bool, rule: str | None,
                 count: int, window: int) -> None:
        self.triggered = triggered
        self.rule = rule            # e.g. "BAN_LIMIT_1=5/60s"
        self.count = count
        self.window = window

    def __bool__(self) -> bool:  # allows `if result:` style checks
        return self.triggered


class ThreatDetector:
    """Evaluates configured thresholds against sliding-window counters.

    IMPORTANT: a single normal moderation action can NEVER trigger this —
    triggering requires crossing the configured multi-action thresholds.
    """

    def __init__(self) -> None:
        longest = max(config.BAN_WINDOW_1, config.BAN_WINDOW_2,
                      config.DELETE_WINDOW_1, config.DELETE_WINDOW_2)
        self.bans = RateTracker(longest)
        self.deletes = RateTracker(longest)
        self.suspicion = SuspicionRegistry()

    @staticmethod
    def _effective_limit(base: int, lockdown: bool) -> int:
        if not lockdown:
            return base
        # Stricter thresholds while locked down (e.g. 5 → max(2, 2.5) = 2).
        return max(2, int(base * config.LOCKDOWN_THRESHOLD_FACTOR))

    def check_ban(self, group_id: int, admin_id: int,
                  lockdown: bool) -> ThresholdResult:
        self.bans.record(group_id, admin_id)
        for name, limit, window in (
            ("BAN_LIMIT_1", config.BAN_LIMIT_1, config.BAN_WINDOW_1),
            ("BAN_LIMIT_2", config.BAN_LIMIT_2, config.BAN_WINDOW_2),
        ):
            eff = self._effective_limit(limit, lockdown)
            count = self.bans.count(group_id, admin_id, window)
            if count >= eff:
                return ThresholdResult(True, f"{name}={eff}/{window}s", count, window)
        return ThresholdResult(False, None, self.bans.count(group_id, admin_id,
                                                            config.BAN_WINDOW_1),
                               config.BAN_WINDOW_1)

    def check_delete(self, group_id: int, admin_id: int,
                     lockdown: bool) -> ThresholdResult:
        self.deletes.record(group_id, admin_id)
        for name, limit, window in (
            ("DELETE_LIMIT_1", config.DELETE_LIMIT_1, config.DELETE_WINDOW_1),
            ("DELETE_LIMIT_2", config.DELETE_LIMIT_2, config.DELETE_WINDOW_2),
        ):
            eff = self._effective_limit(limit, lockdown)
            count = self.deletes.count(group_id, admin_id, window)
            if count >= eff:
                return ThresholdResult(True, f"{name}={eff}/{window}s", count, window)
        return ThresholdResult(False, None, self.deletes.count(group_id, admin_id,
                                                               config.DELETE_WINDOW_1),
                               config.DELETE_WINDOW_1)

    def clear(self, group_id: int, admin_id: int) -> None:
        self.bans.reset(group_id, admin_id)
        self.deletes.reset(group_id, admin_id)
        self.suspicion.clear(group_id, admin_id)


detector = ThreatDetector()


# ---------------------------------------------------------------------------
# 3 + 4. Role gates and the owner shield
# ---------------------------------------------------------------------------

def is_owner(user_id: int | None) -> bool:
    return bool(user_id) and user_id == config.OWNER_ID


def role_of(get_role, user_id: int | None) -> str | None:
    """get_role is injected (Database.get_admin_role) to keep this module
    importable without a live database (tests)."""
    if user_id is None:
        return None
    return get_role(user_id)


def role_at_least(role: str | None, minimum: str) -> bool:
    if role is None:
        return False
    return config.ROLE_ORDER.get(role, 0) >= config.ROLE_ORDER.get(minimum, 99)


def has_permission(role: str | None, permission: str) -> bool:
    if role is None:
        return False
    perms = config.ROLE_PERMISSIONS.get(role, frozenset())
    return "*" in perms or permission in perms


def guard_target(user_id: int | None, target_id: int | None) -> str | None:
    """Single choke-point invoked before EVERY destructive action.

    Returns an error string when the action must be refused, else None.
    """
    if target_id is None:
        return "No target user was resolved."
    if is_owner(target_id):
        # The configured owner is immutable via bot commands — period.
        return "Refused: the configured owner cannot be modified by this system."
    if target_id == user_id:
        return "Refused: you cannot run destructive commands on yourself."
    return None


# ---------------------------------------------------------------------------
# 5. Alert rendering
# ---------------------------------------------------------------------------

def alert_timestamp(tz_name: str | None = None) -> str:
    tz = ZoneInfo(tz_name or config.ALERT_TZ)
    now = datetime.now(tz)
    # %Z renders e.g. "IST" for Asia/Kolkata, matching the spec example.
    return now.strftime("%Y-%m-%d %H:%M:%S %Z")


def render_security_alert(*, group_title: str, group_id: int,
                          admin_display: str, admin_id: int | None,
                          action_detected: str,
                          steps: list[tuple[bool, str]],
                          timestamp: str | None = None) -> str:
    """Render the human-readable alert block from the spec.

    This function receives only typed metadata — codes, passwords and session
    strings are structurally absent from its inputs.
    """
    tick, cross = "✓", "✗"
    lines = [
        "SECURITY ALERT",
        "",
        f"Group: {group_title} ({group_id})",
        f"Admin: {admin_display}",
        f"Admin ID: {admin_id if admin_id is not None else 'unknown'}",
        "",
        "Action detected:",
        action_detected,
        "",
        "Actions:",
    ]
    lines.extend(f"{tick if ok else cross} {label}" for ok, label in steps)
    lines += ["", "Timestamp:", timestamp or alert_timestamp()]
    return "\n".join(lines)
