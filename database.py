"""
database.py — SQLite storage layer.

Design notes
------------
* SQLite keeps the project trivial to deploy (Render free tiers have no
  managed Postgres requirement for personal deployments). WAL mode + a single
  threading lock keep it safe for our architecture: one asyncio worker loop
  plus the Flask status thread.
* Numeric Telegram user ids are the primary identity everywhere.
* Sessions are stored ONLY in encrypted form (see security.SessionCipher).
  The raw MTProto session string never touches the database, the logs, or
  any chat message.
* Only a masked phone fingerprint is kept for display purposes
  (e.g. "+•••••••4321"), never the full number.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from typing import Any, Iterable

import config

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    telegram_id INTEGER PRIMARY KEY,
    username    TEXT,
    first_name  TEXT,
    last_name   TEXT,
    last_seen   INTEGER NOT NULL DEFAULT 0
);

-- Encrypted MTProto sessions. One connected account per row.
CREATE TABLE IF NOT EXISTS sessions (
    user_id           INTEGER PRIMARY KEY,
    encrypted_session TEXT NOT NULL,
    phone_masked      TEXT,
    phone_fp          TEXT,          -- sha256 fingerprint (never the raw number)
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    revoked           INTEGER NOT NULL DEFAULT 0
);

-- Groups where the security system is installed.
CREATE TABLE IF NOT EXISTS groups (
    chat_id    INTEGER PRIMARY KEY,
    title      TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    lockdown   INTEGER NOT NULL DEFAULT 0,
    added_by   INTEGER,
    added_at   INTEGER NOT NULL
);

-- Trusted administrators of THIS security system (not Telegram admins).
CREATE TABLE IF NOT EXISTS admins (
    user_id   INTEGER PRIMARY KEY,
    role      TEXT NOT NULL,
    added_by  INTEGER,
    added_at  INTEGER NOT NULL
);

-- Global (cross-configured-group) mute list.
CREATE TABLE IF NOT EXISTS global_mutes (
    user_id    INTEGER PRIMARY KEY,
    reason     TEXT,
    added_by   INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS warnings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   INTEGER NOT NULL,
    user_id    INTEGER NOT NULL,
    admin_id   INTEGER,
    reason     TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   INTEGER,
    group_title TEXT,
    admin_id   INTEGER,
    target_id  INTEGER,
    action     TEXT NOT NULL,
    result     TEXT,
    details    TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Rolling per-group admin-log cursor so polling only returns new rows.
CREATE INDEX IF NOT EXISTS idx_events_group ON security_events(group_id, id);
CREATE INDEX IF NOT EXISTS idx_warnings_user ON warnings(group_id, user_id);
"""


def _now() -> int:
    return int(time.time())


class Database:
    """Thin, thread-safe wrapper. All SQL is parameterised."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or config.DATABASE_PATH
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # -- low-level helpers --------------------------------------------------

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- users ---------------------------------------------------------------

    def remember_user(self, user_id: int, username: str | None,
                      first_name: str | None, last_name: str | None) -> None:
        self.execute(
            """INSERT INTO users (telegram_id, username, first_name, last_name, last_seen)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(telegram_id) DO UPDATE SET
                   username=excluded.username,
                   first_name=excluded.first_name,
                   last_name=excluded.last_name,
                   last_seen=excluded.last_seen""",
            (user_id, username, first_name, last_name, _now()),
        )

    def get_user(self, user_id: int) -> sqlite3.Row | None:
        return self.query_one("SELECT * FROM users WHERE telegram_id=?", (user_id,))

    # -- sessions (encrypted at rest) ---------------------------------------

    def save_session(self, user_id: int, encrypted_session: str,
                     phone_masked: str | None) -> None:
        fp = hashlib.sha256(
            f"{user_id}:{phone_masked or ''}".encode()
        ).hexdigest()[:16]
        self.execute(
            """INSERT INTO sessions (user_id, encrypted_session, phone_masked,
                                     phone_fp, created_at, updated_at, revoked)
               VALUES (?, ?, ?, ?, ?, ?, 0)
               ON CONFLICT(user_id) DO UPDATE SET
                   encrypted_session=excluded.encrypted_session,
                   phone_masked=excluded.phone_masked,
                   phone_fp=excluded.phone_fp,
                   updated_at=excluded.updated_at,
                   revoked=0""",
            (user_id, encrypted_session, phone_masked, fp, _now(), _now()),
        )

    def get_session(self, user_id: int) -> sqlite3.Row | None:
        return self.query_one(
            "SELECT * FROM sessions WHERE user_id=? AND revoked=0", (user_id,))

    def get_any_active_session(self) -> sqlite3.Row | None:
        return self.query_one(
            "SELECT * FROM sessions WHERE revoked=0 ORDER BY updated_at DESC LIMIT 1")

    def revoke_session(self, user_id: int) -> None:
        """Hard-delete the encrypted session row (called after server-side
        Telegram revocation so nothing reusable remains anywhere)."""
        self.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))

    # -- groups ----------------------------------------------------------------

    def upsert_group(self, chat_id: int, title: str | None,
                     added_by: int | None, enabled: bool = True) -> None:
        self.execute(
            """INSERT INTO groups (chat_id, title, enabled, lockdown, added_by, added_at)
               VALUES (?, ?, ?, 0, ?, ?)
               ON CONFLICT(chat_id) DO UPDATE SET
                   title=excluded.title,
                   enabled=excluded.enabled""",
            (chat_id, title, 1 if enabled else 0, added_by, _now()),
        )

    def get_group(self, chat_id: int) -> sqlite3.Row | None:
        return self.query_one("SELECT * FROM groups WHERE chat_id=?", (chat_id,))

    def enabled_groups(self) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM groups WHERE enabled=1")

    def set_group_enabled(self, chat_id: int, enabled: bool) -> None:
        self.execute("UPDATE groups SET enabled=? WHERE chat_id=?",
                     (1 if enabled else 0, chat_id))

    def set_lockdown(self, chat_id: int, active: bool) -> None:
        self.execute("UPDATE groups SET lockdown=? WHERE chat_id=?",
                     (1 if active else 0, chat_id))

    def is_lockdown(self, chat_id: int) -> bool:
        row = self.get_group(chat_id)
        return bool(row and row["lockdown"])

    def locked_groups(self) -> list[sqlite3.Row]:
        return self.query("SELECT chat_id, title FROM groups WHERE lockdown=1")

    # -- trust roles -------------------------------------------------------------

    def set_admin_role(self, user_id: int, role: str, added_by: int | None) -> None:
        self.execute(
            """INSERT INTO admins (user_id, role, added_by, added_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET role=excluded.role,
                                                 added_by=excluded.added_by,
                                                 added_at=excluded.added_at""",
            (user_id, role, added_by, _now()),
        )

    def get_admin_role(self, user_id: int) -> str | None:
        if user_id == config.OWNER_ID:
            return config.ROLE_OWNER
        row = self.query_one("SELECT role FROM admins WHERE user_id=?", (user_id,))
        return row["role"] if row else None

    def remove_admin(self, user_id: int) -> None:
        self.execute("DELETE FROM admins WHERE user_id=?", (user_id,))

    def list_admins(self) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM admins ORDER BY added_at")

    # -- global mute -------------------------------------------------------------

    def add_gmute(self, user_id: int, reason: str | None, added_by: int | None) -> None:
        self.execute(
            """INSERT INTO global_mutes (user_id, reason, added_by, created_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET reason=excluded.reason,
                                                 added_by=excluded.added_by""",
            (user_id, reason, added_by, _now()),
        )

    def remove_gmute(self, user_id: int) -> bool:
        cur = self.execute("DELETE FROM global_mutes WHERE user_id=?", (user_id,))
        return cur.rowcount > 0

    def is_gmuted(self, user_id: int) -> bool:
        return self.query_one(
            "SELECT 1 AS x FROM global_mutes WHERE user_id=?", (user_id,)) is not None

    def list_gmutes(self) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM global_mutes ORDER BY created_at DESC")

    # -- warnings ------------------------------------------------------------------

    def add_warning(self, group_id: int, user_id: int,
                    admin_id: int | None, reason: str | None) -> int:
        self.execute(
            "INSERT INTO warnings (group_id, user_id, admin_id, reason, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (group_id, user_id, admin_id, reason, _now()),
        )
        row = self.query_one(
            "SELECT COUNT(*) AS c FROM warnings WHERE group_id=? AND user_id=?",
            (group_id, user_id))
        return int(row["c"] if row else 0)

    def count_warnings(self, group_id: int, user_id: int) -> int:
        row = self.query_one(
            "SELECT COUNT(*) AS c FROM warnings WHERE group_id=? AND user_id=?",
            (group_id, user_id))
        return int(row["c"] if row else 0)

    def clear_warnings(self, group_id: int, user_id: int) -> None:
        self.execute("DELETE FROM warnings WHERE group_id=? AND user_id=?",
                     (group_id, user_id))

    # -- security events ------------------------------------------------------------

    def log_event(self, group_id: int | None, admin_id: int | None,
                  target_id: int | None, action: str, result: str | None,
                  details: str | None = None,
                  group_title: str | None = None) -> int:
        cur = self.execute(
            """INSERT INTO security_events
                   (group_id, group_title, admin_id, target_id, action, result, details, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (group_id, group_title, admin_id, target_id, action, result, details, _now()),
        )
        return int(cur.lastrowid or 0)

    def recent_events(self, limit: int = 10,
                      group_id: int | None = None) -> list[sqlite3.Row]:
        if group_id is None:
            return self.query(
                "SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))
        return self.query(
            "SELECT * FROM security_events WHERE group_id=? ORDER BY id DESC LIMIT ?",
            (group_id, limit))

    def get_event(self, event_id: int) -> sqlite3.Row | None:
        return self.query_one("SELECT * FROM security_events WHERE id=?", (event_id,))

    def count_events_since(self, since: int) -> int:
        row = self.query_one(
            "SELECT COUNT(*) AS c FROM security_events WHERE created_at>=?", (since,))
        return int(row["c"] if row else 0)

    # -- settings ---------------------------------------------------------------------

    def set_setting(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value))

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.query_one("SELECT value FROM settings WHERE key=?", (key,))
        return row["value"] if row else default

    def delete_setting(self, key: str) -> None:
        self.execute("DELETE FROM settings WHERE key=?", (key,))

    # -- admin-log cursor ----------------------------------------------------------------

    def get_adminlog_cursor(self, chat_id: int) -> int:
        raw = self.get_setting(f"adminlog_cursor:{chat_id}", "0")
        try:
            return int(raw or 0)
        except ValueError:
            return 0

    def set_adminlog_cursor(self, chat_id: int, cursor: int) -> None:
        self.set_setting(f"adminlog_cursor:{chat_id}", str(cursor))


db = Database()
