"""
userbot.py — the connected-account (MTProto) security worker.

Scope & ethics
--------------
This worker exists ONLY for defensive group security:

* monitors the admin audit log of groups where the connected account is a
  *legitimate* administrator with the required rights;
* enforces the configured global-mute list when listed users appear;
* applies owner-issued moderation commands after strict permission gates.

It NEVER sends bulk/unsolicited messages, invites, advertisements or any
form of raid/flood automation. Every action is either (a) a configured
security event, or (b) an explicit command from a trusted role — and both
paths pass through Telegram's own permission hierarchy, which we respect
and never attempt to bypass.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

from telethon import TelegramClient, events, functions, types, utils
from telethon.errors import (
    AuthKeyUnregisteredError,
    ChannelPrivateError,
    ChatAdminRequiredError,
    FloodWaitError,
    RPCError,
    SessionRevokedError,
    UserAdminInvalidError,
    UserDeactivatedBanError,
    UserNotParticipantError,
)
from telethon.sessions import StringSession
from telethon.tl import types as t

import config
import security
from database import Database

log = logging.getLogger("userbot")

Notifier = Callable[[str], Awaitable[None]]

# Service-message types that announce a new chat member. Used to enforce
# the global-mute list and lockdown restrictions the instant a user appears.
_JOIN_ACTIONS = (
    t.MessageActionChatAddUser,
    t.MessageActionChatJoinedByLink,
    t.MessageActionChatJoinedByRequest,
)

# Rights revoked by a global mute / lockdown restriction = "can read, cannot
# send anything". until_date=None means "until explicitly lifted".
_GMUTE_RIGHTS = t.ChatBannedRights(
    until_date=None,
    send_messages=True,
    send_media=True,
    send_stickers=True,
    send_gifs=True,
    send_games=True,
    send_inline=True,
    embed_links=True,
    send_polls=True,
    send_photos=True,
    send_videos=True,
    send_audios=True,
    send_voices=True,
    send_roundvideos=True,
)

# Full ban (cannot see or re-enter the group).
_BAN_RIGHTS = t.ChatBannedRights(until_date=None, view_messages=True)

# All-false rights lift every restriction (unban/unmute).
_UNBAN_RIGHTS = t.ChatBannedRights(until_date=None)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


_DURATION_TOKEN_RE = re.compile(r"^\d+[smhd]$", re.IGNORECASE)
# "/ban@AnyBotUsername" → strip the addressee. We deliberately do NOT care
# WHICH bot a command is addressed to: any bot, userbot or account may be the
# executor, and new ones may appear tomorrow.
_ADDRESSEE_RE = re.compile(r"@[A-Za-z0-9_]{3,}$")

# Requested action → admin-log kind (see config.COMMAND_ACTION_TO_KIND).
_VERB_TO_KIND = config.COMMAND_ACTION_TO_KIND


def build_command_index(extra: dict[str, list[str]] | None = None
                        ) -> dict[str, str]:
    """Flatten configured patterns into {token: action}.

    Executor-agnostic: tokens are shapes ("/ban", ".ban", "!ban", "/kill"…),
    never bot identities. Runtime additions (settings store) are merged in."""
    index: dict[str, str] = {}
    for action, patterns in config.MODERATION_COMMAND_PATTERNS.items():
        kind = config.COMMAND_ACTION_TO_KIND.get(action.lower())
        if not kind:
            continue
        for pattern in patterns:
            token = str(pattern).strip().lower()
            if token:
                index[token] = action.lower()
    for action, patterns in (extra or {}).items():
        if not config.COMMAND_ACTION_TO_KIND.get(str(action).lower()):
            continue
        for pattern in patterns:
            token = str(pattern).strip().lower()
            if token:
                index[token] = str(action).lower()
    return index


def match_moderation_command(text: str, index: dict[str, str]
                             ) -> tuple[str, str] | None:
    """Return (action, remaining_args) when the FIRST word of `text` is a
    configured moderation command token, else None.

    Only exact configured tokens match, so ordinary chat mentioning the word
    "ban" is never treated as a command."""
    if not text:
        return None
    parts = text.strip().split(None, 1)
    if not parts:
        return None
    first = parts[0].strip()
    rest = parts[1].strip() if len(parts) > 1 else ""
    token = first.lower()
    action = index.get(token)
    if action is None:
        # tolerate "/ban@SomeBot" for ANY addressee (bot-agnostic)
        stripped = _ADDRESSEE_RE.sub("", first).lower()
        if stripped and stripped != token:
            action = index.get(stripped)
    return (action, rest) if action else None


class PendingActions:
    """In-memory pending-moderation queue for initiator correlation.

    Keys: (chat_id, kind, target_id) → deque of pending items, each
    {initiator_id, message_id, created_at}. Pending items expire quickly
    (a few correlation windows) so they can never match unrelated future
    actions; matched items are consumed exactly once (no double counting).
    """

    def __init__(self, window_seconds: int, max_per_key: int = 16) -> None:
        self.window = max(3, int(window_seconds))
        self.max_per_key = max_per_key
        self._items: dict[tuple[int, str, int], deque[dict]] = defaultdict(deque)

    def add(self, chat_id: int, kind: str, target_id: int, *,
            initiator_id: int, message_id: int, created_at: float) -> None:
        key = (chat_id, kind, target_id)
        dq = self._items[key]
        dq.append({"initiator_id": initiator_id, "message_id": message_id,
                   "created_at": created_at})
        self._prune(dq, created_at)
        while len(dq) > self.max_per_key:
            dq.popleft()

    def match(self, chat_id: int, kind: str, target_id: int,
              now: float | None = None) -> dict | None:
        """Oldest unexpired match wins; the matched item is REMOVED once."""
        now = now or time.time()
        dq = self._items.get((chat_id, kind, target_id))
        if not dq:
            return None
        self._prune(dq, now)
        if not dq:
            return None
        return dq.popleft() if dq[0]["created_at"] >= now - self.window else None

    # Restriction-family kinds are interchangeable for fuzzy correlation:
    # a custom bot may answer "/kill" with a ban, or "/mute" with a kick.
    _FUZZY_FAMILY = {"ban": ("ban", "restrict"),
                     "restrict": ("restrict", "ban"),
                     "unban": ("unban",),
                     "promote": ("promote",),
                     "demote": ("demote",)}

    def match_related(self, chat_id: int, kind: str, target_id: int,
                      now: float | None = None) -> tuple[dict | None, bool]:
        """Exact-kind match first; if none, try the related kind family for
        the SAME chat+target inside the window.

        Returns (item, fuzzy). This keeps attribution working for bots whose
        command vocabulary does not map 1:1 onto Telegram's admin-log action
        types — without ever assuming which bot is involved."""
        exact = self.match(chat_id, kind, target_id, now)
        if exact is not None:
            return exact, False
        for alt in self._FUZZY_FAMILY.get(kind, ())[1:]:
            item = self.match(chat_id, alt, target_id, now)
            if item is not None:
                return item, True
        return None, False

    def _prune(self, dq: deque[dict], now: float) -> None:
        cutoff = now - max(self.window * 4, 30)
        while dq and dq[0]["created_at"] < cutoff:
            dq.popleft()

    def pending_count(self, chat_id: int) -> int:
        return sum(len(dq) for (cid, _, _), dq in self._items.items()
                   if cid == chat_id)


def display_name(entity: Any, user_id: int | None = None) -> str:
    """Human label for a user/chat without exposing anything sensitive."""
    if entity is None:
        return f"id:{user_id}" if user_id is not None else "unknown"
    username = getattr(entity, "username", None)
    first = getattr(entity, "first_name", None) or getattr(entity, "title", None)
    if username:
        return f"@{username}"
    if first:
        uid = getattr(entity, "id", user_id)
        return f"{first} (id:{uid})"
    uid = getattr(entity, "id", user_id)
    return f"id:{uid}"


def participant_user_id(participant: Any) -> int | None:
    """Extract a user id across TL layers (some layers embed a Peer)."""
    if participant is None:
        return None
    uid = getattr(participant, "user_id", None)
    if uid:
        return int(uid)
    peer = getattr(participant, "peer", None)
    if peer is not None:
        try:
            return utils.get_peer_id(peer)
        except Exception:
            return None
    return None


class CallResult:
    """Uniform (ok, value-or-error) envelope for every Telegram RPC."""

    def __init__(self, ok: bool, value: Any = None, error: str | None = None):
        self.ok = ok
        self.value = value
        self.error = error

    def __bool__(self) -> bool:
        return self.ok


class UserbotManager:
    """Owns the Telethon client lifecycle, group registry, event handlers
    and the admin-log monitoring loop."""

    def __init__(self, db: Database, cipher: security.SessionCipher,
                 notifier: Notifier, status: dict) -> None:
        self.db = db
        self.cipher = cipher
        self.notifier = notifier
        self.status = status
        self.client: TelegramClient | None = None
        self.self_id: int | None = None
        self.me: Any = None
        self.running = False
        self._monitor_task: asyncio.Task | None = None
        # Short-lived cache of our own permissions per chat (60 s TTL).
        self._perm_cache: dict[int, tuple[float, Any]] = {}
        # Anti-flood tracking: (chat_id, user_id) → deque[(monotonic, msg_id)]
        self._spam_hits: dict[tuple[int, int], deque] = defaultdict(deque)
        self._spam_alerts: dict[tuple[int, int], float] = {}
        # Set while admin monitoring is switched off in /settings; forces a
        # cursor re-seed on resume so paused activity isn't misread as a burst.
        self._monitor_suspended = False
        # Two-layer abuse detection state:
        self._pending = PendingActions(config.ADMIN_CORRELATION_WINDOW)
        self._cmd_index: dict[str, str] | None = None
        self._cmd_index_at = 0.0
        # Rate-limit for UNKNOWN-executor notifications, keyed by executor.
        self._unknown_alerts: dict[tuple[int, int], float] = {}
        # small TTL caches to avoid re-resolving the same actors/labels
        self._actor_bot_cache: dict[int, tuple[float, bool]] = {}
        self._label_cache: dict[int, tuple[float, str]] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self, user_id: int) -> tuple[bool, str | None]:
        """Load the stored (encrypted) session and connect."""
        row = self.db.get_session(user_id)
        if not row:
            return False, "No stored session — run /login first."
        session_string = self.cipher.decrypt(row["encrypted_session"])
        if not session_string:
            return False, ("Stored session could not be decrypted "
                           "(SESSION_SECRET mismatch?). Run /login again.")
        client = TelegramClient(
            StringSession(session_string), config.API_ID, config.API_HASH,
            device_model=config.DEVICE_MODEL,
        )
        try:
            await client.connect()
            if not await client.is_user_authorized():
                # Session was revoked server-side (or auth key expired).
                await client.disconnect()
                return False, ("Stored session is no longer authorized "
                               "(revoked or expired). Run /login again.")
            self.client = client
            self.me = await client.get_me()
            self.self_id = int(self.me.id)
        except (SessionRevokedError, AuthKeyUnregisteredError):
            await client.disconnect()
            return False, "Session was revoked remotely. Run /login again."
        except UserDeactivatedBanError:
            await client.disconnect()
            return False, "This account is deactivated/banned by Telegram."
        except Exception as exc:  # network etc. — never crash live.py
            await client.disconnect()
            log.error("Userbot connect failed: %s", security.redact(str(exc)))
            return False, f"Connection failed: {type(exc).__name__}"

        self._register_handlers()
        await self.sync_groups()
        self.running = True
        self.status["userbot"] = True
        self.status["userbot_account"] = self.self_id
        self._monitor_task = asyncio.create_task(
            self._adminlog_supervisor(), name="adminlog-supervisor")
        log.info("Userbot online as id=%s; monitoring %d group(s).",
                 self.self_id, len(self.db.enabled_groups()))
        return True, None

    async def stop(self, revoke: bool = False) -> None:
        """Disconnect. With revoke=True, additionally invalidate the session
        server-side (auth.logOut) so the authorization disappears from the
        account's active-session list — a true logout, not just a disconnect."""
        self.running = False
        self.status["userbot"] = False
        if self._monitor_task:
            self._monitor_task.cancel()
            self._monitor_task = None
        client = self.client
        self.client = None
        self._perm_cache.clear()
        if client:
            try:
                if revoke:
                    await client.log_out()   # server-side session revocation
                    log.info("MTProto session revoked via auth.logOut.")
                else:
                    await client.disconnect()
            except Exception as exc:
                log.warning("Userbot stop: %s", security.redact(str(exc)))
        if revoke and self.self_id is not None:
            self.db.revoke_session(self.self_id)
        self.self_id = None
        self.me = None

    # ------------------------------------------------------------------
    # Guarded RPC helper — one moderation failure must never kill the app
    # ------------------------------------------------------------------

    async def call(self, coro: Awaitable[Any], desc: str,
                   retry_floodwait: bool = True) -> CallResult:
        """Execute a Telegram call translating every known failure mode into
        a readable error string. Secrets are structurally absent from these
        calls; even so, error text is redacted before logging."""
        for attempt in (0, 1):
            try:
                return CallResult(True, await coro)
            except FloodWaitError as fw:
                if attempt == 0 and retry_floodwait and \
                        fw.seconds <= config.MAX_FLOODWAIT_SLEEP:
                    log.warning("FloodWait %ss during %s — waiting once.",
                                fw.seconds, desc)
                    await asyncio.sleep(fw.seconds + 1)
                    continue
                return CallResult(False, error=(
                    f"Rate-limited by Telegram (wait {fw.seconds}s). "
                    "Slow down and retry."))
            except ChatAdminRequiredError:
                return CallResult(False, error=(
                    "Insufficient admin rights: the connected account lacks "
                    f"the permission required to {desc}."))
            except UserAdminInvalidError:
                return CallResult(False, error=(
                    "Telegram refused: this administrator is protected by "
                    "the admin hierarchy and cannot be modified by the "
                    "connected account (only the group owner, or the admin "
                    "who promoted them, can)."))
            except UserNotParticipantError:
                return CallResult(False, error="User is not a member of this group.")
            except ChannelPrivateError:
                return CallResult(False, error=(
                    "The connected account no longer has access to this group."))
            except (SessionRevokedError, AuthKeyUnregisteredError):
                self.status["userbot"] = False
                return CallResult(False, error=(
                    "Session was revoked/expired — please /login again."))
            except RPCError as rpc:
                msg = security.redact(str(rpc))
                log.warning("RPC error during %s: %s", desc, msg)
                return CallResult(False, error=f"Telegram API error: {msg}")
            except Exception as exc:
                msg = security.redact(str(exc))
                log.exception("Unexpected error during %s", desc)
                return CallResult(False, error=f"Unexpected error: {type(exc).__name__}")
        return CallResult(False, error="unreachable")

    # ------------------------------------------------------------------
    # Permission introspection
    # ------------------------------------------------------------------

    async def permissions(self, chat: Any, user: Any) -> Any | None:
        """Fetch ParticipantPermissions for `user` in `chat` (None on error)."""
        res = await self.call(client_call(self.client, chat, user,
                                          what="permissions"),
                              desc="read permissions")
        return res.value if res.ok else None

    async def self_permissions(self, chat: Any) -> Any | None:
        """Cached fetch of the connected account's rights in a chat."""
        chat_id = utils.get_peer_id(chat) if not isinstance(chat, int) else chat
        cached = self._perm_cache.get(chat_id)
        if cached and time.monotonic() - cached[0] < 60:
            return cached[1]
        res = await self.call(
            self.client.get_permissions(chat, "me"),  # type: ignore[union-attr]
            desc="read own permissions")
        if res.ok:
            self._perm_cache[chat_id] = (time.monotonic(), res.value)
            return res.value
        return None

    async def can_modify_admin(self, chat: Any) -> bool:
        """True if the connected account may legally promote/demote admins
        (creator, or admin holding the add_admins right). Telegram may still
        refuse for hierarchy reasons — always followed by a try/except."""
        perms = await self.self_permissions(chat)
        if perms is None:
            return False
        if getattr(perms, "is_creator", False):
            return True
        return bool(getattr(perms, "add_admins", False))

    async def can_ban(self, chat: Any) -> bool:
        perms = await self.self_permissions(chat)
        if perms is None:
            return False
        return bool(getattr(perms, "is_creator", False)
                    or getattr(perms, "ban_users", False))

    # ------------------------------------------------------------------
    # Moderation primitives (permission checks happen in admin_commands /
    # _enforce_call sites; these only perform the RPC safely)
    # ------------------------------------------------------------------

    async def apply_ban_rights(self, chat: Any, user: Any,
                               rights: t.ChatBannedRights,
                               desc: str) -> CallResult:
        return await self.call(
            self.client(functions.channels.EditBannedRequest(chat, user, rights)),  # type: ignore[union-attr]
            desc=desc)

    async def ban_user(self, chat: Any, user: Any, desc: str = "ban user") -> CallResult:
        return await self.apply_ban_rights(chat, user, _BAN_RIGHTS, desc)

    async def unban_user(self, chat: Any, user: Any, desc: str = "unban user") -> CallResult:
        return await self.apply_ban_rights(chat, user, _UNBAN_RIGHTS, desc)

    async def mute_user(self, chat: Any, user: Any, seconds: int | None = None,
                        desc: str = "mute user") -> CallResult:
        until = (utc_now() + timedelta(seconds=seconds)) if seconds else None
        rights = t.ChatBannedRights(
            until_date=until,
            send_messages=True, send_media=True, send_stickers=True,
            send_gifs=True, send_games=True, send_inline=True,
            embed_links=True, send_polls=True, send_photos=True,
            send_videos=True, send_audios=True, send_voices=True,
            send_roundvideos=True,
        )
        return await self.apply_ban_rights(chat, user, rights, desc)

    async def gmute_restrict(self, chat: Any, user: Any, desc: str) -> CallResult:
        return await self.apply_ban_rights(chat, user, _GMUTE_RIGHTS, desc)

    async def demote_user(self, chat: Any, user: Any, desc: str = "demote admin") -> CallResult:
        empty = t.ChatAdminRights()  # every flag False ⇒ full demotion
        return await self.call(
            self.client(functions.channels.EditAdminRequest(chat, user, empty, "")),  # type: ignore[union-attr]
            desc=desc)

    async def promote_user(self, chat: Any, user: Any,
                           desc: str = "promote user") -> CallResult:
        rights = t.ChatAdminRights(
            change_info=True, post_messages=False, edit_messages=False,
            delete_messages=True, ban_users=True, invite_users=True,
            pin_messages=True, add_admins=False, anonymous=False,
            manage_call=True, other=False, manage_topics=True,
        )
        return await self.call(
            self.client(functions.channels.EditAdminRequest(chat, user, rights, "moderator")),  # type: ignore[union-attr]
            desc=desc)

    async def resolve_chat(self, chat_id: int) -> Any:
        """Resolve a stored bare chat id to its full Channel entity (with the
        access hash already known from dialog sync). Raises on real failure."""
        assert self.client is not None
        try:
            return await self.client.get_entity(t.PeerChannel(int(chat_id)))
        except Exception:
            # Basic (non-migrated) group or cache refresh needed.
            return await self.client.get_entity(int(chat_id))

    async def run_moderation(self, op: str, chat_id: int | None,
                             target_id: int, actor_id: int,
                             duration: int | None = None
                             ) -> tuple[bool, str]:
        """Execute a moderation op issued via the MANAGEMENT BOT.

        Runs the same shields as the in-group commands — owner protection,
        connected-account protection, right checks, Telegram admin hierarchy —
        and audits every outcome. Returns (ok, user-facing message)."""
        if not self.client or not self.running:
            return False, "Security worker offline — /login, then /rescan."

        shield = security.guard_target(actor_id, target_id)
        if shield:
            return False, shield
        if target_id == self.self_id:
            return False, ("Refused: the connected account cannot be its own "
                           "moderation target.")

        # -- resolve target entity --------------------------------------
        target_entity: Any = None
        for probe in (target_id, t.PeerUser(int(target_id))):
            try:
                target_entity = await self.client.get_entity(probe)
                break
            except Exception:
                continue

        # -- global ops (no group picker needed) -------------------------
        if op == "gmute":
            if target_entity is None:
                # Identity not resolvable yet: the ID is remembered and the
                # restriction applies on sight — exactly like in-group /gmute.
                target_entity = target_id
            self.db.add_gmute(target_id, None, added_by=actor_id)
            applied, skipped = 0, 0
            for grp in self.db.enabled_groups():
                try:
                    chat = await self.resolve_chat(grp["chat_id"])
                except Exception:
                    skipped += 1
                    continue
                if not await self.can_ban(chat):
                    skipped += 1
                    continue
                tperms = await self.permissions(chat, target_entity)
                if tperms is None:
                    continue  # appears later → restriction applies then
                if getattr(tperms, "is_creator", False):
                    skipped += 1
                    continue  # never another group's owner
                res = await self.gmute_restrict(chat, target_entity,
                                                desc="apply global mute")
                if res.ok:
                    applied += 1
                else:
                    skipped += 1
            self.db.log_event(None, actor_id, target_id, "gmute",
                              f"applied={applied} skipped={skipped}")
            name = display_name(target_entity, target_id) \
                if not isinstance(target_entity, int) else f"id:{target_id}"
            return True, (f"{name} added to the global mute list. Restricted "
                          f"in {applied} configured group(s); the restriction "
                          "applies on sight everywhere else.")

        if op == "ungmute":
            existed = self.db.remove_gmute(target_id)
            lifted = 0
            for grp in self.db.enabled_groups():
                try:
                    chat = await self.resolve_chat(grp["chat_id"])
                except Exception:
                    continue
                if not await self.can_ban(chat):
                    continue
                res = await self.unban_user(chat, target_entity or target_id,
                                            desc="lift global mute")
                if res.ok:
                    lifted += 1
            self.db.log_event(None, actor_id, target_id, "ungmute",
                              "ok" if existed else "not-listed")
            if not existed:
                return True, "That user was not on the global mute list."
            return True, (f"Removed from the global mute list; restrictions "
                          f"lifted in {lifted} group(s).")

        # -- group ops -----------------------------------------------------
        if chat_id is None:
            return False, "This action needs a target group."
        group = self.db.get_group(chat_id)
        if not group or not group["enabled"]:
            return False, "That group is not protected (enabled) by this system."
        try:
            chat = await self.resolve_chat(chat_id)
        except Exception as exc:
            return False, f"Cannot access the group: {type(exc).__name__}"

        perms = await self.self_permissions(chat)
        if perms is None or not (getattr(perms, "is_admin", False)
                                 or getattr(perms, "is_creator", False)):
            return False, ("The connected account is not an administrator in "
                           "that group — no moderation action is possible.")
        need_right = {"mute": "ban_users", "unmute": "ban_users",
                      "ban": "ban_users", "unban": "ban_users",
                      "kick": "ban_users", "promote": "add_admins",
                      "demote": "add_admins"}.get(op)
        if need_right and not getattr(perms, "is_creator", False) \
                and not getattr(perms, need_right, False):
            return False, (f"Missing Telegram permission: the connected "
                           f"account needs '{need_right.replace('_', ' ')}' "
                           f"rights for /{op}.")
        if target_entity is None:
            return False, ("Cannot resolve that user from here — use "
                           "@username or a visible group member.")

        tperms = await self.permissions(chat, target_entity)
        if tperms is not None and getattr(tperms, "is_creator", False):
            return False, ("Telegram does not allow modifying the group "
                           "owner — action refused.")
        if op in {"ban", "kick", "mute", "demote"} \
                and tperms is not None and getattr(tperms, "is_admin", False) \
                and not await self.can_modify_admin(chat):
            return False, ("The target is an administrator this account "
                           "cannot modify (Telegram admin hierarchy). Only "
                           "the group owner or their promoting admin can.")

        if op == "mute":
            res = await self.mute_user(chat, target_entity, seconds=duration,
                                       desc="bot-command mute")
            label = "Muted" + (f" for {duration}s" if duration else "")
        elif op == "unmute":
            res = await self.unban_user(chat, target_entity,
                                        desc="bot-command unmute")
            label = "Unmuted"
        elif op == "ban":
            res = await self.ban_user(chat, target_entity, desc="bot-command ban")
            label = "Banned"
        elif op == "unban":
            res = await self.unban_user(chat, target_entity,
                                        desc="bot-command unban")
            label = "Unbanned"
        elif op == "kick":
            ban = await self.ban_user(chat, target_entity, desc="bot-command kick")
            res = await self.unban_user(chat, target_entity,
                                        desc="bot-command kick (rejoin allowed)") \
                if ban.ok else ban
            label = "Kicked"
        elif op == "promote":
            res = await self.promote_user(chat, target_entity,
                                          desc="bot-command promote")
            label = "Promoted"
        elif op == "demote":
            res = await self.demote_user(chat, target_entity,
                                         desc="bot-command demote")
            label = "Demoted"
        else:
            return False, f"Unknown moderation op: {op}"

        self.db.log_event(chat_id, actor_id, target_id, f"bot.{op}",
                          "ok" if res.ok else f"failed: {res.error}",
                          group_title=group["title"])
        if res.ok:
            return True, f"{label} successfully."
        return False, f"{label} failed: {res.error}"

    async def send_owner_dm(self, text: str) -> None:
        """Owner notifications go through the management BOT (notifier) —
        the userbot itself never initiates unsolicited conversations."""
        try:
            await self.notifier(text)
        except Exception as exc:
            log.error("Owner notification failed: %s", security.redact(str(exc)))

    # ------------------------------------------------------------------
    # Group registry
    # ------------------------------------------------------------------

    async def sync_groups(self) -> int:
        """Register every group where the connected account is legitimately
        an administrator. Groups the operator previously disabled stay
        disabled (their row is left untouched)."""
        if not self.client:
            return 0
        count = 0
        try:
            async for dialog in self.client.iter_dialogs():
                entity = dialog.entity
                if not isinstance(entity, t.Channel) or not entity.megagroup:
                    continue
                if getattr(entity, "admin_rights", None) is None \
                        and not getattr(entity, "creator", False):
                    continue
                existing = self.db.get_group(entity.id)
                enabled = bool(existing["enabled"]) if existing else True
                if not existing:
                    self.db.upsert_group(entity.id, dialog.title,
                                         added_by=self.self_id, enabled=enabled)
                else:
                    self.db.execute("UPDATE groups SET title=? WHERE chat_id=?",
                                    (dialog.title, entity.id))
                count += 1
        except Exception as exc:
            log.warning("Group sync incomplete: %s", security.redact(str(exc)))
        return count

    def _register_handlers(self) -> None:
        assert self.client is not None
        self.client.add_event_handler(
            self._on_group_message,
            events.NewMessage(func=lambda e: e.is_group and not e.out))
        self.client.add_event_handler(
            self._on_member_join,
            events.NewMessage(
                func=lambda e: e.is_group and isinstance(
                    getattr(e.message, "action", None), _JOIN_ACTIONS)))
        # Layer B of admin-abuse detection: observe moderation requests
        # spoken by ANYONE in the group, addressed to ANY executor (any bot,
        # userbot or account — including ones that appear tomorrow).
        # Records pending actions ONLY — executes nothing.
        self.client.add_event_handler(
            self._track_pending_command,
            events.NewMessage(
                func=lambda e: e.is_group and bool(e.raw_text)
                and e.raw_text.startswith("/")))
        # Trusted-role moderation commands live in admin_commands.py.
        import admin_commands
        admin_commands.register(self.client, self)

    # ------------------------------------------------------------------
    # Global-mute enforcement
    # ------------------------------------------------------------------

    async def _restrict_if_gmuted(self, chat: Any, user_id: int,
                                  message: Any | None = None) -> None:
        """Restrict a gmuted user the moment they appear/speak. Only acts in
        *configured* groups (db.enabled_groups) where we hold ban rights —
        never does mass actions across unrelated chats."""
        chat_id = getattr(chat, "id", None)
        if chat_id is None and message is not None:
            chat_id = message.chat_id
        group = self.db.get_group(chat_id) if chat_id is not None else None
        if not group or not group["enabled"]:
            return
        if not self.db.is_gmuted(user_id):
            return
        if security.is_owner(user_id):
            return  # owner shield — the owner is never restricted
        if not await self.can_ban(chat):
            log.warning("gmute: no ban rights in %s, cannot restrict id=%s",
                        group["chat_id"], user_id)
            return
        if message is not None:
            await self.call(self.client.delete_messages(chat, [message.id]),  # type: ignore[union-attr]
                            desc="delete gmuted message")
        res = await self.gmute_restrict(chat, user_id,
                                        desc="enforce global mute")
        self.db.log_event(group["chat_id"], self.self_id, user_id,
                          "gmute.enforce",
                          "ok" if res.ok else f"failed: {res.error}",
                          group_title=group["title"])

    async def _on_group_message(self, event: events.NewMessage.Event) -> None:
        sender_id = event.sender_id
        if not sender_id or sender_id == self.self_id:
            return
        chat = await event.get_chat()
        await self._spam_guard(event, chat, sender_id)
        await self._restrict_if_gmuted(chat, sender_id, event.message)

    # ------------------------------------------------------------------
    # Layer B — moderation-command monitoring (record only, never execute)
    # ------------------------------------------------------------------

    def _is_protected(self, user_id: int | None) -> bool:
        """Immutable protected set: the configured owner AND the connected
        account's real ID (from get_me() at login, not a guessed PeerUser)."""
        if user_id is None:
            return False
        return security.is_owner(user_id) or user_id == self.self_id

    def command_index(self) -> dict[str, str]:
        """Configured patterns + runtime additions from the settings store.
        Cached for 60s so operators can extend patterns without a restart."""
        now = time.monotonic()
        if self._cmd_index is not None and now - self._cmd_index_at < 60:
            return self._cmd_index
        extra: dict[str, list[str]] = {}
        raw = self.db.get_setting("custom_mod_patterns")
        if raw:
            try:
                import json
                loaded = json.loads(raw)
                if isinstance(loaded, dict):
                    extra = {str(k): ([v] if isinstance(v, str) else list(v))
                             for k, v in loaded.items()}
            except Exception:
                log.warning("custom_mod_patterns setting is not valid JSON")
        self._cmd_index = build_command_index(extra)
        self._cmd_index_at = now
        return self._cmd_index

    async def _track_pending_command(self, event: events.NewMessage.Event) -> None:
        """Remember moderation *requests* (initiator, target, action) so a
        later admin-log action can be attributed to the human who asked.

        Executor-agnostic: we do not know or care which bot/account will carry
        the request out — that is resolved later by admin-log correlation.
        This handler NEVER executes anything."""
        try:
            sender = event.sender_id
            if not sender or sender == self.self_id:
                return
            matched = match_moderation_command(event.raw_text,
                                               self.command_index())
            if not matched:
                return
            verb, args = matched
            kind = _VERB_TO_KIND.get(verb)
            if not kind:
                return

            # Pending entries are only useful for attribution of actions we
            # did not perform ourselves; commands from our own trust roles
            # are executed + audited by admin_commands.py already.
            if self.db.get_admin_role(sender) is not None:
                return

            chat = await event.get_chat()
            chat_id = getattr(chat, "id", None)
            if chat_id is None:
                return
            group = self.db.get_group(chat_id)
            if not group or not group["enabled"]:
                return  # only configured groups — never unrelated chats

            target_id = await self._command_target(event, args)
            if target_id is None:
                return  # cannot correlate without a numeric target ID

            self._pending.add(
                int(chat_id), kind, target_id,
                initiator_id=int(sender), message_id=event.message.id,
                created_at=time.time())
            log.info("[ADMIN ACTION] pending %s recorded: initiator=%s "
                     "target=%s chat=%s msg=%s",
                     verb, sender, target_id, chat_id, event.message.id)
        except Exception as exc:  # observer must never break the worker
            log.warning("pending-command tracker error: %s",
                        security.redact(str(exc)))

    async def _command_target(self, event, args: str) -> int | None:
        """Resolve the numeric target ID for a moderation verb: replied-to
        author first, then @username / numeric ID token. Usernames are used
        ONLY to resolve to an ID once — the ID is what we store."""
        try:
            reply = await event.get_reply_message()
        except Exception:
            reply = None
        if reply is not None and reply.sender_id:
            return int(reply.sender_id)
        for tok in args.split():
            if tok.startswith("/") or _DURATION_TOKEN_RE.match(tok):
                continue
            if tok.startswith("@"):
                try:
                    entity = await self.client.get_entity(tok.lstrip("@"))  # type: ignore[union-attr]
                    if not isinstance(entity, t.Channel):
                        return int(entity.id)
                except Exception:
                    continue
            elif tok.lstrip("-").isdigit() and len(tok) >= 6:
                return int(tok)
        return None

    async def _spam_guard(self, event: events.NewMessage.Event, chat: Any,
                          sender_id: int) -> None:
        """Lightweight anti-flood spam protection (toggle: spam_protection).

        Strictly defensive and local: inside protected groups only, after the
        configured per-user burst threshold is crossed, the flood messages are
        deleted and the sender is muted for SPAM_MUTE_SECONDS. Group admins,
        trust-role members and the owner are never targeted.
        """
        if security.is_owner(sender_id):
            return
        if not self.db.get_feature("spam_protection"):
            return
        chat_id = getattr(chat, "id", None)
        if chat_id is None:
            return
        group = self.db.get_group(chat_id)
        if not group or not group["enabled"]:
            return
        if self.db.get_admin_role(sender_id) is not None:
            return  # trust-role members are exempt

        key = (int(chat_id), int(sender_id))
        now = time.monotonic()
        dq = self._spam_hits[key]
        dq.append((now, event.message.id))
        while dq and dq[0][0] < now - config.SPAM_WINDOW:
            dq.popleft()
        if len(dq) < config.SPAM_LIMIT:
            return

        # threshold crossed — verify target and our rights before acting
        tperms = await self.permissions(chat, event.message.sender_id)
        if tperms is not None and (getattr(tperms, "is_creator", False)
                                   or getattr(tperms, "is_admin", False)):
            dq.clear()
            return  # never punish group admins for hyperactivity
        if not await self.can_ban(chat):
            dq.clear()
            log.warning("spam guard: no ban rights in %s — cannot act.", chat_id)
            return

        ids = [mid for _, mid in dq]
        dq.clear()
        await self.call(self.client.delete_messages(chat, ids),  # type: ignore[union-attr]
                        desc="delete flood messages")
        res = await self.mute_user(chat, event.message.sender_id,
                                   seconds=config.SPAM_MUTE_SECONDS,
                                   desc="anti-flood mute")
        self.db.log_event(chat_id, self.self_id, sender_id,
                          "security.spam_flood",
                          "ok" if res.ok else f"failed: {res.error}",
                          group_title=group["title"])

        last = self._spam_alerts.get(key, 0.0)
        if time.time() - last > 300:  # alert rate-limit: 5 minutes
            self._spam_alerts[key] = time.time()
            try:
                who = await self.client.get_entity(sender_id)  # type: ignore[union-attr]
            except Exception:
                who = None
            alert = security.render_security_alert(
                group_title=group["title"] or str(chat_id),
                group_id=chat_id,
                admin_display=display_name(who, sender_id),
                admin_id=sender_id,
                action_detected=(f"Spam flood — {len(ids)}+ messages in "
                                 f"{config.SPAM_WINDOW}s"),
                steps=[
                    (True, "Event recorded"),
                    (bool(res.ok), f"Sender muted for "
                                   f"{config.SPAM_MUTE_SECONDS // 60} minutes"
                                   + ("" if res.ok else f" — failed: {res.error}")),
                    (True, "Flood messages deleted"),
                    (True, "Owner notified"),
                ])
            await self.send_owner_dm(alert)

    async def _on_member_join(self, event: events.NewMessage.Event) -> None:
        chat = await event.get_chat()
        chat_id = getattr(chat, "id", None)
        if chat_id is None:
            return
        group = self.db.get_group(chat_id)
        if not group or not group["enabled"]:
            return

        action = event.message.action
        joined: list[int] = []
        if isinstance(action, t.MessageActionChatAddUser):
            joined = [int(u) for u in (action.users or [])]
        else:  # joined by link / approved request → sender joined themselves
            uid = utils.get_peer_id(event.message.from_id) \
                if event.message.from_id else event.sender_id
            if uid:
                joined = [int(uid)]

        for uid in joined:
            if security.is_owner(uid):
                continue
            # 1) Global mute list
            if self.db.is_gmuted(uid) and await self.can_ban(chat):
                res = await self.gmute_restrict(chat, uid,
                                                desc="enforce global mute on join")
                self.db.log_event(chat_id, self.self_id, uid,
                                  "gmute.enforce_on_join",
                                  "ok" if res.ok else f"failed: {res.error}",
                                  group_title=group["title"])
                continue
            # 2) Lockdown: new joiners are restricted while active
            if group["lockdown"] and config.LOCKDOWN_RESTRICT_NEW_MEMBERS \
                    and await self.can_ban(chat):
                await self.gmute_restrict(chat, uid,
                                          desc="lockdown new-member restriction")

    def _audit_observed(self, group_id: int, admin_id: int | None,
                        target_id: int | None, action: str,
                        group_title: str | None = None) -> None:
        """Routine 'observed' audit writes honor the audit_logging toggle.
        (security.* responses and enforcement actions are always recorded.)"""
        if not self.db.get_feature("audit_logging"):
            return
        self.db.log_event(group_id, admin_id, target_id, action, "observed",
                          group_title=group_title)

    # ------------------------------------------------------------------
    # Admin-log monitoring
    # ------------------------------------------------------------------

    async def _adminlog_supervisor(self) -> None:
        """Poll each configured group's admin log. Telethon does not push
        admin-log events to us, so periodic polling with a persistent cursor
        is the correct, respectful approach (no flood — one request per
        group per interval)."""
        await asyncio.sleep(5)  # let startup settle
        while self.running and self.client:
            try:
                await self._poll_all_groups()
            except asyncio.CancelledError:
                return
            except Exception as exc:
                log.error("Admin-log loop error: %s", security.redact(str(exc)))
            await asyncio.sleep(config.ADMIN_LOG_POLL_INTERVAL)

    async def _poll_all_groups(self) -> None:
        if not self.db.get_feature("admin_monitoring"):
            # Monitoring paused via /settings: make no API calls, and remember
            # to re-seed cursors on resume so during-pause admin activity is
            # never mistaken for a fresh mass-action burst.
            self._monitor_suspended = True
            return
        for group in self.db.enabled_groups():
            if not self.running:
                return
            try:
                await self._poll_group(group, reseed=self._monitor_suspended)
            except Exception as exc:
                log.warning("Admin-log poll failed for %s: %s",
                            group["chat_id"], security.redact(str(exc)))
        self._monitor_suspended = False

    async def _poll_group(self, group: Any, reseed: bool = False) -> None:
        chat_id = group["chat_id"]
        cursor = self.db.get_adminlog_cursor(chat_id)
        try:
            entity = await self.client.get_entity(chat_id)  # type: ignore[union-attr]
        except Exception:
            return
        if not isinstance(entity, t.Channel):
            return

        try:
            entries = [e async for e in self.client.get_admin_log(  # type: ignore[union-attr]
                entity, limit=config.ADMIN_LOG_PAGE, min_id=cursor or 0)]
        except ChatAdminRequiredError:
            # We lost admin rights — disable monitoring for this group.
            self.db.set_group_enabled(chat_id, False)
            log.info("Admin rights lost in %s — group disabled.", chat_id)
            return
        except FloodWaitError as fw:
            await asyncio.sleep(min(fw.seconds + 1, config.MAX_FLOODWAIT_SLEEP))
            return
        except Exception as exc:
            log.warning("Admin-log fetch failed in %s: %s",
                        chat_id, security.redact(str(exc)))
            return

        if not entries:
            return
        newest = max(e.id for e in entries)
        if not cursor or reseed:
            # First poll (or resume after monitoring was paused): establish
            # the cursor without replaying history, so old admin activity
            # never triggers false mass-action alerts.
            self.db.set_adminlog_cursor(chat_id, newest)
            return
        self.db.set_adminlog_cursor(chat_id, newest)

        for entry in sorted(entries, key=lambda e: e.id):
            try:
                await self._handle_admin_event(group, entity, entry)
            except Exception as exc:
                log.error("Admin event handling error: %s",
                          security.redact(str(exc)))

    async def _handle_admin_event(self, group: Any, chat: Any,
                                  entry: t.ChannelAdminLogEvent) -> None:
        action = entry.action
        actor = int(entry.user_id) if entry.user_id else None
        chat_id = group["chat_id"]

        # Our own actions are already audited at command time.
        if actor == self.self_id:
            return

        # ---- bans / restrictions / unbans -------------------------------
        if isinstance(action, t.ChannelAdminLogEventActionParticipantToggleBan):
            prev, new = action.prev_participant, action.new_participant
            target = participant_user_id(new) or participant_user_id(prev)
            if target is None:
                return
            new_banned = isinstance(new, t.ChannelParticipantBanned)
            if new_banned:
                rights: t.ChatBannedRights = new.banned_rights
                kind = "ban" if (getattr(rights, "view_messages", False)
                                 or getattr(new, "kicked", False)) \
                    else "restrict"
                await self._attributed_admin_action(
                    group, chat, actor, target, kind, entry)
            else:
                prev_banned = isinstance(prev, t.ChannelParticipantBanned)
                if prev_banned:
                    await self._attributed_admin_action(
                        group, chat, actor, target, "unban", entry)
            return

        # ---- message deletions -------------------------------------------
        if isinstance(action, t.ChannelAdminLogEventActionDeleteMessage):
            await self._mass_delete_check(group, chat, actor)
            return

        # ---- admin promotions / demotions (incl. manual detection) -------
        if isinstance(action, t.ChannelAdminLogEventActionParticipantToggleAdmin):
            prev, new = action.prev_participant, action.new_participant
            target = participant_user_id(new) or participant_user_id(prev)
            if target is None:
                return
            new_admin = isinstance(new, t.ChannelParticipantAdmin) and new.admin_rights
            was_admin = isinstance(prev, t.ChannelParticipantAdmin) and prev.admin_rights
            if new_admin and not was_admin:
                # gated by ADMIN_PERMISSION_CHANGE_PROTECTION
                if config.ADMIN_PERMISSION_CHANGE_PROTECTION:
                    await self._on_manual_promotion(group, chat, actor, target)
                else:
                    self._audit_observed(chat_id, actor, target, "admin.promote",
                                         group_title=group["title"])
            elif was_admin and not new_admin:
                # correlate a possible /demote command for attribution
                pending = self._pending.match(chat_id, "demote", target)
                self.db.add_admin_security_event(
                    chat_id=chat_id,
                    initiator_id=int(pending["initiator_id"]) if pending else actor,
                    executor_id=actor, target_id=target, action="demote",
                    source="command+admin_log" if pending else "admin_log",
                    correlated=bool(pending), action_taken="observed")
                self._audit_observed(chat_id, actor, target, "admin.demote",
                                     group_title=group["title"])
            else:
                self._audit_observed(chat_id, actor, target,
                                     "admin.rights_change",
                                     group_title=group["title"])
            return

        # ---- default member rights changed (relevant to lockdown) --------
        if isinstance(action, t.ChannelAdminLogEventActionDefaultBannedRights):
            self._audit_observed(chat_id, actor, None, "admin.default_rights",
                                 group_title=group["title"])
            return

    # ------------------------------------------------------------------
    # Layer A+B — initiator attribution + admin-abuse thresholds
    # ------------------------------------------------------------------

    async def _is_bot_account(self, user_id: int) -> bool:
        """Cached check whether an admin-log actor is a bot account.
        Bot-executed actions WITHOUT a human initiator are never counted
        (they are the executor's own automation)."""
        cached = self._actor_bot_cache.get(user_id)
        if cached and time.monotonic() - cached[0] < 900:
            return cached[1]
        is_bot = False
        try:
            entity = await self.client.get_entity(user_id)  # type: ignore[union-attr]
            is_bot = bool(getattr(entity, "bot", False))
        except Exception:
            is_bot = False  # fail toward counting real human actors
        self._actor_bot_cache[user_id] = (time.monotonic(), is_bot)
        return is_bot

    async def _label_for(self, user_id: int | None) -> str:
        if user_id is None:
            return "unknown"
        cached = self._label_cache.get(user_id)
        if cached and time.monotonic() - cached[0] < 600:
            return cached[1]
        label = f"id:{user_id}"
        try:
            entity = await self.client.get_entity(user_id)  # type: ignore[union-attr]
            label = display_name(entity, user_id)
        except Exception:
            pass
        self._label_cache[user_id] = (time.monotonic(), label)
        return label

    async def _attributed_admin_action(self, group: Any, chat: Any,
                                       actor: int | None, target: int,
                                       kind: str, entry: Any) -> None:
        """Attribute an admin-log action to its true INITIATOR, record both
        identities, and feed the abuse counters.

        Attribution is EVIDENCE-BASED and executor-agnostic. In priority
        order:

          A. a matching moderation request was seen in the group shortly
             before  →  initiator = the human who sent it, executor = whoever
             the admin log says (any bot/userbot/account, known or brand new);
          B. the admin-log actor is a human account  →  initiator = executor
             (direct Telegram UI / their own userbot);
          C. no evidence  →  initiator = UNKNOWN. Nobody is blamed; the
             executor is recorded and handled by executor-based rules.

        kind: 'ban' | 'restrict' | 'unban'."""
        chat_id = group["chat_id"]
        event_id = getattr(entry, "id", 0) or 0

        # ---- A: command correlation (executor identity irrelevant) --------
        pending, fuzzy = self._pending.match_related(chat_id, kind, target)
        correlated = pending is not None
        if correlated:
            initiator: int | None = int(pending["initiator_id"])
            evidence = "command_correlation" + ("_fuzzy" if fuzzy else "")
            source = "command+admin_log"
            log.info("[CORRELATION] command matched admin-log event=%s "
                     "(chat=%s initiator=%s executor=%s target=%s action=%s%s)",
                     event_id, chat_id, initiator, actor, target, kind,
                     " fuzzy" if fuzzy else "")
        else:
            # ---- B/C: is the raw actor a human, or an unattributed bot? ---
            actor_is_bot = bool(actor) and await self._is_bot_account(actor)
            if actor is not None and not actor_is_bot:
                initiator = actor            # direct admin action
                evidence = "direct_admin_log"
                source = "admin_log"
            else:
                initiator = None             # UNKNOWN — never guess a human
                evidence = "none"
                source = "admin_log"
                log.info("[ADMIN ACTION] unattributed executor=%s target=%s "
                         "action=%s chat=%s (no linking request observed)",
                         actor, target, kind, chat_id)

        # ---- counting rules (false-positive firewall) ---------------------
        count_it = True
        why_not: str | None = None
        if initiator is None:
            count_it, why_not = False, "unknown-initiator"
        elif self._is_protected(initiator):
            count_it, why_not = False, "protected-user"
        if kind == "unban" and not config.ADMIN_COUNT_UNBAN:
            count_it = False
            why_not = why_not or "unban-not-counted"

        # ---- dual-identity record (initiator AND executor retained) -------
        self.db.add_admin_security_event(
            chat_id=chat_id, initiator_id=initiator, executor_id=actor,
            target_id=target, action=kind, source=source,
            correlated=correlated,
            risk_level="unknown-executor" if initiator is None else "normal",
            action_taken="counted" if count_it else "observed",
            reason=why_not or evidence)
        self._audit_observed(chat_id, actor, target, f"admin.{kind}",
                             group_title=group["title"])
        log.info("[ADMIN ACTION] initiator=%s executor=%s target=%s "
                 "action=%s source=%s evidence=%s counted=%s",
                 initiator if initiator is not None else "UNKNOWN",
                 actor, target, kind, source, evidence, count_it)

        if initiator is None:
            # Executor-based rules only; no human is ever punished for this.
            await self._unattributed_executor_check(group, chat, actor,
                                                    target, kind)
            return
        if not count_it:
            return

        # ---- thresholds: ONE counter per human, across ALL executors ------
        if kind in ("ban", "restrict"):
            await self._abuse_check(group, chat, actor, int(initiator), target,
                                    "ban" if kind == "ban" else "mute")
        # legacy large-scale shield, also initiator-keyed
        if kind == "ban":
            await self._mass_ban_check(group, chat, int(initiator), target)

    async def _unattributed_executor_check(self, group: Any, chat: Any,
                                           executor_id: int | None,
                                           target_id: int, kind: str) -> None:
        """Separate, executor-scoped rules for actions with NO human evidence.

        Telegram does not reveal who controls an external bot, so we never
        invent an initiator. Instead the *executor* is tracked; sustained
        unattributed moderation raises an owner alert (and can optionally
        demote the rogue executor itself — never a guessed human)."""
        if executor_id is None or kind == "unban":
            return
        if not config.ADMIN_ABUSE_ENABLED or \
                not self.db.get_feature("admin_abuse"):
            return
        if self._is_protected(executor_id):
            return

        chat_id = group["chat_id"]
        count, _, _ = security.abuse_tracker.record(
            chat_id, executor_id, "executor")
        limit = max(1, config.EXECUTOR_ABUSE_THRESHOLD)
        if count < limit:
            return
        key = (chat_id, executor_id)
        last = self._unknown_alerts.get(key, 0.0)
        if time.time() - last < 600:
            return
        self._unknown_alerts[key] = time.time()

        executor_label = await self._label_for(executor_id)
        target_label = await self._label_for(target_id)
        title = str(group["title"] or chat_id)
        steps_line = ("No admin was automatically punished because "
                      "attribution was not established.")
        action_taken = "alerted-unattributed"

        if config.AUTO_DEMOTE_UNATTRIBUTED_EXECUTOR:
            if await self.can_modify_admin(chat):
                res = await self.demote_user(chat, executor_id,
                                             desc="unattributed executor demote")
                steps_line = ("Executor demoted automatically."
                              if res.ok else
                              f"Executor demotion failed: {res.error}")
                action_taken = "executor-demoted" if res.ok else "executor-demote-failed"
            else:
                steps_line = ("Executor demotion BLOCKED: Telegram permission "
                              "hierarchy does not allow this account to edit "
                              "that executor.")
                action_taken = "ACTION_BLOCKED_BY_TELEGRAM_PERMISSIONS"

        body = [
            "⚠️ UNKNOWN MODERATION EXECUTOR",
            "",
            f"Group: {title}",
            f"Executor: {executor_label}",
            f"Executor ID: {executor_id}",
            f"Action: {kind.upper()}",
            f"Target: {target_label}",
            "",
            "Initiator: UNKNOWN",
            "",
            f"Detected: {count} unattributed moderation actions within "
            f"{config.EXECUTOR_ABUSE_WINDOW}s",
            "",
            steps_line,
            "",
            f"Timestamp: {security.alert_timestamp()}",
        ]
        self.db.log_event(chat_id, executor_id, target_id,
                          "security.unknown_executor", action_taken,
                          details="\n".join(body), group_title=title)
        log.warning("[SECURITY] unattributed executor=%s reached %s actions "
                    "in group %s → %s", executor_id, count, chat_id,
                    action_taken)
        if config.UNKNOWN_EXECUTOR_ALERTS:
            await self.send_owner_dm("\n".join(body))

    async def _abuse_check(self, group: Any, chat: Any, executor_id: int | None,
                           initiator_id: int, target_id: int,
                           kind: str) -> None:
        """Sliding-window abuse counter per (group, human initiator, kind)."""
        if not config.ADMIN_ABUSE_ENABLED or \
                not self.db.get_feature("admin_abuse"):
            return
        chat_id = group["chat_id"]
        count, limit, window = security.abuse_tracker.record(
            chat_id, initiator_id, kind)
        log.info("[ADMIN MONITOR] group=%s initiator=%s kind=%s count=%s "
                 "(threshold %s/%ss)", chat_id, initiator_id, kind, count,
                 limit, window)
        if count < limit:
            return
        log.warning("[SECURITY] threshold reached: initiator=%s %s/%ss "
                    "(%s actions) in group %s",
                    initiator_id, limit, window, count, chat_id)
        # one response per initiator per cooldown window (shared registry so
        # the mass-ban shield doesn't double-respond to the same human)
        if not security.detector.suspicion.should_alert(chat_id, initiator_id,
                                                        cooldown=300):
            return
        security.detector.suspicion.flag(chat_id, initiator_id)
        await self._respond_abuse(group, chat, executor_id, initiator_id,
                                  kind, count, limit, window)

    async def _respond_abuse(self, group: Any, chat: Any,
                             executor_id: int | None, initiator_id: int,
                             kind: str, count: int, limit: int,
                             window: int) -> None:
        """Threshold response with honest hierarchy checks.

        Never demotes/bans: the configured owner, the connected account, or
        any admin Telegram's hierarchy does not let this account edit —
        that case is logged and alerted as ACTION_BLOCKED."""
        chat_id = group["chat_id"]
        if self._is_protected(initiator_id):
            return  # shield twice: counters skip it, response shields again

        initiator_label = await self._label_for(initiator_id)
        kind_word = "ban" if kind == "ban" else "mute/restrict"
        detected = (f"{count} {kind_word} actions within {window} seconds "
                    f"(threshold {limit})")
        title = str(group["title"] or chat_id)

        # ---- execution sources: EVERY executor this human drove -----------
        # One human may mix methods (third-party bot, custom bot, their own
        # userbot, direct Telegram UI). All of it counts toward the same
        # initiator; the executors are listed for the audit trail.
        source_lines: list[str] = []
        try:
            rows = self.db.executors_for_initiator(
                chat_id, initiator_id, int(time.time()) - window - 5)
            for row in rows:
                ex_id = row["executor_id"]
                if ex_id is None:
                    continue
                label = (f"{initiator_label} (own account)"
                         if ex_id == initiator_id
                         else await self._label_for(int(ex_id)))
                source_lines.append(f"• {label} — {row['n']} action(s)")
        except Exception as exc:
            log.info("execution-source lookup failed: %s", type(exc).__name__)
        if not source_lines:
            fallback = (f"{initiator_label} (own account)"
                        if executor_id in (None, initiator_id)
                        else await self._label_for(executor_id))
            source_lines = [f"• {fallback}"]

        steps: list[tuple[bool, str]] = []
        taken, reason = "alert-only", None

        # -- hierarchy pre-check BEFORE attempting anything ---------------
        blocked = None
        auto_response = (config.AUTO_DEMOTE_ABUSIVE_ADMIN
                         or config.AUTO_BAN_ABUSIVE_ADMIN)
        tperms = await self.permissions(chat, initiator_id)
        if tperms is not None and getattr(tperms, "is_creator", False):
            blocked = ("Target is the group owner — Telegram forbids any "
                       "modification.")
        elif tperms is not None and not getattr(tperms, "is_admin", False):
            blocked = ("Initiator is no longer an admin (already demoted by "
                       "someone else?).")
            taken = "already-demoted"
        elif not await self.can_modify_admin(chat):
            blocked = ("Telegram permission hierarchy does not allow this "
                       "account to demote the admin (this account must be "
                       "the group owner, or the admin who promoted them).")

        if not auto_response:
            steps.append((True, "Owner notified"))
            steps.append((True, "Automatic response disabled "
                                "(AUTO_DEMOTE_ABUSIVE_ADMIN=0)"))
        elif taken == "already-demoted":
            steps.append((True, "Owner notified"))
            steps.append((True, "No action needed — initiator is not an "
                                "admin anymore"))
        elif blocked:
            steps.append((True, "Owner notified"))
            steps.append((False, "Demotion BLOCKED by Telegram permissions"))
            taken = "ACTION_BLOCKED_BY_TELEGRAM_PERMISSIONS"
            reason = blocked
            log.warning("[SECURITY] %s — %s (initiator=%s group=%s)",
                        taken, reason, initiator_id, chat_id)
        else:
            log.warning("[SECURITY] attempting demotion of %s in group %s",
                        initiator_id, chat_id)
            dres = await self.demote_user(chat, initiator_id,
                                          desc="admin-abuse demote")
            if dres.ok:
                log.warning("[SECURITY] demotion successful: %s in %s",
                            initiator_id, chat_id)
                steps.append((True, "Admin demoted automatically"))
                taken = "demoted"
            else:
                steps.append((False, f"Demotion failed: {dres.error}"))
                taken = "demote-failed"
                reason = dres.error
            if config.AUTO_BAN_ABUSIVE_ADMIN:
                bres = await self.ban_user(chat, initiator_id,
                                           desc="admin-abuse ban")
                steps.append((bool(bres.ok), "Ban executed" if bres.ok
                              else f"Ban failed: {bres.error}"))
                if bres.ok:
                    taken += "+banned"
            steps.insert(0, (True, "Owner notified"))

        # persist outcome onto the initiator's recent rows + summary event
        self.db.mark_admin_actions(chat_id, initiator_id, taken,
                                   reason or detected)
        self.db.log_event(chat_id, executor_id, initiator_id,
                          "security.admin_abuse", taken,
                          details=detected, group_title=title)
        security.abuse_tracker.reset(chat_id, initiator_id)

        # -- owner alert in the requested format ---------------------------
        if taken == "demoted":
            action_line = "Admin demoted automatically"
        elif taken == "demoted+banned":
            action_line = "Admin demoted and banned automatically"
        elif taken == "alert-only":
            action_line = "Owner notified — manual review required"
        elif taken == "already-demoted":
            action_line = "No action — initiator is no longer an admin"
        else:
            action_line = "Protection attempt failed (see below)"
        failed = taken in {"ACTION_BLOCKED_BY_TELEGRAM_PERMISSIONS",
                           "demote-failed"}

        body = [
            "🚨 ADMIN ABUSE DETECTED",
            "",
            f"Group: {title}",
            "",
            "Initiator:",
            initiator_label,
            "",
            "User ID:",
            str(initiator_id),
            "",
            "Detected:",
            detected,
            "",
            "Execution sources:",
            *source_lines,
            "",
            "Security action:",
            action_line,
        ]
        if failed:
            body += ["", "⚠️ ACTION FAILED", "Reason:", str(reason)]
        body += ["", f"Timestamp: {security.alert_timestamp()}"]
        log.warning("\n%s", "\n".join(body))
        await self.send_owner_dm("\n".join(body))

    # ------------------------------------------------------------------
    # Mass-ban / mass-delete protection
    # ------------------------------------------------------------------

    async def _mass_ban_check(self, group: Any, chat: Any,
                              actor: int | None, target: int | None) -> None:
        if actor is None:
            return
        if not self.db.get_feature("massban_detection"):
            return  # detection paused via /settings
        # The owner is never flagged or punished — by design.
        if security.is_owner(actor):
            return
        chat_id = group["chat_id"]
        lockdown = bool(group["lockdown"])
        result = security.detector.check_ban(chat_id, actor, lockdown)
        if not result.triggered:
            return
        if not security.detector.suspicion.should_alert(chat_id, actor):
            return  # already alerting recently; actions continue below via TTL
        security.detector.suspicion.flag(chat_id, actor)

        try:
            actor_entity = await self.client.get_entity(actor)  # type: ignore[union-attr]
        except Exception:
            actor_entity = None
        actor_display = display_name(actor_entity, actor)

        steps: list[tuple[bool, str]] = [(True, "Event recorded")]
        actions_taken = "suspicious-flag"

        # Emergency protection: demote (and optionally ban) — only when
        # Telegram's hierarchy allows the connected account to touch them.
        demote_ok, demote_note = False, "Administrator demotion skipped by configuration"
        if config.AUTO_DEMOTE_ON_MASS_BAN or config.AUTO_BAN_ON_MASS_BAN:
            if await self.can_modify_admin(chat):
                res = await self.demote_user(
                    chat, actor, desc="emergency demote (mass ban)")
                demote_ok = res.ok
                demote_note = ("Administrator protection procedure executed "
                               f"(demote: {'ok' if res.ok else res.error})")
                if config.AUTO_BAN_ON_MASS_BAN:
                    ban_res = await self.ban_user(
                        chat, actor, desc="emergency ban (mass ban)")
                    demote_note += f"; ban: {'ok' if ban_res.ok else ban_res.error}"
                    actions_taken += "+ban" if ban_res.ok else "+ban-failed"
            else:
                demote_note = ("Automatic demotion unavailable — the offending "
                               "administrator is outside this account's "
                               "modifiable set (owner/hierarchy protection)")
        actions_taken += "+demote" if demote_ok else ""
        steps.append((True, "Owner notified"))
        steps.append((demote_ok, demote_note))

        if config.AUTO_LOCKDOWN_ON_MASS_BAN and not lockdown:
            self.db.set_lockdown(chat_id, True)
            steps.append((True, "Lockdown engaged automatically"))
            actions_taken += "+lockdown"

        alert = security.render_security_alert(
            group_title=group["title"] or str(chat_id),
            group_id=chat_id,
            admin_display=actor_display,
            admin_id=actor,
            action_detected=(f"Mass ban — {result.rule} "
                             f"({result.count} bans in {result.window}s)"),
            steps=steps)
        self.db.log_event(chat_id, actor, target, "security.mass_ban",
                          actions_taken, details=alert,
                          group_title=group["title"])
        log.warning("\n%s", alert)
        await self.send_owner_dm(alert)

    async def _mass_delete_check(self, group: Any, chat: Any,
                                 actor: int | None) -> None:
        if actor is None or security.is_owner(actor):
            return
        if not self.db.get_feature("massdelete_detection"):
            return  # detection paused via /settings
        chat_id = group["chat_id"]
        result = security.detector.check_delete(chat_id, actor,
                                                bool(group["lockdown"]))
        if not result.triggered:
            return
        if not security.detector.suspicion.should_alert(chat_id, actor):
            return
        security.detector.suspicion.flag(chat_id, actor)

        try:
            actor_entity = await self.client.get_entity(actor)  # type: ignore[union-attr]
        except Exception:
            actor_entity = None
        actor_display = display_name(actor_entity, actor)

        steps: list[tuple[bool, str]] = [(True, "Event recorded"),
                                         (True, "Owner notified")]
        if config.AUTO_DEMOTE_ON_MASS_DELETE and await self.can_modify_admin(chat):
            res = await self.demote_user(
                chat, actor, desc="emergency demote (mass delete)")
            steps.append((res.ok, f"Emergency demotion executed "
                                  f"({'ok' if res.ok else res.error})"))
        else:
            steps.append((True, "Emergency protection set to notify-only "
                                "(AUTO_DEMOTE_ON_MASS_DELETE=0)"))

        alert = security.render_security_alert(
            group_title=group["title"] or str(chat_id),
            group_id=chat_id,
            admin_display=actor_display,
            admin_id=actor,
            action_detected=(f"Mass message deletion — {result.rule} "
                             f"({result.count} deletions in {result.window}s)"),
            steps=steps)
        self.db.log_event(chat_id, actor, None, "security.mass_delete",
                          "alerted", details=alert, group_title=group["title"])
        log.warning("\n%s", alert)
        await self.send_owner_dm(alert)

    # ------------------------------------------------------------------
    # Manual promotion detection
    # ------------------------------------------------------------------

    async def _on_manual_promotion(self, group: Any, chat: Any,
                                   actor: int | None, target: int) -> None:
        """A promotion happened outside our command path (e.g. the owner
        pressed 'Promote' inside the Telegram app). Record it, notify the
        owner, and honestly assess whether automatic protection could ever
        demote this admin — we NEVER assume it can."""
        chat_id = group["chat_id"]
        can_modify = await self.can_modify_admin(chat)
        try:
            target_entity = await self.client.get_entity(target)  # type: ignore[union-attr]
        except Exception:
            target_entity = None
        target_display = display_name(target_entity, target)

        # was the promotion requested via a visible /promote command?
        pending = self._pending.match(chat_id, "promote", target)
        self.db.add_admin_security_event(
            chat_id=chat_id,
            initiator_id=int(pending["initiator_id"]) if pending else actor,
            executor_id=actor, target_id=target, action="promote",
            source="command+admin_log" if pending else "admin_log",
            correlated=bool(pending),
            action_taken="observed",
            reason="modifiable" if can_modify else "hierarchy-protected")

        if security.is_owner(target):
            can_modify = False  # owner is never a demotion candidate

        result = ("observed; protection-available"
                  if can_modify else "observed; protection-unavailable")
        if self.db.get_feature("audit_logging"):
            self.db.log_event(chat_id, actor, target, "admin.promote", result,
                              group_title=group["title"])
        self.db.set_setting(
            f"manual_admin:{chat_id}:{target}",
            f"{int(time.time())}:{'modifiable' if can_modify else 'protected'}")

        notice = security.render_security_alert(
            group_title=group["title"] or str(chat_id),
            group_id=chat_id,
            admin_display=target_display,
            admin_id=target,
            action_detected="New administrator detected (manual promotion)",
            steps=[
                (True, "Promotion event recorded"),
                (True, "Owner notified"),
                (can_modify,
                 "Automatic protection available (this account can demote "
                 "this admin if they turn rogue)" if can_modify else
                 "Automatic protection NOT available — Telegram's hierarchy "
                 "does not allow this account to demote this admin"),
            ])
        log.info("\n%s", notice)
        await self.send_owner_dm(notice)


# ---------------------------------------------------------------------------
# Small indirection so UserbotManager.call can wrap get_permissions uniformly
# ---------------------------------------------------------------------------

def client_call(client: TelegramClient, chat: Any, user: Any,
                what: str = "permissions") -> Awaitable[Any]:
    if what == "permissions":
        return client.get_permissions(chat, user)
    raise ValueError(f"unknown client_call: {what}")
