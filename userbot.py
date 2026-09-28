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
import time
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
        await self._restrict_if_gmuted(chat, sender_id, event.message)

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
        for group in self.db.enabled_groups():
            if not self.running:
                return
            try:
                await self._poll_group(group)
            except Exception as exc:
                log.warning("Admin-log poll failed for %s: %s",
                            group["chat_id"], security.redact(str(exc)))

    async def _poll_group(self, group: Any) -> None:
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
        if not cursor:
            # First poll: establish the cursor without replaying history, so
            # old admin activity never triggers false mass-action alerts.
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
                self.db.log_event(chat_id, actor, target, f"admin.{kind}",
                                  "observed", group_title=group["title"])
                if kind == "ban":
                    await self._mass_ban_check(group, chat, actor, target)
            else:
                prev_banned = isinstance(prev, t.ChannelParticipantBanned)
                if prev_banned:
                    self.db.log_event(chat_id, actor, target, "admin.unban",
                                      "observed", group_title=group["title"])
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
                await self._on_manual_promotion(group, chat, actor, target)
            elif was_admin and not new_admin:
                self.db.log_event(chat_id, actor, target, "admin.demote",
                                  "observed", group_title=group["title"])
            else:
                self.db.log_event(chat_id, actor, target,
                                  "admin.rights_change", "observed",
                                  group_title=group["title"])
            return

        # ---- default member rights changed (relevant to lockdown) --------
        if isinstance(action, t.ChannelAdminLogEventActionDefaultBannedRights):
            self.db.log_event(chat_id, actor, None, "admin.default_rights",
                              "observed", group_title=group["title"])
            return

    # ------------------------------------------------------------------
    # Mass-ban / mass-delete protection
    # ------------------------------------------------------------------

    async def _mass_ban_check(self, group: Any, chat: Any,
                              actor: int | None, target: int | None) -> None:
        if actor is None:
            return
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

        if security.is_owner(target):
            can_modify = False  # owner is never a demotion candidate

        result = ("observed; protection-available"
                  if can_modify else "observed; protection-unavailable")
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
