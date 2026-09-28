"""
bot.py — the owner-facing management bot ("SecurityGuard").

Patch scope
-----------
Everything that existed before still works the same way:

* the secure /login MTProto flow (phone → code → 2FA, credential hygiene,
  owner-account enforcement, encrypted session storage);
* /logout with server-side revocation;
* /session, /security, /groups, /rescan functionality (now dashboards);
* the SQLite-backed data and the userbot worker contract.

Added on top (additive only):

* polished /start welcome screen with inline keyboards;
* setMyCommands registration (Telegram "/" command menu);
* inline navigation — every button is wired to a real handler;
* /admins, /settings (live feature toggles), /logs views;
* /lockdown & /unlock with confirmation keyboards;
* management-bot moderation relay (/mute … /ungmute) executed through the
  existing userbot worker with the same shields as in-group commands;
* a robust notify_owner that resolves the owner entity properly and falls
  back to the connected account's Saved Messages instead of guessing raw
  PeerUser objects (fixes "Could not find the input entity" failures).

Credential hygiene is unchanged: codes, 2FA passwords, session strings and
API secrets are never shown or logged. UI text avoids markdown entirely —
all panels render as plain text so dynamic content (group titles, user
names) can never corrupt formatting or leak through markup entities.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from zoneinfo import ZoneInfo

from telethon import Button, TelegramClient, events
from telethon.errors import (
    FloodWaitError,
    PasswordHashInvalidError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    PhoneNumberBannedError,
    PhoneNumberInvalidError,
    PhoneNumberOccupiedError,
    SessionPasswordNeededError,
)
from telethon.sessions import StringSession
from telethon.tl import functions, types as t

import config
import security
from security import SessionCipher
from database import Database
from userbot import UserbotManager, display_name

log = logging.getLogger("bot")

_PHONE_RE = re.compile(r"^\+\d{7,15}$")

# Telegram "/" command menu (registered via setMyCommands at start).
COMMAND_MENU: list[tuple[str, str]] = [
    ("start", "Open SecurityGuard"),
    ("help", "Show help"),
    ("login", "Connect Telegram account"),
    ("logout", "Disconnect Telegram account"),
    ("session", "Show connection status"),
    ("security", "Show security status"),
    ("groups", "Show protected groups"),
    ("admins", "Show admin security status"),
    ("mute", "Mute a user"),
    ("unmute", "Unmute a user"),
    ("ban", "Ban a user"),
    ("unban", "Unban a user"),
    ("promote", "Promote a user"),
    ("demote", "Demote an admin"),
    ("gmute", "Globally mute a user"),
    ("ungmute", "Remove global mute"),
    ("lockdown", "Enable emergency protection"),
    ("unlock", "Disable emergency protection"),
    ("settings", "Security settings"),
    ("logs", "Show security events"),
    ("rescan", "Re-discover admin groups"),
    ("cancel", "Abort an in-progress login"),
]

# Management-bot moderation verbs handled by the relay.
_BOT_MOD_OPS = {"mute", "unmute", "ban", "unban", "promote", "demote",
                "gmute", "ungmute"}
# Ops that act globally instead of inside one group.
_GLOBAL_OPS = {"gmute", "ungmute"}

_LOG_PAGE_SIZE = 5
_MAX_GROUP_BUTTONS = 10


@dataclass
class LoginState:
    """Transient login attempt. Holds ONLY what MTProto strictly needs while
    the handshake is in flight: the phone (required to re-submit with the
    code) and Telegram's phone_code_hash. Never holds the code/password
    beyond a single await, and is destroyed on completion/cancel/expiry."""
    stage: str                       # 'phone' | 'code' | 'password'
    client: TelegramClient
    phone: str = ""
    phone_code_hash: str = ""
    attempts: int = 0
    created_at: float = field(default_factory=time.time)


class ManagementBot:
    def __init__(self, db: Database, cipher: SessionCipher,
                 userbot: UserbotManager, status: dict) -> None:
        self.db = db
        self.cipher = cipher
        self.userbot = userbot
        self.status = status
        self.client: TelegramClient | None = None
        self._login: LoginState | None = None
        self._login_lock = asyncio.Lock()
        # Cached owner entity (access-hash resolved) so notifications never
        # need raw PeerUser construction.
        self._owner_entity = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        # In-memory session: bot tokens re-authenticate cheaply on each
        # start, and nothing sensitive needs persistence for the BOT side.
        self.client = TelegramClient(
            StringSession(), config.API_ID, config.API_HASH,
            device_model=config.DEVICE_MODEL)
        await self.client.start(bot_token=config.BOT_TOKEN)
        # Plain-text rendering everywhere: dynamic titles/names can never
        # break markdown parsing.
        self.client.parse_mode = None
        self._register_handlers()
        await self._register_command_menu()
        self.status["bot"] = True
        # Warm the owner-entity cache silently (best effort).
        await self._get_owner_entity()
        me = await self.client.get_me()
        log.info("Management bot online as @%s", getattr(me, "username", "?"))

    async def _register_command_menu(self) -> None:
        """Publish the "/" command menu. Non-fatal if Telegram rejects it."""
        try:
            await self.client(functions.bots.SetBotCommandsRequest(
                scope=t.BotCommandScopeDefault(),
                lang_code="",
                commands=[t.BotCommand(command=c, description=d)
                          for c, d in COMMAND_MENU]))
        except Exception as exc:
            log.warning("setMyCommands failed: %s", type(exc).__name__)

    async def stop(self) -> None:
        self.status["bot"] = False
        await self._cleanup_login()
        if self.client:
            await self.client.disconnect()
            self.client = None

    # ------------------------------------------------------------------
    # Owner notifications — entity-safe, multi-route, never fatal
    # ------------------------------------------------------------------

    async def _get_owner_entity(self):
        """Resolve the owner as a proper input entity (access hash included).
        Returns None when the bot has never seen the owner this session —
        callers then use the Saved Messages fallback instead of guessing
        PeerUser objects (that was the source of the old crash log)."""
        if self._owner_entity is not None:
            return self._owner_entity
        if not self.client:
            return None
        for resolver in (self.client.get_input_entity, self.client.get_entity):
            try:
                self._owner_entity = await resolver(config.OWNER_ID)
                return self._owner_entity
            except Exception:
                continue
        return None

    async def notify_owner(self, text: str) -> None:
        """Alert delivery pipeline:

        1. management-bot DM using the resolved owner entity;
        2. fallback: the connected account's Saved Messages ("me") — always
           available when the connected account IS the owner account;
        3. concise safe log line, then continue monitoring. Never raises,
           never logs secrets.
        """
        if not self.db.get_feature("owner_alerts"):
            log.info("Owner alerts disabled — notification suppressed.")
            return
        if not self.client:
            log.warning("Bot offline; dropping owner notification.")
            return

        entity = await self._get_owner_entity()
        if entity is not None:
            try:
                await self.client.send_message(entity, text)
                return
            except Exception as exc:
                log.info("Owner DM via bot failed (%s) — trying fallback.",
                         type(exc).__name__)

        try:
            if self.userbot.client is not None and \
                    self.userbot.self_id == config.OWNER_ID:
                await self.userbot.client.send_message("me", text)
                return
        except Exception as exc:
            log.info("Owner Saved-Messages fallback failed (%s).",
                     type(exc).__name__)

        log.warning("Owner notification undeliverable; monitoring continues.")

    async def run_until_stopped(self, stop_event: asyncio.Event) -> None:
        await stop_event.wait()

    # ------------------------------------------------------------------
    # Authorization helpers (numeric Telegram IDs only — never usernames)
    # ------------------------------------------------------------------

    @staticmethod
    def _is_owner(user_id: int | None) -> bool:
        return bool(user_id) and user_id == config.OWNER_ID

    def _role(self, user_id: int | None) -> str | None:
        if user_id is None:
            return None
        return self.db.get_admin_role(user_id)

    def _is_security_user(self, user_id: int | None) -> bool:
        """Owner, or a trust role of SECURITY_ADMIN or higher."""
        if self._is_owner(user_id):
            return True
        return security.role_at_least(self._role(user_id),
                                      config.ROLE_SECURITY)

    async def _warm_owner_entity(self, event) -> None:
        if self._is_owner(event.sender_id) and self._owner_entity is None:
            try:
                self._owner_entity = await event.get_sender()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # View layer — every panel returns (text, inline keyboard)
    # ------------------------------------------------------------------

    def _tz(self) -> ZoneInfo:
        try:
            return ZoneInfo(config.ALERT_TZ)
        except Exception:
            return ZoneInfo("UTC")

    def _connected(self) -> bool:
        return self.db.get_session(config.OWNER_ID) is not None

    def _account_label(self) -> str:
        if self.userbot.me is not None:
            return display_name(self.userbot.me, self.userbot.self_id)
        row = self.db.get_session(config.OWNER_ID)
        if row:
            return f"id:{row['user_id']}"
        return "unknown"

    # ----- home / welcome ---------------------------------------------------

    def view_home(self, public: bool = False):
        if public:
            text = (
                "🛡️ SecurityGuard\n\n"
                "A private Telegram Group Security & Moderation system "
                "(anti-spam, rogue-admin detection, audit logging).\n\n"
                "This instance is privately operated — only its operator can "
                "manage it.")
            return text, [[Button.inline("📖 Help", b"pub:help")]]

        if not self._connected():
            text = (
                "🛡️ SecurityGuard\n\n"
                "Your Telegram Group Security & Moderation System.\n\n"
                "Protect your groups against:\n"
                "  • Spam\n"
                "  • Admin abuse\n"
                "  • Mass-ban activity\n"
                "  • Suspicious moderation\n"
                "  • Unwanted content\n\n"
                "Account Status:\n"
                "🔴 Not connected\n\n"
                "Use the button below to connect your Telegram account.")
            buttons = [
                [Button.inline("🔐 Connect Telegram", b"login")],
                [Button.inline("🛡️ Security Status", b"sec"),
                 Button.inline("📖 Help", b"help")],
            ]
            return text, buttons

        state_line = ("Security System: ACTIVE" if self.userbot.running
                      else "Security System: starting — check /session")
        text = (
            "🛡️ SecurityGuard\n\n"
            "Your Telegram Group Security & Moderation System.\n\n"
            "Account Status:\n"
            "🟢 Telegram account connected\n"
            f"Account: {self._account_label()}\n\n"
            f"{state_line}")
        buttons = [
            [Button.inline("🛡️ Security Status", b"sec"),
             Button.inline("👥 Groups", b"grp:l")],
            [Button.inline("⚙️ Settings", b"set:p"),
             Button.inline("📖 Help", b"help")],
            [Button.inline("👮 Admins", b"adm:l"),
             Button.inline("📋 Logs", b"log:0")],
        ]
        return text, buttons

    # ----- help ---------------------------------------------------------------

    def view_help(self, public: bool = False):
        if public:
            text = (
                "📖 SecurityGuard — Help\n\n"
                "SecurityGuard protects Telegram groups against spam, admin "
                "abuse and mass-moderation events.\n\n"
                "This bot is a private management console. No management "
                "commands are available for your account.")
            return text, [[Button.inline("◀️ Back", b"pub:home")]]

        text = (
            "📖 HELP\n\n"
            "🔐 ACCOUNT\n"
            "/login — connect your Telegram account (MTProto)\n"
            "/logout — revoke the session (server-side) + delete it locally\n"
            "/session — connection status (never shows credentials)\n\n"
            "🛡️ SECURITY\n"
            "/security — live security dashboard\n"
            "/lockdown — enable emergency protection (with confirmation)\n"
            "/unlock — return to normal protection\n"
            "/logs — recent security events\n\n"
            "👥 GROUP MANAGEMENT\n"
            "/groups — protected groups + per-group controls\n"
            "/admins — administrator security status\n"
            "/rescan — re-discover groups where the account is admin\n\n"
            "🔨 MODERATION\n"
            "/mute /unmute /ban /unban\n"
            "/promote /demote /gmute /ungmute\n\n"
            "Two ways to target a user:\n"
            "1) /ban @username (or a numeric Telegram ID)\n"
            "2) Reply-based: in a protected group, reply to the user's "
            "message with /ban or /mute — the system uses the replied "
            "user's Telegram ID. In this chat, forward a message from the "
            "user first, then reply to it with the command.\n\n"
            "Every destructive action re-verifies the connected account, "
            "the group, your rights, the target and Telegram's admin "
            "hierarchy before it runs.")
        return text, [[Button.inline("◀️ Back", b"home")]]

    # ----- session ---------------------------------------------------------------

    def view_session(self):
        row = self.db.get_session(config.OWNER_ID)
        if not row:
            text = (
                "🔐 Telegram Connection\n\n"
                "Status: 🔴 Not connected\n\n"
                "Use /login to connect your Telegram account.")
            return text, [[Button.inline("🔐 Connect Telegram", b"login")],
                          [Button.inline("◀️ Back", b"home")]]
        age = int(time.time()) - int(row["created_at"])
        worker = "🟢 running" if self.userbot.running else "🔴 offline"
        text = (
            "🔐 Telegram Connection\n\n"
            "Status: 🟢 Connected\n\n"
            f"Account:\n{self._account_label()}\n\n"
            f"User ID:\n{row['user_id']}\n\n"
            f"Phone: {row['phone_masked'] or 'unavailable'}\n"
            f"Authorized for: {age // 3600}h {(age % 3600) // 60}m\n"
            f"Worker: {worker}\n\n"
            "Session:\n🔒 Securely stored (encrypted at rest)\n\n"
            "The raw session string is never displayed.")
        buttons = [
            [Button.inline("🛡️ Security Status", b"sec"),
             Button.inline("🚪 Log out", b"lout:a")],
            [Button.inline("◀️ Back", b"home")],
        ]
        return text, buttons

    def view_logout_confirm(self):
        text = (
            "🚪 Disconnect account?\n\n"
            "This will revoke the MTProto session on Telegram's servers and "
            "delete the local encrypted copy. Monitoring stops until the "
            "next /login.")
        return text, [[Button.inline("🚪 CONFIRM LOGOUT", b"lout:y"),
                       Button.inline("❌ CANCEL", b"lout:n")]]

    # ----- security dashboard --------------------------------------------------------

    def _feat(self, key: str) -> str:
        return "🟢 ON" if self.db.get_feature(key) else "⚪ OFF"

    def view_security(self):
        groups = self.db.enabled_groups()
        locked = [g for g in groups if g["lockdown"]]
        emergency = "🔵 OFF"
        if locked:
            emergency = f"🔴 ACTIVE ({len(locked)} group(s))"
        system = "🟢 ACTIVE" if self.userbot.running else "🔴 WORKER OFFLINE"
        account = "🟢 Connected" if self._connected() else "🔴 Not connected"
        text = (
            "🛡️ SECURITY STATUS\n\n"
            f"System: {system}\n\n"
            f"Telegram Account: {account}\n\n"
            f"Protected Groups: {len(groups)}\n\n"
            f"Admin Monitoring: {self._feat('admin_monitoring')}\n"
            f"Mass-Ban Detection: {self._feat('massban_detection')}  "
            f"({config.BAN_LIMIT_1}/{config.BAN_WINDOW_1}s)\n"
            f"Mass-Delete Detection: {self._feat('massdelete_detection')}  "
            f"({config.DELETE_LIMIT_1}/{config.DELETE_WINDOW_1}s)\n"
            f"Spam Protection: {self._feat('spam_protection')}\n"
            f"Audit Logging: {self._feat('audit_logging')}\n\n"
            f"Emergency Mode: {emergency}")
        buttons = [
            [Button.inline("👥 Groups", b"grp:l"),
             Button.inline("👮 Admins", b"adm:l")],
            [Button.inline("🚨 Lockdown", b"lock:m"),
             Button.inline("📋 Logs", b"log:0")],
            [Button.inline("⚙️ Settings", b"set:p"),
             Button.inline("◀️ Back", b"home")],
        ]
        return text, buttons

    # ----- groups ----------------------------------------------------------------------

    def view_groups(self):
        rows = self.db.enabled_groups()
        if not rows:
            text = (
                "👥 Protected Groups\n\n"
                "None yet. Add your account as a group administrator, then "
                "tap Rescan — or type /install inside the group.\n\n"
                "Only groups the connected account can legitimately access "
                "are ever shown.")
            return text, [[Button.inline("🔄 Rescan", b"grp:rescan")],
                          [Button.inline("◀️ Back", b"home")]]
        lines = ["👥 Protected Groups", ""]
        buttons: list[list] = []
        for i, g in enumerate(rows[:_MAX_GROUP_BUTTONS], 1):
            state = "🔴 LOCKDOWN" if g["lockdown"] else "🟢 Protection Active"
            lines.append(f"{i}. {g['title'] or g['chat_id']}")
            lines.append(f"   {state}")
            cid = str(g["chat_id"]).encode()
            buttons.append([
                Button.inline("Security", b"grp:s:" + cid),
                Button.inline("Admins", b"grp:a:" + cid),
                Button.inline("Settings", b"grp:c:" + cid),
            ])
        if len(rows) > _MAX_GROUP_BUTTONS:
            lines.append("")
            lines.append(f"… plus {len(rows) - _MAX_GROUP_BUTTONS} more "
                         "(first 10 shown).")
        buttons.append([Button.inline("🔄 Rescan", b"grp:rescan"),
                        Button.inline("◀️ Back", b"home")])
        return "\n".join(lines), buttons

    def _group_or_none(self, chat_id: int):
        g = self.db.get_group(chat_id)
        return g if g and g["enabled"] else None

    def view_group_security(self, chat_id: int):
        g = self._group_or_none(chat_id)
        if not g:
            return ("Group not found or protection is disabled.",
                    [[Button.inline("◀️ Back", b"grp:l")]])
        events = self.db.events_page(3, 0, chat_id)
        lines = [
            f"🛡️ {g['title'] or chat_id}",
            "",
            f"Protection: {'🟢 ON' if g['enabled'] else '⚪ OFF'}",
            f"Emergency Mode: {'🔴 LOCKDOWN' if g['lockdown'] else '🔵 normal'}",
            f"Thresholds: {config.BAN_LIMIT_1} bans/{config.BAN_WINDOW_1}s · "
            f"{config.DELETE_LIMIT_1} deletions/{config.DELETE_WINDOW_1}s",
            "",
            "Recent events in this group:",
        ]
        if not events:
            lines.append("• none recorded")
        for r in events:
            when = datetime.fromtimestamp(int(r["created_at"]), self._tz())
            lines.append(f"• {r['action']} → {r['result']} "
                         f"({when.strftime('%H:%M %d %b')})")
        cid = str(chat_id).encode()
        lock_btn = (Button.inline("🔓 Unlock group", b"unlk:a:" + cid)
                    if g["lockdown"]
                    else Button.inline("🚨 Lockdown group", b"lock:a:" + cid))
        buttons = [
            [lock_btn],
            [Button.inline("👮 Admins", b"grp:a:" + cid),
             Button.inline("⚙️ Settings", b"grp:c:" + cid)],
            [Button.inline("◀️ Back", b"grp:l")],
        ]
        return "\n".join(lines), buttons

    # ----- admins -----------------------------------------------------------------------

    def view_admins_overview(self):
        rows = self.db.enabled_groups()
        if not rows:
            return ("👮 ADMIN SECURITY\n\nNo protected groups yet.",
                    [[Button.inline("◀️ Back", b"home")]])
        lines = ["👮 ADMIN SECURITY", "",
                 "Monitoring: 🟢 ON for every protected group.",
                 "Pick a group for the detailed roster:"]
        buttons: list[list] = []
        for g in rows[:_MAX_GROUP_BUTTONS]:
            buttons.append([Button.inline(
                f"👮 {g['title'] or g['chat_id']}",
                b"grp:a:" + str(g["chat_id"]).encode())])
        buttons.append([Button.inline("◀️ Back", b"home")])
        return "\n".join(lines), buttons

    async def view_group_admins(self, chat_id: int):
        """Honest per-group admin roster. 'Demotable: YES' is only shown when
        the connected account can actually demote that admin under
        Telegram's hierarchy — never assumed."""
        g = self._group_or_none(chat_id)
        back = [[Button.inline("◀️ Back", b"grp:l")]]
        if not g:
            return "Group not found or protection disabled.", back
        if not self.userbot.running or not self.userbot.client:
            return ("👮 ADMIN SECURITY\n\nSecurity worker offline — "
                    "/login and /rescan first, then retry."), back

        buttons = [[Button.inline("◀️ Back", f"grp:s:{chat_id}".encode()),
                    Button.inline("🏠 Home", b"home")]]
        lines = ["👮 ADMIN SECURITY", "", f"{g['title'] or chat_id}", ""]

        chat = await self.userbot.resolve_chat(chat_id)
        perms = await self.userbot.self_permissions(chat)
        self_creator = bool(getattr(perms, "is_creator", False))
        can_add = bool(getattr(perms, "add_admins", False))

        try:
            admins = await self.userbot.client.get_participants(
                chat, filter=t.ChannelParticipantsAdmins, limit=30)
        except Exception as exc:
            log.info("admin roster unavailable in %s (%s)", chat_id,
                     type(exc).__name__)
            lines.append("Telegram admin roster unavailable for this group "
                         "(the connected account cannot read it).")
            lines.append("")
            lines.append("Monitoring: 🟢 ON — admin-log events are still "
                         "tracked where Telegram provides them.")
            return "\n".join(lines), buttons

        owner_line = None
        admin_blocks: list[str] = []
        for user in admins:
            part = getattr(user, "participant", None)
            label = display_name(user, int(user.id))
            if security.is_owner(int(user.id)):
                suffix = "Monitoring: ON · Demotable: NO (system owner)"
                admin_blocks.append(f"⭐ {label}\n{suffix}")
                continue
            if isinstance(part, t.ChannelParticipantCreator):
                suffix = "Monitoring: ON · Demotable: NO (Telegram rule)"
                owner_line = f"👑 Owner\n{label}\n{suffix}"
                continue
            promoted_by = getattr(part, "promoted_by", None)
            if self_creator:
                demotable = "YES"
            elif can_add and promoted_by == self.userbot.self_id:
                demotable = "YES (promoted by this account)"
            else:
                demotable = "NO (hierarchy)"
            suffix = f"Monitoring: ON · Demotable: {demotable}"
            admin_blocks.append(f"⭐ {label}\n{suffix}")

        if owner_line:
            lines.append(owner_line)
            lines.append("")
        if admin_blocks:
            lines.append("🛡️ Administrators (Telegram)")
            for block in admin_blocks:
                lines.extend(block.split("\n"))
        else:
            lines.append("No additional Telegram administrators found.")

        # Trust roles of THIS system (global, ID-keyed)
        lines.append("")
        lines.append("🔧 Trust roles (this system)")
        lines.append("👑 Owner — complete access (protected, immutable)")
        role_rows = self.db.list_admins()
        if not role_rows:
            lines.append("• none granted yet — use /trust inside a group")
        icon = {config.ROLE_SECURITY: "🛡️", config.ROLE_TRUSTED: "⭐",
                config.ROLE_MODERATOR: "🔧"}
        for r in role_rows:
            u = self.db.get_user(int(r["user_id"]))
            label = f"@{u['username']}" if u and u["username"] \
                else f"id:{r['user_id']}"
            lines.append(f"{icon.get(r['role'], '•')} {r['role']}: {label}")

        # Manually promoted admins detected by the watcher
        detected = self.db.list_settings_prefix(f"manual_admin:{chat_id}:")
        if detected:
            lines.append("")
            lines.append("📡 Detected manual promotions")
            for row in detected:
                uid = row["key"].rsplit(":", 1)[-1]
                state = ("automatic protection AVAILABLE"
                         if row["value"].endswith("modifiable")
                         else "automatic protection NOT available")
                lines.append(f"• id:{uid} — {state}")

        return "\n".join(lines), buttons

    # ----- settings ----------------------------------------------------------------------

    def view_settings(self):
        def lamp(key: str) -> str:
            return "🟢" if self.db.get_feature(key) else "⚪"

        locked = len(self.db.locked_groups())
        text = (
            "⚙️ SETTINGS\n\n"
            "Changes apply instantly and persist in the settings store.\n\n"
            "🛡️ Protection\n"
            f"Spam Protection (anti-flood): {self._feat('spam_protection')}\n\n"
            "👮 Admin Security\n"
            f"Admin Monitoring: {self._feat('admin_monitoring')}\n"
            f"Mass-Ban Detection: {self._feat('massban_detection')}\n"
            f"Mass-Delete Detection: {self._feat('massdelete_detection')}\n\n"
            "🔔 Notifications\n"
            f"Owner Alerts: {self._feat('owner_alerts')}\n\n"
            "📋 Logging\n"
            f"Audit Logs: {self._feat('audit_logging')}\n"
            "Critical security responses are always recorded.\n\n"
            "🚨 Emergency Mode\n"
            f"Groups in lockdown: {locked}")
        buttons = [
            [Button.inline(f"Spam Protection: {lamp('spam_protection')}",
                           b"set:k:spam_protection")],
            [Button.inline(f"Admin Monitoring: {lamp('admin_monitoring')}",
                           b"set:k:admin_monitoring")],
            [Button.inline(f"Mass-Ban Detection: {lamp('massban_detection')}",
                           b"set:k:massban_detection")],
            [Button.inline(f"Mass-Delete Detection: {lamp('massdelete_detection')}",
                           b"set:k:massdelete_detection")],
            [Button.inline(f"Owner Alerts: {lamp('owner_alerts')}",
                           b"set:k:owner_alerts")],
            [Button.inline(f"Audit Logs: {lamp('audit_logging')}",
                           b"set:k:audit_logging")],
            [Button.inline("🚨 Emergency Mode…", b"lock:m")],
            [Button.inline("◀️ Back", b"home")],
        ]
        return text, buttons

    def view_group_settings(self, chat_id: int):
        g = self._group_or_none(chat_id)
        back = [[Button.inline("◀️ Back", b"grp:l")]]
        if not g:
            return "Group not found or protection disabled.", back
        new_member = ("🟢 ON" if config.LOCKDOWN_RESTRICT_NEW_MEMBERS
                      else "⚪ OFF")
        text = (
            "⚙️ Group Settings\n\n"
            f"{g['title'] or chat_id}\n\n"
            f"Protection: {'🟢 ON' if g['enabled'] else '⚪ OFF'}\n"
            f"Emergency Mode: {'🔴 LOCKDOWN' if g['lockdown'] else '🔵 normal'}\n"
            f"New-member restriction during lockdown: {new_member} "
            "(global config)\n\n"
            "Disabling protection pauses monitoring and gmute enforcement "
            "for this group only.")
        cid = str(chat_id).encode()
        toggle_label = ("⏸ Disable protection" if g["enabled"]
                        else "▶️ Enable protection")
        buttons = [
            [Button.inline(toggle_label, b"grp:t:" + cid)],
            [(Button.inline("🔓 Unlock group", b"unlk:a:" + cid)
              if g["lockdown"]
              else Button.inline("🚨 Lockdown group", b"lock:a:" + cid))],
            [Button.inline("◀️ Back", b"grp:l")],
        ]
        return text, buttons

    # ----- logs ----------------------------------------------------------------------------

    def view_logs(self, page: int = 0):
        total = self.db.count_events()
        if total == 0:
            text = (
                "📋 SECURITY LOG\n\n"
                "No security events recorded yet.\n\n"
                "Everything the watcher sees will appear here with "
                "timestamps — never any credentials.")
            return text, [[Button.inline("◀️ Back", b"home")]]

        pages = max(1, (total + _LOG_PAGE_SIZE - 1) // _LOG_PAGE_SIZE)
        page = max(0, min(page, pages - 1))
        rows = self.db.events_page(_LOG_PAGE_SIZE, page * _LOG_PAGE_SIZE)
        icon_map = {
            "security.mass_ban": "🚨", "security.mass_delete": "⚠️",
            "security.spam_flood": "🧹", "admin.ban": "🔨",
            "admin.restrict": "🤐", "admin.unban": "🕊",
            "admin.promote": "⬆️", "admin.demote": "⬇️",
            "gmute": "🌐", "group.lockdown": "🚨", "group.unlock": "🔓",
            "warn": "⚠️", "trust": "🤝",
        }
        lines = [f"📋 SECURITY LOG  ({page + 1}/{pages})", ""]
        for r in rows:
            action = str(r["action"])
            icon = icon_map.get(action, "•")
            pretty = action.replace(".", " ").replace("_", " ")
            when = datetime.fromtimestamp(int(r["created_at"]), self._tz())
            lines.append(f"{icon} {pretty}")
            if r["admin_id"]:
                lines.append(f"Admin: id:{r['admin_id']}")
            if r["target_id"]:
                lines.append(f"Target: id:{r['target_id']}")
            lines.append(f"Action: {r['result']}")
            lines.append(f"Time: {when.strftime('%H:%M · %d %b %Y')}")
            lines.append("━━━━━━━━━━━━━━")
        buttons: list[list] = []
        nav = []
        if page > 0:
            nav.append(Button.inline("◀️ Newer", f"log:{page - 1}".encode()))
        if page < pages - 1:
            nav.append(Button.inline("Older ▶️", f"log:{page + 1}".encode()))
        if nav:
            buttons.append(nav)
        buttons.append([Button.inline("🔄 Refresh", f"log:{page}".encode())])
        buttons.append([Button.inline("🛡️ Security", b"sec"),
                        Button.inline("◀️ Back", b"home")])
        return "\n".join(lines), buttons

    # ----- lockdown / unlock -----------------------------------------------------------------

    def view_lock_menu(self, unlock: bool = False):
        rows = self.db.enabled_groups()
        rows = [g for g in rows if bool(g["lockdown"]) == unlock]
        verb, icon = ("Unlock", "🔓") if unlock else ("Lockdown", "🚨")
        if not rows:
            note = ("No groups are currently in lockdown."
                    if unlock else
                    "No protected groups available — /rescan first.")
            return f"{icon} Emergency {verb}\n\n{note}", \
                [[Button.inline("◀️ Back", b"sec")]]
        text = (f"{icon} {'Disable' if unlock else 'Enable'} Emergency "
                "Lockdown\n\nChoose a target group:")
        prefix = "unlk:a:" if unlock else "lock:a:"
        buttons = [[Button.inline(
            f"{icon} {g['title'] or g['chat_id']}",
            (prefix + str(g["chat_id"])).encode())]
            for g in rows[:_MAX_GROUP_BUTTONS]]
        if len(rows) > 1:
            buttons.append([Button.inline(
                f"{icon} ALL GROUPS ({len(rows)})", (prefix + "all").encode())])
        buttons.append([Button.inline("❌ CANCEL", b"lock:n")])
        return text, buttons

    def view_lock_confirm(self, sel: str, unlock: bool = False):
        verb, icon = ("Disable", "🔓") if unlock else ("Enable", "🚨")
        if sel == "all":
            target = "ALL protected groups"
        else:
            g = self.db.get_group(int(sel))
            target = str(g["title"] or sel) if g else sel
        if unlock:
            effect = "This returns the group to normal protection thresholds."
        else:
            effect = ("This will activate stricter group protection:\n"
                      "  • lower rogue-admin thresholds\n"
                      "  • new members restricted on join\n"
                      "  • increased logging\n\n"
                      "The owner is notified — and can never be locked out.")
        text = (f"{icon} {verb} Emergency Lockdown?\n\n"
                f"Target: {target}\n\n{effect}")
        prefix = "unlk:y:" if unlock else "lock:y:"
        buttons = [[Button.inline(f"{icon} CONFIRM", (prefix + sel).encode()),
                    Button.inline("❌ CANCEL", b"lock:n")]]
        return text, buttons

    async def _execute_lock(self, sel: str, unlock: bool, actor_id: int):
        rows = self.db.enabled_groups()
        if sel != "all":
            rows = [g for g in rows if g["chat_id"] == int(sel)]
        # only the rows whose state actually changes
        rows = [g for g in rows if bool(g["lockdown"]) == unlock]
        if not rows:
            return ("ℹ️ Nothing changed — the target group(s) were already "
                    "in that state.",
                    [[Button.inline("◀️ Back", b"sec")]])
        names = []
        for g in rows:
            self.db.set_lockdown(g["chat_id"], not unlock)
            self.db.log_event(g["chat_id"], actor_id, None,
                              "group.unlock" if unlock else "group.lockdown",
                              "ok", group_title=g["title"])
            names.append(str(g["title"] or g["chat_id"]))
        if unlock:
            headline = "🔓 EMERGENCY MODE DISABLED"
            sub = "Normal security mode restored for:"
        else:
            headline = "🚨 EMERGENCY MODE ACTIVE"
            sub = "Enhanced monitoring is now enabled for:"
        text = f"{headline}\n\n{sub}\n" + "\n".join(f"  • {n}" for n in names)
        if not unlock:
            await self.notify_owner(
                f"🚨 Emergency lockdown ENABLED for {len(names)} group(s): "
                + ", ".join(names))
        buttons = [[Button.inline("🛡️ Security", b"sec"),
                    Button.inline("◀️ Back", b"home")]]
        return text, buttons

    # ------------------------------------------------------------------
    # Send helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _norm(view):
        return view if isinstance(view, tuple) else (view, None)

    async def _send(self, event, view) -> None:
        text, buttons = self._norm(view)
        await event.respond(text, buttons=buttons)

    async def _edit(self, event, view) -> None:
        text, buttons = self._norm(view)
        try:
            await event.edit(text, buttons=buttons)
        except Exception:
            await event.respond(text, buttons=buttons)

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _register_handlers(self) -> None:
        assert self.client is not None

        @self.client.on(events.NewMessage(incoming=True, func=lambda e: e.is_private))
        async def _router(event: events.NewMessage.Event) -> None:
            await self._warm_owner_entity(event)
            text = (event.raw_text or "").strip()
            sender = event.sender_id

            # Stale login state expiry (owner flow only)
            if self._login and \
                    time.time() - self._login.created_at > config.LOGIN_STATE_TTL:
                await self._cleanup_login()
                await event.reply("Login attempt expired — start again with /login.")
                if not text.startswith("/"):
                    return

            # ---------- authorization gate (numeric IDs only) --------------
            if not self._is_owner(sender):
                if not text.startswith("/"):
                    return  # strangers' chatter is ignored entirely
                cmd = text[1:].split()[0].split("@")[0].lower()
                if cmd == "start":
                    await self._send(event, self.view_home(public=True))
                elif cmd == "help":
                    await self._send(event, self.view_help(public=True))
                elif self._is_security_user(sender) and cmd in {
                        "lockdown", "unlock"}:
                    # Trusted security staff get emergency controls here;
                    # all informational views stay owner-only.
                    await self._dispatch_command(event, cmd, text)
                else:
                    await event.reply(
                        "⛔ SecurityGuard is a private management console. "
                        "You are not authorized to use this command.")
                return

            # ---------- owner flow ------------------------------------------
            if text.startswith("/"):
                cmd = text[1:].split()[0].split("@")[0].lower()
                handled = await self._dispatch_command(event, cmd, text)
                if not handled:
                    await event.reply("Unknown command. Use /help.")
                return

            # Non-command text only matters mid-login.
            if self._login:
                await self._handle_login_input(event, text)

        @self.client.on(events.CallbackQuery)
        async def _callback(event: events.CallbackQuery.Event) -> None:
            data = (event.data or b"").decode("utf-8", "ignore")
            sender = event.sender_id
            await self._warm_owner_entity(event)

            # Public surface (non-owners): /start & /help navigation only.
            if data.startswith("pub:"):
                await event.answer()
                if data == "pub:help":
                    await self._edit(event, self.view_help(public=True))
                else:
                    await self._edit(event, self.view_home(public=True))
                return

            if not self._is_owner(sender) and not self._is_security_user(sender):
                await event.answer("Not authorized.", alert=True)
                return

            # Non-owner security users may touch the lock/unlock flows only.
            if not self._is_owner(sender) and not data.startswith(
                    ("lock", "unlk")):
                await event.answer("Owner-only section.", alert=True)
                return

            try:
                await self._dispatch_callback(event, data)
            except Exception as exc:
                log.warning("callback %r failed: %s", data.split(':')[0],
                            security.redact(str(exc)))
            # Acknowledge exactly once — branches that already answered with a
            # toast/alert keep priority (Telethon tracks _answered itself).
            if not getattr(event, "_answered", False):
                try:
                    await event.answer()
                except Exception:
                    pass

    async def _dispatch_command(self, event, cmd: str, raw: str) -> bool:
        if cmd == "start":
            await self._send(event, self.view_home())
        elif cmd == "help":
            await self._send(event, self.view_help())
        elif cmd == "login":
            await self._cmd_login(event)
        elif cmd == "cancel":
            await self._cmd_cancel(event)
        elif cmd == "logout":
            await self._send(event, self.view_logout_confirm())
        elif cmd == "session":
            if not self.userbot.running:
                await self._cmd_session(event)  # auto-reconnect attempt
            await self._send(event, self.view_session())
        elif cmd == "security":
            await self._send(event, self.view_security())
        elif cmd == "groups":
            await self._send(event, self.view_groups())
        elif cmd == "admins":
            await self._send(event, self.view_admins_overview())
        elif cmd == "settings":
            await self._send(event, self.view_settings())
        elif cmd == "logs":
            await self._send(event, self.view_logs(0))
        elif cmd == "rescan":
            await self._cmd_rescan(event)
        elif cmd == "lockdown":
            if not self._is_security_user(event.sender_id):
                await event.reply("⛔ Only the owner or a security admin may use lockdown.")
                return True
            await self._send(event, self.view_lock_menu(unlock=False))
        elif cmd == "unlock":
            if not self._is_security_user(event.sender_id):
                await event.reply("⛔ Only the owner or a security admin may unlock.")
                return True
            await self._send(event, self.view_lock_menu(unlock=True))
        elif cmd in _BOT_MOD_OPS:
            await self._handle_mod_command(event, cmd, raw)
        else:
            return False
        return True

    async def _dispatch_callback(self, event, data: str) -> None:
        parts = data.split(":")
        head = parts[0]

        if head == "home":
            await self._edit(event, self.view_home())
        elif head == "help":
            await self._edit(event, self.view_help())
        elif head == "login":
            # Triggers the EXISTING secure /login flow (same code path).
            await self._cmd_login(event)
        elif head == "sec":
            await self._edit(event, self.view_security())
        elif head == "ses":
            await self._edit(event, self.view_session())
        elif head == "lout":
            sub = parts[1] if len(parts) > 1 else "n"
            if sub == "a":
                await self._edit(event, self.view_logout_confirm())
            elif sub == "y":
                await self._perform_logout(event, edit=True)
            else:
                await self._edit(event, self.view_session())
        elif head == "grp":
            sub = parts[1] if len(parts) > 1 else "l"
            if sub == "l":
                await self._edit(event, self.view_groups())
            elif sub == "rescan":
                if not self.userbot.running:
                    await event.answer("Worker offline — /login first.", alert=True)
                    return
                count = await self.userbot.sync_groups()
                await event.answer(f"Rescan: {count} admin group(s) registered.",
                                   alert=True)
                await self._edit(event, self.view_groups())
            elif sub == "s":
                await self._edit(event, self.view_group_security(int(parts[2])))
            elif sub == "a":
                await self._edit(event, await self.view_group_admins(int(parts[2])))
            elif sub == "c":
                await self._edit(event, self.view_group_settings(int(parts[2])))
            elif sub == "t":
                g = self.db.get_group(int(parts[2]))
                if g:
                    new_state = not g["enabled"]
                    self.db.set_group_enabled(g["chat_id"], new_state)
                    self.db.log_event(g["chat_id"], config.OWNER_ID, None,
                                      "group.toggle_protection",
                                      "enabled" if new_state else "disabled",
                                      group_title=g["title"])
                await self._edit(event, self.view_groups())
        elif head == "adm":
            await self._edit(event, self.view_admins_overview())
        elif head == "log":
            page = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            await self._edit(event, self.view_logs(page))
        elif head == "set":
            sub = parts[1] if len(parts) > 1 else "p"
            if sub == "k" and len(parts) > 2:
                key = parts[2]
                if key in config.FEATURE_TOGGLES:
                    self.db.set_feature(key, not self.db.get_feature(key))
                    await event.answer(
                        f"{key.replace('_', ' ')} → "
                        f"{'ON' if self.db.get_feature(key) else 'OFF'}")
            await self._edit(event, self.view_settings())
        elif head == "lock":
            sub = parts[1] if len(parts) > 1 else "m"
            if sub == "m":
                await self._edit(event, self.view_lock_menu(unlock=False))
            elif sub == "a":
                await self._edit(event, self.view_lock_confirm(parts[2], unlock=False))
            elif sub == "y":
                result = await self._execute_lock(parts[2], unlock=False,
                                                  actor_id=event.sender_id)
                await self._edit(event, result)
            else:
                await self._edit(event, self.view_security())
        elif head == "unlk":
            sub = parts[1] if len(parts) > 1 else "m"
            if sub == "m":
                await self._edit(event, self.view_lock_menu(unlock=True))
            elif sub == "a":
                await self._edit(event, self.view_lock_confirm(parts[2], unlock=True))
            elif sub == "y":
                result = await self._execute_lock(parts[2], unlock=True,
                                                  actor_id=event.sender_id)
                await self._edit(event, result)
            else:
                await self._edit(event, self.view_security())
        elif head == "mod":
            # mod:g:<op>:<target_uid>:<chat_id>
            if len(parts) == 5 and parts[1] == "g":
                await self._execute_bot_mod(event, op=parts[2],
                                            target_id=int(parts[3]),
                                            chat_id=int(parts[4]))
        else:
            await event.answer("Unknown action.", alert=True)

    # ------------------------------------------------------------------
    # Management-bot moderation relay (existing worker reused)
    # ------------------------------------------------------------------

    async def _resolve_mod_target(self, event, args: str):
        """Target sources, in order:
        1. reply to a forwarded message → the original sender's ID;
        2. @username / numeric ID argument.
        Returns (user_id, label, error)."""
        reply = await event.get_reply_message()
        if reply is not None and getattr(reply, "fwd_from", None):
            from_id = getattr(reply.fwd_from, "from_id", None)
            uid = getattr(from_id, "user_id", None)
            if uid:
                return int(uid), f"id:{uid}", None
            return None, "", ("That message was forwarded anonymously — the "
                              "sender's ID is hidden. Use @username instead.")

        tokens = args.split()
        if tokens and tokens[0].startswith("/"):
            tokens = tokens[1:]
        from admin_commands import parse_duration
        for tok in tokens:
            if parse_duration(tok) or tok.isdigit() and len(tok) < 6:
                continue
            if tok.startswith("@") or tok.lstrip("-").isdigit():
                if not self.userbot.client:
                    return None, "", "Security worker offline — /login first."
                try:
                    if tok.lstrip("-").isdigit():
                        entity = await self.userbot.client.get_entity(int(tok))
                    else:
                        entity = await self.userbot.client.get_entity(tok.lstrip("@"))
                except ValueError:
                    return None, "", ("User not found — unknown ID/username, or "
                                      "the account has never seen them.")
                except Exception as exc:
                    return None, "", f"Lookup failed: {type(exc).__name__}"
                if isinstance(entity, t.Channel):
                    return None, "", "That is a channel/group, not a user."
                return int(entity.id), display_name(entity, int(entity.id)), None
        return None, "", ("No target found. Use /ban @username, or forward a "
                          "message from the user here and reply with the command.")

    async def _handle_mod_command(self, event, op: str, raw: str) -> None:
        if not self.userbot.running:
            await event.respond("⚠️ Security worker offline — /login, then /rescan.")
            return

        duration = None
        if op == "mute":
            from admin_commands import parse_duration
            for tok in raw.split():
                d = parse_duration(tok)
                if d:
                    duration = d
                    break

        target_id, label, err = await self._resolve_mod_target(event, raw)
        if err:
            await event.respond(f"⚠️ {err}")
            return

        # Owner shield + connected-account shield (same choke-point as groups).
        shield = security.guard_target(config.OWNER_ID, target_id)
        if shield:
            await event.respond(f"🛡 {shield}")
            return
        if target_id == self.userbot.self_id:
            await event.respond("🛡 Refused: the connected account cannot be its "
                                "own moderation target.")
            return

        if op in _GLOBAL_OPS:
            await self._execute_bot_mod(event, op=op, target_id=target_id,
                                        chat_id=None, label=label,
                                        duration=duration)
            return

        groups = self.db.enabled_groups()
        if not groups:
            await event.respond("No protected groups — /rescan first.")
            return
        if len(groups) == 1:
            await self._execute_bot_mod(event, op=op, target_id=target_id,
                                        chat_id=int(groups[0]["chat_id"]),
                                        label=label, duration=duration)
            return

        text = (f"🔨 /{op} — {label}\n\n"
                "Choose the group where this action should run:")
        buttons = []
        for g in groups[:_MAX_GROUP_BUTTONS]:
            data = f"mod:g:{op}:{target_id}:{g['chat_id']}".encode()
            buttons.append([Button.inline(f"👥 {g['title'] or g['chat_id']}", data)])
        buttons.append([Button.inline("❌ CANCEL", b"sec")])
        await event.respond(text, buttons=buttons)

    async def _execute_bot_mod(self, event, op: str, target_id: int,
                               chat_id: int | None, label: str | None = None,
                               duration: int | None = None) -> None:
        if label is None:
            try:
                ent = await self.userbot.client.get_entity(target_id)
                label = display_name(ent, target_id)
            except Exception:
                label = f"id:{target_id}"
        ok, message = await self.userbot.run_moderation(
            op, chat_id, target_id, actor_id=config.OWNER_ID, duration=duration)
        where = ""
        if chat_id is not None:
            g = self.db.get_group(chat_id)
            if g:
                where = f"\nGroup: {g['title'] or chat_id}"
        icon = "✅" if ok else "✖️"
        text = f"{icon} /{op} — {label}{where}\n\n{message}"
        buttons = [[Button.inline("🛡️ Security", b"sec"),
                    Button.inline("👥 Groups", b"grp:l")]]
        await self._edit(event, (text, buttons))

    # ------------------------------------------------------------------
    # Legacy entry points (behavior preserved)
    # ------------------------------------------------------------------

    async def _cmd_rescan(self, event) -> None:
        if not self.userbot.running:
            await event.respond("Userbot offline — /login first.")
            return
        count = await self.userbot.sync_groups()
        await event.respond(f"Rescan complete — {count} group(s) with admin "
                            f"rights detected and registered.")

    async def _cmd_session(self, event) -> None:
        """Legacy behavior: opportunistic worker reconnect attempt.
        Rendering happens in view_session()."""
        if self.db.get_session(config.OWNER_ID) and not self.userbot.running:
            await self.userbot.start(config.OWNER_ID)

    # ------------------------------------------------------------------
    # /login flow (unchanged secure implementation)
    # ------------------------------------------------------------------

    async def _cmd_login(self, event) -> None:
        async with self._login_lock:
            if self._login is not None:
                await event.respond("A login is already in progress. "
                                    "Finish it or /cancel first.")
                return
            if not self._is_owner(event.sender_id):
                await event.respond("⛔ Only the configured owner may connect "
                                    "an account.")
                return

            client = TelegramClient(
                StringSession(), config.API_ID, config.API_HASH,
                device_model=config.DEVICE_MODEL)
            try:
                await client.connect()
            except Exception as exc:
                await client.disconnect()
                await event.respond("Could not reach Telegram: "
                                    f"{type(exc).__name__}. Try again shortly.")
                return

            self._login = LoginState(stage="phone", client=client)
        await event.respond(
            "🔐 Step 1/3 — phone number\n"
            "Reply with the phone number of the account to connect, in "
            "international format (e.g. +15551234567).\n\n"
            "Rules:\n"
            "• the account must be yours and match the configured owner id\n"
            "• your message is deleted immediately after being read\n"
            "• codes, passwords and session strings are never shown or logged\n"
            "• /cancel aborts at any time")

    async def _handle_login_input(self, event, text: str) -> None:
        state = self._login
        if state is None:
            return

        # Delete the user's message FIRST — it carries a phone number, a
        # sign-in code or a 2FA password. Never log `text` anywhere below.
        try:
            await event.delete()
        except Exception:
            pass  # best effort; content still never persisted

        if state.stage == "phone":
            await self._stage_phone(event, state, text)
        elif state.stage == "code":
            await self._stage_code(event, state, text)
        elif state.stage == "password":
            await self._stage_password(event, state, text)

    async def _stage_phone(self, event, state: LoginState, phone: str) -> None:
        if not _PHONE_RE.match(phone):
            await event.respond("That does not look like an international phone "
                                "number (format +15551234567). Try again or /cancel.")
            return
        try:
            sent = await state.client.send_code_request(phone)
        except PhoneNumberInvalidError:
            await event.respond("Telegram says this phone number is invalid. "
                                "Check it and send again, or /cancel.")
            return
        except PhoneNumberBannedError:
            await self._cleanup_login()
            await event.respond("This phone number is banned by Telegram. "
                                "Login aborted.")
            return
        except FloodWaitError as fw:
            await event.respond(f"Telegram rate limit: wait {fw.seconds}s, then "
                                "send the number again.")
            return
        except Exception as exc:
            log.error("send_code_request failed: %s", type(exc).__name__)
            await self._cleanup_login()
            await event.respond("Login failed while requesting the code "
                                f"({type(exc).__name__}). Start again with /login.")
            return

        state.phone = phone
        state.phone_code_hash = sent.phone_code_hash
        state.stage = "code"
        await event.respond(
            "🔑 Step 2/3 — verification code\n"
            "Telegram just sent a sign-in code. Reply with the digits only.\n"
            "Your reply is deleted immediately and never logged.")

    async def _stage_code(self, event, state: LoginState, text: str) -> None:
        code = re.sub(r"[\s-]", "", text)
        try:
            await state.client.sign_in(
                phone=state.phone, code=code,
                phone_code_hash=state.phone_code_hash)
        except PhoneCodeInvalidError:
            state.attempts += 1
            left = config.LOGIN_MAX_CODE_ATTEMPTS - state.attempts
            if left <= 0:
                await self._cleanup_login()
                await event.respond("Too many wrong codes — login aborted. "
                                    "Start again with /login.")
            else:
                await event.respond(f"Wrong code ({left} attempt(s) left). "
                                    "Send the code again, or /cancel.")
            return
        except PhoneCodeExpiredError:
            await self._cleanup_login()
            await event.respond("That code expired. Start again with /login "
                                "to request a fresh one.")
            return
        except SessionPasswordNeededError:
            state.stage = "password"
            state.attempts = 0
            await event.respond(
                "🗝 Step 3/3 — two-factor password\n"
                "This account has 2FA enabled. Reply with your Telegram "
                "cloud password. It is used once for sign-in, then deleted "
                "from memory — never stored, never logged.")
            return
        except Exception as exc:
            log.error("code sign-in failed: %s", type(exc).__name__)
            await self._cleanup_login()
            await event.respond(f"Login failed ({type(exc).__name__}). "
                                "Start again with /login.")
            return
        await self._finalize_login(event, state)

    async def _stage_password(self, event, state: LoginState, password: str) -> None:
        try:
            # Telethon performs the SRP exchange internally; the password
            # exists only in this local variable for the duration of the call.
            await state.client.sign_in(password=password)
        except PasswordHashInvalidError:
            state.attempts += 1
            left = config.LOGIN_MAX_CODE_ATTEMPTS - state.attempts
            if left <= 0:
                await self._cleanup_login()
                await event.respond("Too many wrong passwords — login aborted. "
                                    "Start again with /login.")
            else:
                await event.respond(f"Wrong 2FA password ({left} attempt(s) left). "
                                    "Send it again, or /cancel.")
            return
        except Exception as exc:
            log.error("password sign-in failed: %s", type(exc).__name__)
            await self._cleanup_login()
            await event.respond(f"Login failed ({type(exc).__name__}). "
                                "Start again with /login.")
            return
        finally:
            password = ""  # scrub the local variable as early as possible
        await self._finalize_login(event, state)

    async def _finalize_login(self, event, state: LoginState) -> None:
        try:
            me = await state.client.get_me()
        except Exception as exc:
            log.error("get_me after login failed: %s", type(exc).__name__)
            await self._cleanup_login()
            await event.respond("Login finished but the account could not be "
                                "read. Try again with /login.")
            return

        # Hard rule: the connected account must be the configured owner.
        if int(me.id) != config.OWNER_ID:
            log.warning("Rejected login of non-owner account id=%s", me.id)
            try:
                await state.client.log_out()  # discard the foreign session
            except Exception:
                pass
            await self._cleanup_login()
            await event.respond(
                "Refused: the connected account is not the configured owner. "
                "The session has been discarded and NOT stored.")
            return

        # Export → encrypt → store. The plaintext session string never
        # touches the DB, the logs, or any chat message.
        session_string = state.client.session.save()
        encrypted = self.cipher.encrypt(session_string)
        session_string = ""  # scrub
        masked = security.mask_phone(getattr(me, "phone", None))
        self.db.save_session(int(me.id), encrypted, masked)

        client = state.client
        self._login = None           # drop state BEFORE heavy work
        try:
            await client.disconnect()
        except Exception:
            pass
        del client

        # Swap the worker onto the freshly stored session now.
        if self.userbot.running:
            await self.userbot.stop(revoke=False)
        ok, err = await self.userbot.start(int(me.id))
        lines = [
            "✅ Login successful",
            f"Account: {display_name(me, int(me.id))} ({me.id})",
            f"Phone: {masked or 'unavailable'}",
            f"Security worker: {'online' if ok else 'offline'}",
            f"Monitored groups: {len(self.db.enabled_groups())}",
        ]
        if err:
            lines.append(f"Worker note: {err}")
        await event.respond("\n".join(lines))
        log.info("Owner login completed for id=%s", me.id)

        # Land on the connected home screen.
        await self._send(event, self.view_home())

    async def _cmd_cancel(self, event) -> None:
        if self._login is None:
            await event.respond("Nothing to cancel.")
            return
        await self._cleanup_login()
        await event.respond("Login attempt cancelled; no data was stored.")

    async def _cleanup_login(self) -> None:
        """Destroy the transient state and disconnect its temp client."""
        state, self._login = self._login, None
        if state is None:
            return
        try:
            await state.client.disconnect()
        except Exception:
            pass
        # Scrub what MTProto required us to hold transiently.
        state.phone = ""
        state.phone_code_hash = ""

    # ------------------------------------------------------------------
    # /logout — true revocation (unchanged core, new confirm UI)
    # ------------------------------------------------------------------

    async def _cmd_logout(self, event) -> None:
        """Text-command path kept for muscle memory; shows the confirm UI."""
        await self._send(event, self.view_logout_confirm())

    async def _perform_logout(self, event, edit: bool = False) -> None:
        row = self.db.get_session(config.OWNER_ID)
        if not self.userbot.running and not row:
            await event.respond("No active session to revoke.")
            return
        # stop(revoke=True) calls auth.logOut (server-side invalidation,
        # visible in Telegram → Settings → Devices) and deletes the local
        # encrypted copy.
        await self.userbot.stop(revoke=True)
        self.db.revoke_session(config.OWNER_ID)
        log.info("Session revoked for owner id=%s", config.OWNER_ID)
        text = ("🚪 Logged out.\n\n"
                "• MTProto session revoked on Telegram's servers\n"
                "• Local encrypted session deleted\n"
                "• Security worker stopped\n\n"
                "Use /login to connect again.")
        if edit:
            await self._edit(event, (
                text, [[Button.inline("🔐 Connect Telegram", b"login")]]))
        else:
            await event.respond(text)
