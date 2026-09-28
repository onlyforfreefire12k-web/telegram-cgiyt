"""
bot.py — the owner-facing management bot.

Purpose
-------
Gives the OWNER a private, authenticated control channel to:

* /login    — connect their Telegram account via the official MTProto
              authorization flow (phone → code → optional 2FA password);
* /logout   — revoke the session server-side and delete it locally;
* /session  — inspect connection status (never any credentials);
* /security — global security overview + recent audit events;
* /groups   — list monitored groups; /rescan re-discovers admin groups.

Credential hygiene (critical)
-----------------------------
* The phone number, sign-in code and 2FA password are read into memory,
  the user's message is deleted immediately (best effort), and the values
  are NEVER logged, stored in the database, or re-sent. Code/password are
  kept only as local variables for the duration of one sign_in call.
* The resulting MTProto session string is encrypted (Fernet) before it
  touches SQLite, and is never shown to anyone — including the owner.
* Only the configured OWNER_ID can talk to this bot at all; everyone else
  is ignored silently.
* The connected account must BE the owner account. If someone connects a
  different account, the session is discarded immediately.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field

from telethon import TelegramClient, events
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

import config
import security
from security import SessionCipher
from database import Database
from userbot import UserbotManager, display_name

log = logging.getLogger("bot")

_PHONE_RE = re.compile(r"^\+\d{7,15}$")


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
        self.client.parse_mode = "md"
        self._register_handlers()
        self.status["bot"] = True
        me = await self.client.get_me()
        log.info("Management bot online as @%s", getattr(me, "username", "?"))

    async def stop(self) -> None:
        self.status["bot"] = False
        await self._cleanup_login()
        if self.client:
            await self.client.disconnect()
            self.client = None

    async def notify_owner(self, text: str) -> None:
        """All owner notifications flow through the BOT, so the userbot
        account never needs to initiate private conversations."""
        if not self.client:
            log.warning("Bot offline; dropping owner notification.")
            return
        try:
            await self.client.send_message(config.OWNER_ID, text)
        except Exception as exc:
            log.error("notify_owner failed: %s", security.redact(str(exc)))

    async def run_until_stopped(self, stop_event: asyncio.Event) -> None:
        await stop_event.wait()

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _register_handlers(self) -> None:
        assert self.client is not None

        @self.client.on(events.NewMessage(incoming=True, func=lambda e: e.is_private))
        async def _router(event: events.NewMessage.Event) -> None:
            if event.sender_id != config.OWNER_ID:
                return  # silent — this bot serves exactly one user
            text = (event.raw_text or "").strip()

            # Stale login state expiry
            if self._login and \
                    time.time() - self._login.created_at > config.LOGIN_STATE_TTL:
                await self._cleanup_login()
                await event.reply("Login attempt expired — start again with /login.")
                if not text.startswith("/"):
                    return

            if text.startswith("/"):
                cmd = text[1:].split()[0].split("@")[0].lower()
                if cmd in {"start", "help"}:
                    await self._cmd_help(event)
                elif cmd == "login":
                    await self._cmd_login(event)
                elif cmd == "cancel":
                    await self._cmd_cancel(event)
                elif cmd == "logout":
                    await self._cmd_logout(event)
                elif cmd == "session":
                    await self._cmd_session(event)
                elif cmd == "security":
                    await self._cmd_security(event)
                elif cmd == "groups":
                    await self._cmd_groups(event)
                elif cmd == "rescan":
                    await self._cmd_rescan(event)
                else:
                    await event.reply("Unknown command. Use /help.")
                return

            # Non-command text only matters mid-login.
            if self._login:
                await self._handle_login_input(event, text)

    # ------------------------------------------------------------------
    # Informational commands
    # ------------------------------------------------------------------

    async def _cmd_help(self, event) -> None:
        await event.reply(
            "**Security Userbot — owner console**\n\n"
            "/login — connect your Telegram account (MTProto)\n"
            "/logout — revoke the session (server-side) and delete it locally\n"
            "/session — connection status (no credentials, ever)\n"
            "/security — global security status + recent alerts\n"
            "/groups — monitored groups and lockdown state\n"
            "/rescan — re-discover groups where the account is admin\n"
            "/cancel — abort an in-progress login\n\n"
            "In any installed group, trusted roles can use:\n"
            "`/mute /unmute /ban /unban /kick /promote /demote`\n"
            "`/warn /warnings /gmute /ungmute /lockdown /unlock`\n"
            "`/trust /untrust /security` — reply to a user or pass @username."
        )

    async def _cmd_session(self, event) -> None:
        row = self.db.get_session(config.OWNER_ID)
        if not row:
            await event.reply("No session stored. Use /login to connect your account.")
            return
        age = int(time.time()) - int(row["created_at"])
        locked = len(self.db.locked_groups())
        lines = [
            "**Session status**",
            f"Connected account: `{row['user_id']}`",
            f"Phone: {row['phone_masked'] or 'unavailable'}",
            f"Authorized for: {age // 3600}h {(age % 3600) // 60}m",
            f"Worker running: {'yes' if self.userbot.running else 'no'}",
            f"Monitored groups: {len(self.db.enabled_groups())}"
            f" ({locked} in lockdown)",
            f"Global mute list: {len(self.db.list_gmutes())} user(s)",
            "",
            "Storage: MTProto session encrypted at rest (Fernet/AES). "
            "Session strings, codes and 2FA passwords are never displayed, "
            "logged or stored in plaintext.",
        ]
        if not self.userbot.running:
            action = await self.userbot.start(config.OWNER_ID)
            if action[0]:
                lines.append("\nWorker was offline — reconnected just now.")
            else:
                lines.append(f"\nWorker offline: {action[1]}")
        await event.reply("\n".join(lines))

    async def _cmd_security(self, event) -> None:
        rows = self.db.recent_events(limit=6)
        lines = [
            "**Global security status**",
            f"Mass-ban rule: {config.BAN_LIMIT_1}/{config.BAN_WINDOW_1}s, "
            f"{config.BAN_LIMIT_2}/{config.BAN_WINDOW_2}s",
            f"Mass-delete rule: {config.DELETE_LIMIT_1}/{config.DELETE_WINDOW_1}s, "
            f"{config.DELETE_LIMIT_2}/{config.DELETE_WINDOW_2}s",
            f"Auto-demote on mass-ban: "
            f"{'on' if config.AUTO_DEMOTE_ON_MASS_BAN else 'off'}",
            f"Auto-ban on mass-ban: "
            f"{'on' if config.AUTO_BAN_ON_MASS_BAN else 'off'}",
            f"Lockdown groups: {len(self.db.locked_groups())}",
            "",
            "Recent security events:",
        ]
        if not rows:
            lines.append("• none recorded")
        for r in rows:
            when = time.strftime("%Y-%m-%d %H:%M:%S",
                                 time.gmtime(int(r["created_at"])))
            lines.append(
                f"• `{r['action']}` group={r['group_id']} "
                f"admin={r['admin_id']} target={r['target_id']} "
                f"→ {r['result']} ({when} UTC)")
        await event.reply("\n".join(lines))

    async def _cmd_groups(self, event) -> None:
        rows = self.db.enabled_groups()
        if not rows:
            await event.reply("No monitored groups. Add the account as a group "
                              "admin, then /rescan or use /install in the group.")
            return
        lines = ["**Monitored groups**"]
        for g in rows:
            flag = " [LOCKDOWN]" if g["lockdown"] else ""
            lines.append(f"• {g['title'] or g['chat_id']} (`{g['chat_id']}`){flag}")
        await event.reply("\n".join(lines))

    async def _cmd_rescan(self, event) -> None:
        if not self.userbot.running:
            await event.reply("Userbot offline — /login first.")
            return
        count = await self.userbot.sync_groups()
        await event.reply(f"Rescan complete — {count} group(s) with admin "
                          f"rights detected and registered.")

    # ------------------------------------------------------------------
    # /login flow
    # ------------------------------------------------------------------

    async def _cmd_login(self, event) -> None:
        async with self._login_lock:
            if self._login is not None:
                await event.reply("A login is already in progress. "
                                  "Finish it or /cancel first.")
                return

            # Note: an existing worker keeps running during the handshake and
            # is only swapped out once the NEW session is fully authorized
            # (see _finalize_login) — a cancelled login changes nothing.

            client = TelegramClient(
                StringSession(), config.API_ID, config.API_HASH,
                device_model=config.DEVICE_MODEL)
            try:
                await client.connect()
            except Exception as exc:
                await client.disconnect()
                await event.reply(f"Could not reach Telegram: {type(exc).__name__}. "
                                  "Try again shortly.")
                return

            self._login = LoginState(stage="phone", client=client)
        await event.reply(
            "**Step 1/3 — phone number**\n"
            "Reply with the phone number of the account to connect, in "
            "international format (e.g. `+15551234567`).\n\n"
            "Rules:\n"
            "• the account must be **yours** and match the configured owner id\n"
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
            await event.reply("That does not look like an international phone "
                              "number (format `+15551234567`). Try again or /cancel.")
            return
        try:
            sent = await state.client.send_code_request(phone)
        except PhoneNumberInvalidError:
            await event.reply("Telegram says this phone number is invalid. "
                              "Check it and send again, or /cancel.")
            return
        except PhoneNumberBannedError:
            await self._cleanup_login()
            await event.reply("This phone number is banned by Telegram. "
                              "Login aborted.")
            return
        except FloodWaitError as fw:
            await event.reply(f"Telegram rate limit: wait {fw.seconds}s, then "
                              "send the number again.")
            return
        except Exception as exc:
            log.error("send_code_request failed: %s", type(exc).__name__)  # no payload
            await self._cleanup_login()
            await event.reply("Login failed while requesting the code "
                              f"({type(exc).__name__}). Start again with /login.")
            return

        state.phone = phone
        state.phone_code_hash = sent.phone_code_hash
        state.stage = "code"
        await event.reply(
            "**Step 2/3 — verification code**\n"
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
                await event.reply("Too many wrong codes — login aborted. "
                                  "Start again with /login.")
            else:
                await event.reply(f"Wrong code ({left} attempt(s) left). "
                                  "Send the code again, or /cancel.")
            return
        except PhoneCodeExpiredError:
            await self._cleanup_login()
            await event.reply("That code expired. Start again with /login "
                              "to request a fresh one.")
            return
        except SessionPasswordNeededError:
            state.stage = "password"
            state.attempts = 0
            await event.reply(
                "**Step 3/3 — two-factor password**\n"
                "This account has 2FA enabled. Reply with your Telegram "
                "cloud password. It is used once for sign-in, then deleted "
                "from memory — never stored, never logged.")
            return
        except Exception as exc:
            log.error("code sign-in failed: %s", type(exc).__name__)
            await self._cleanup_login()
            await event.reply(f"Login failed ({type(exc).__name__}). "
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
                await event.reply("Too many wrong passwords — login aborted. "
                                  "Start again with /login.")
            else:
                await event.reply(f"Wrong 2FA password ({left} attempt(s) left). "
                                  "Send it again, or /cancel.")
            return
        except Exception as exc:
            log.error("password sign-in failed: %s", type(exc).__name__)
            await self._cleanup_login()
            await event.reply(f"Login failed ({type(exc).__name__}). "
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
            await event.reply("Login finished but the account could not be "
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
            await event.reply(
                "Refused: the connected account is not the configured owner "
                f"(`OWNER_ID={config.OWNER_ID}`). The session has been "
                "discarded and NOT stored.")
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
        name = display_name(me, int(me.id))
        groups = len(self.db.enabled_groups())
        lines = [
            "**Login successful**",
            f"Account: {name} (`{me.id}`)",
            f"Phone: {masked or 'unavailable'}",
            f"Security worker: {'online' if ok else 'offline'}",
            f"Monitored groups: {groups}",
        ]
        if err:
            lines.append(f"Worker note: {err}")
        lines.append("")
        lines.append("Session stored encrypted. Use /logout to revoke it at "
                     "any time — revocation happens on Telegram's servers, "
                     "not just locally.")
        await event.reply("\n".join(lines))
        log.info("Owner login completed for id=%s", me.id)

    async def _cmd_cancel(self, event) -> None:
        if self._login is None:
            await event.reply("Nothing to cancel.")
            return
        await self._cleanup_login()
        await event.reply("Login attempt cancelled; no data was stored.")

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
    # /logout — true revocation
    # ------------------------------------------------------------------

    async def _cmd_logout(self, event) -> None:
        row = self.db.get_session(config.OWNER_ID)
        if not self.userbot.running and not row:
            await event.reply("No active session to revoke.")
            return
        # stop(revoke=True) calls auth.logOut (server-side invalidation,
        # visible in Telegram → Settings → Devices) and deletes the local
        # encrypted copy. Even if the network call fails, the local copy is
        # still destroyed below.
        await self.userbot.stop(revoke=True)
        self.db.revoke_session(config.OWNER_ID)
        log.info("Session revoked for owner id=%s", config.OWNER_ID)
        await event.reply(
            "**Logged out.**\n"
            "• MTProto session revoked on Telegram's servers\n"
            "• Local encrypted session deleted\n"
            "• Security worker stopped\n\n"
            "Use /login to connect again.")
