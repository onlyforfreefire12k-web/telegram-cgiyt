"""
admin_commands.py — trusted-role moderation commands executed by the
connected account inside configured groups.

Command surface
---------------
/install  /uninstall
/mute /unmute /ban /unban /kick /promote /demote    (reply or @username/ID)
/warn /warnings
/gmute /ungmute
/lockdown /unlock
/trust /untrust                                     (manage the trust roles)
/security                                           (per-group status)

Every command passes a mandatory gate BEFORE touching Telegram:

  1. the group is registered & enabled;
  2. the invoker holds a trust role with the required permission;
  3. the target is not the owner, not the invoker, not this account;
  4. the connected account actually holds the needed admin right here;
  5. if the target is an admin, Telegram's hierarchy must allow us to
     modify them — otherwise a clear error is returned. We never try to
     bypass Telegram's restrictions.

Untrusted invokers are ignored SILENTLY (no error, no acknowledgement)
so outsiders cannot even confirm the system is listening.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from telethon import events
from telethon.tl import types as t

import config
import security
from userbot import UserbotManager, display_name

log = logging.getLogger("admin_commands")

_COMMAND_RE = re.compile(r"^/([A-Za-z]+)(?:@\w+)?(?:\s+(.*))?$", re.S)
_DURATION_RE = re.compile(r"^(\d+)([smhd])$", re.IGNORECASE)
_DURATION_MULT = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# command → required trust permission
PERMISSIONS = {
    "install": "trust", "uninstall": "trust",
    "mute": "mute", "unmute": "unmute",
    "ban": "ban", "unban": "unban", "kick": "kick",
    "promote": "promote", "demote": "demote",
    "warn": "warn", "warnings": "warnings",
    "gmute": "gmute", "ungmute": "ungmute",
    "lockdown": "lockdown", "unlock": "unlock",
    "trust": "trust", "untrust": "untrust",
    "security": None,  # any trusted role may view status
}


def register(client, manager: UserbotManager) -> None:  # noqa: ANN001
    """Attach the unified command handler to the Telethon client."""

    @client.on(events.NewMessage(func=lambda e: e.is_group))
    async def _handler(event: events.NewMessage.Event) -> None:
        text = (event.raw_text or "").strip()
        match = _COMMAND_RE.match(text)
        if not match:
            return
        cmd = match.group(1).lower()
        args = (match.group(2) or "").strip()
        if cmd not in PERMISSIONS:
            return
        await dispatch(manager, event, cmd, args)


# ---------------------------------------------------------------------------
# Response + parsing helpers
# ---------------------------------------------------------------------------

async def respond(manager: UserbotManager, event, text: str) -> None:
    """Self-issued commands edit in place (clean); others get a reply."""
    try:
        if event.sender_id == manager.self_id:
            await event.edit(text)
        else:
            await event.reply(text)
    except Exception as exc:
        log.warning("respond failed: %s", security.redact(str(exc)))


def parse_duration(token: str) -> int | None:
    match = _DURATION_RE.match(token.strip())
    if not match:
        return None
    return min(int(match.group(1)) *
               _DURATION_MULT[match.group(2).lower()], 366 * 86400)


async def resolve_target(manager: UserbotManager, event, args: str):
    """Reply takes precedence; then @username/ID. Returns
    (user_id, entity, error_message)."""
    client = manager.client
    reply = await event.get_reply_message()
    tokens = args.split()

    if tokens and parse_duration(tokens[0]) and reply:  # "/mute 1h" w/ reply
        tokens = []

    if reply and not tokens:
        sender = await reply.get_sender()
        if sender is None:
            return None, None, "Could not identify the replied-to user."
        return int(sender.id), sender, None

    if not tokens:
        return None, None, ("Specify a user: reply to their message or use "
                            "`@username` / numeric ID.")

    handle = tokens[0]
    try:
        if handle.lstrip("-").isdigit():
            entity = await client.get_entity(int(handle))
        else:
            entity = await client.get_entity(handle.lstrip("@"))
    except ValueError:
        return None, None, ("User not found — unknown ID or username. "
                            "Tip: reply to one of their messages instead.")
    except Exception as exc:
        return None, None, f"User lookup failed: {type(exc).__name__}"
    if isinstance(entity, t.Channel):
        return None, None, "That identifier is a channel/group, not a user."
    return int(entity.id), entity, None


# ---------------------------------------------------------------------------
# The mandatory pre-flight gate
# ---------------------------------------------------------------------------

async def gate(manager: UserbotManager, event, cmd: str, args: str,
               *, need_target: bool, required_right: str | None,
               destructive: bool = True, skip_account_check: bool = False):
    """Returns (chat, chat_id, group, invoker_role, target_id, target_entity)
    on success, or None after handling the refusal/silent-ignore."""
    db = manager.db
    chat = await event.get_chat()
    chat_id = getattr(chat, "id", None)
    invoker = event.sender_id

    # 1 — registered group?
    group = db.get_group(chat_id)
    if cmd == "install":
        group = group  # may legitimately be missing
    elif not group or not group["enabled"]:
        return None  # not installed here → total silence

    # 2 — invoker trust role & permission
    role = db.get_admin_role(invoker)
    needed = PERMISSIONS.get(cmd)
    if needed and not security.has_permission(role, needed):
        return None  # silent: do not reveal the control surface
    if needed is None and role is None:
        return None  # /security visible to trusted roles only

    # 3 — target resolution + owner/self shields
    target_id, target_entity = None, None
    if need_target:
        target_id, target_entity, err = await resolve_target(manager, event, args)
        if err:
            await respond(manager, event, f"{err}")
            return None
        if destructive:
            shield = security.guard_target(invoker, target_id)
            if shield:
                await respond(manager, event, f"{shield}")
                return None
            if target_id == manager.self_id:
                await respond(manager, event,
                              "Refused: the connected account cannot be "
                              "the target of its own moderation commands.")
                return None

    # 4 — connected account must hold the required Telegram admin right
    perms = None
    if not skip_account_check:
        perms = await manager.self_permissions(chat)
        if perms is None or not (getattr(perms, "is_admin", False)
                                 or getattr(perms, "is_creator", False)):
            await respond(manager, event,
                          "The connected account is not an administrator in "
                          "this group, so no moderation action is possible.")
            return None
    if required_right and not getattr(perms, "is_creator", False):
        if not getattr(perms, required_right, False):
            human = required_right.replace("_", " ")
            await respond(manager, event,
                          f"Missing Telegram permission: the connected "
                          f"account needs “{human}” rights to /{cmd}.")
            return None

    # 5 — target-side hierarchy: protected targets are refused up front
    if need_target and destructive and target_id is not None:
        tperms = await manager.permissions(chat, target_entity)
        if tperms is not None and getattr(tperms, "is_creator", False):
            await respond(manager, event,
                          "Telegram does not allow modifying the group "
                          "owner — command refused.")
            return None
        if tperms is not None and getattr(tperms, "is_admin", False) \
                and cmd in {"ban", "kick", "mute", "demote"}:
            if not await manager.can_modify_admin(chat):
                await respond(manager, event,
                              "The target is an administrator this account "
                              "cannot modify (Telegram admin hierarchy). "
                              "Only the group owner or their promoting admin "
                              "can change them.")
                return None

    return chat, chat_id, group, role, target_id, target_entity


def audit(manager: UserbotManager, group, invoker: int, action: str,
          target: int | None, result: str) -> None:
    manager.db.log_event(group["chat_id"] if group else None,
                         invoker, target, action, result,
                         group_title=group["title"] if group else None)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

async def dispatch(manager: UserbotManager, event, cmd: str, args: str) -> None:
    invoker = event.sender_id or 0
    db = manager.db

    # ---------------------------------------------------------------- install
    if cmd == "install":
        # /install deliberately skips the "registered group" requirement and
        # verifies account admin rights itself (the group row may not exist
        # yet — that is the whole point of the command).
        gate_result = await gate(manager, event, cmd, args,
                                 need_target=False, required_right=None,
                                 destructive=False, skip_account_check=True)
        role = db.get_admin_role(invoker)
        if not security.has_permission(role, "trust"):
            return  # untrusted invoker: total silence
        chat = await event.get_chat()
        perms = await manager.self_permissions(chat)
        if perms is None or not (getattr(perms, "is_admin", False)
                                 or getattr(perms, "is_creator", False)):
            await respond(manager, event,
                          "Install failed: the connected account is not an "
                          "administrator in this group, so protection cannot "
                          "be enabled here.")
            return
        chat_id = chat.id
        already = db.get_group(chat_id)
        db.upsert_group(chat_id, getattr(chat, "title", None),
                        added_by=invoker, enabled=True)
        audit(manager, db.get_group(chat_id), invoker, "group.install", None, "ok")
        await respond(
            manager, event,
            "Security system installed in this group. Admin-log monitoring "
            "and gmute enforcement are now active." if not already else
            "Group already installed — admin rights re-verified, protection active.")
        return

    if cmd == "uninstall":
        g = await gate(manager, event, cmd, args, need_target=False,
                       required_right=None, destructive=False)
        if g is None:
            return
        _, chat_id, group, *_ = g
        db.set_lockdown(chat_id, False)
        db.set_group_enabled(chat_id, False)
        audit(manager, group, invoker, "group.uninstall", None, "ok")
        await respond(manager, event, "Security system disabled for this group.")
        return

    # -------------------------------------------------- status (read-only)
    if cmd == "security":
        group = db.get_group(getattr((await event.get_chat()), "id", None))
        if not group or not group["enabled"]:
            return
        role = db.get_admin_role(invoker)
        if role is None:
            return
        events_rows = db.recent_events(limit=3, group_id=group["chat_id"])
        lines = [
            "Group security status",
            f"• Lockdown: {'ACTIVE' if group['lockdown'] else 'off'}",
            f"• Anti-raid thresholds: {config.BAN_LIMIT_1}/{config.BAN_WINDOW_1}s, "
            f"{config.BAN_LIMIT_2}/{config.BAN_WINDOW_2}s (bans) · "
            f"{config.DELETE_LIMIT_1}/{config.DELETE_WINDOW_1}s (deletions)",
            f"• Global mute list: {len(db.list_gmutes())} user(s)",
            f"• Your role: {role}",
            "",
            "Recent events:",
        ]
        if not events_rows:
            lines.append("• none recorded yet")
        for row in events_rows:
            lines.append(f"• [{row['action']}] target={row['target_id']} "
                         f"by admin={row['admin_id']} → {row['result']}")
        await respond(manager, event, "\n".join(lines))
        return

    # ------------------------------------------------------------- lockdown
    if cmd in {"lockdown", "unlock"}:
        g = await gate(manager, event, cmd, args, need_target=False,
                       required_right="ban_users", destructive=False)
        if g is None:
            return
        chat, chat_id, group, role, *_ = g
        if cmd == "lockdown":
            if group["lockdown"]:
                await respond(manager, event, "Lockdown is already active.")
                return
            db.set_lockdown(chat_id, True)
            audit(manager, group, invoker, "group.lockdown", None, "ok")
            note = (f"New joiners will be restricted automatically."
                    if config.LOCKDOWN_RESTRICT_NEW_MEMBERS else
                    "New joiners are NOT restricted (config).")
            await respond(manager, event,
                          f"LOCKDOWN engaged. Stricter thresholds active. {note}")
            await manager.send_owner_dm(
                f"Lockdown engaged in “{group['title']}” ({chat_id}) by "
                f"trusted admin id={invoker}.")
        else:
            if not group["lockdown"]:
                await respond(manager, event, "No lockdown is currently active.")
                return
            db.set_lockdown(chat_id, False)
            audit(manager, group, invoker, "group.unlock", None, "ok")
            await respond(manager, event, "Lockdown lifted. Normal thresholds restored.")
            await manager.send_owner_dm(
                f"Lockdown lifted in “{group['title']}” ({chat_id}).")
        return

    # --------------------------------------------------- trust management
    if cmd in {"trust", "untrust"}:
        g = await gate(manager, event, cmd, args, need_target=True,
                       required_right=None, destructive=False)
        if g is None:
            return
        chat, chat_id, group, role, target_id, target_entity = g
        tokens = args.split()
        display = display_name(target_entity, target_id)

        if cmd == "trust":
            role_arg = ""
            for tok in tokens:
                if tok.upper() in config.ROLE_ORDER and tok.upper() != config.ROLE_OWNER:
                    role_arg = tok.upper()
            if not role_arg:
                await respond(manager, event,
                              "Usage: /trust @user <MODERATOR|TRUSTED_ADMIN|SECURITY_ADMIN>")
                return
            # Nobody may grant a rank above their own (owner excepted).
            if not security.is_owner(invoker) and \
                    config.ROLE_ORDER.get(role_arg, 0) >= config.ROLE_ORDER.get(role or "", 0):
                await respond(manager, event,
                              "You can only grant roles below your own rank.")
                return
            if security.is_owner(target_id):
                await respond(manager, event,
                              "That user is the configured owner — role is fixed.")
                return
            db.set_admin_role(target_id, role_arg, added_by=invoker)
            audit(manager, group, invoker, "trust.grant", target_id, role_arg)
            await respond(manager, event, f"{display} is now {role_arg}.")
            return

        # untrust
        if security.is_owner(target_id):
            await respond(manager, event,
                          "The configured owner cannot be removed from the trust system.")
            return
        existing = db.get_admin_role(target_id)
        if existing is None:
            await respond(manager, event, "That user has no trust role.")
            return
        if not security.is_owner(invoker) and \
                config.ROLE_ORDER.get(existing, 0) >= config.ROLE_ORDER.get(role or "", 0):
            await respond(manager, event,
                          "You cannot remove someone of equal or higher rank.")
            return
        db.remove_admin(target_id)
        audit(manager, group, invoker, "trust.revoke", target_id, "ok")
        await respond(manager, event, f"{display} removed from the trust system.")
        return

    # ---------------------------------------------------------- destructive
    spec = {
        "mute":     dict(right="ban_users", label="Muted"),
        "unmute":   dict(right="ban_users", label="Unmuted"),
        "ban":      dict(right="ban_users", label="Banned"),
        "unban":    dict(right="ban_users", label="Unbanned"),
        "kick":     dict(right="ban_users", label="Kicked"),
        "promote":  dict(right="add_admins", label="Promoted"),
        "demote":   dict(right="add_admins", label="Demoted"),
        "gmute":    dict(right="ban_users", label="Globally muted"),
        "ungmute":  dict(right="ban_users", label="Global mute lifted"),
        "warn":     dict(right="ban_users", label="Warned"),
        "warnings": dict(right=None, label=""),
    }[cmd]

    destructive = cmd not in {"unban", "unmute", "ungmute", "promote", "warnings"}
    g = await gate(manager, event, cmd, args,
                   need_target=True,
                   required_right=spec["right"],
                   destructive=destructive)
    if g is None:
        return
    chat, chat_id, group, role, target_id, target_entity = g
    manager.db.remember_user(
        target_id,
        getattr(target_entity, "username", None),
        getattr(target_entity, "first_name", None),
        getattr(target_entity, "last_name", None))
    display = display_name(target_entity, target_id)

    # duration parsing only meaningful for /mute ("reply + /mute 1h" works)
    seconds: int | None = None
    if cmd == "mute":
        for tok in args.split():
            dur = parse_duration(tok)
            if dur:
                seconds = dur
                break

    # ----------------------------------------------------------------- warn
    if cmd == "warn":
        reason = " ".join(tok for tok in args.split()
                          if not tok.startswith("@") and not tok.isdigit()) or None
        count = db.add_warning(chat_id, target_id, invoker, reason)
        applied = ""
        if count >= config.WARN_LIMIT and config.WARN_ACTION != "none" \
                and not security.is_owner(target_id):
            if config.WARN_ACTION == "mute":
                res = await manager.mute_user(chat, target_entity,
                                              seconds=config.WARN_MUTE_SECONDS,
                                              desc="warn-limit mute")
                applied = (" Auto-action: muted for "
                           f"{config.WARN_MUTE_SECONDS // 60}m."
                           if res.ok else f" Auto-action failed: {res.error}")
            elif config.WARN_ACTION == "kick":
                ban = await manager.ban_user(chat, target_entity, desc="warn-limit kick")
                if ban.ok:
                    await manager.unban_user(chat, target_entity, desc="warn-limit unban")
                applied = " Auto-action: kicked." if ban.ok else f" Auto-action failed: {ban.error}"
            db.clear_warnings(chat_id, target_id)
        audit(manager, group, invoker, "warn", target_id, f"count={count}")
        await respond(manager, event,
                      f"{display} warned ({count}/{config.WARN_LIMIT})."
                      f"{f' Reason: {reason}.' if reason else ''}{applied}")
        return

    if cmd == "warnings":
        count = db.count_warnings(chat_id, target_id)
        await respond(manager, event,
                      f"{display} has {count}/{config.WARN_LIMIT} warning(s).")
        return

    # ---------------------------------------------------------------- gmute
    if cmd == "gmute":
        reason_tokens = [tok for tok in args.split()
                         if not tok.startswith("@") and not tok.isdigit()
                         and not parse_duration(tok)]
        reason = " ".join(reason_tokens) or None
        db.add_gmute(target_id, reason, added_by=invoker)
        applied, skipped = 0, 0
        for grp in db.enabled_groups():
            if not await manager.can_ban(grp["chat_id"]):
                skipped += 1
                continue
            tperms = await manager.permissions(grp["chat_id"], target_entity)
            if tperms is None:
                continue  # not currently present — restriction applies on join
            if getattr(tperms, "is_creator", False):
                skipped += 1
                continue  # never touch another group's owner
            res = await manager.gmute_restrict(grp["chat_id"], target_entity,
                                               desc="apply global mute")
            applied += 1 if res.ok else 0
            skipped += 0 if res.ok else 1
        audit(manager, group, invoker, "gmute", target_id,
              f"applied={applied} skipped={skipped}")
        await respond(manager, event,
                      f"{display} added to the global mute list. "
                      f"Restricted in {applied} configured group(s); "
                      f"restriction will apply on sight elsewhere.")
        return

    if cmd == "ungmute":
        existed = db.remove_gmute(target_id)
        lifted = 0
        for grp in db.enabled_groups():
            if not await manager.can_ban(grp["chat_id"]):
                continue
            res = await manager.unban_user(grp["chat_id"], target_entity,
                                           desc="lift global mute")
            lifted += 1 if res.ok else 0
        audit(manager, group, invoker, "ungmute", target_id,
              "ok" if existed else "not-listed")
        await respond(manager, event,
                      (f"{display} removed from the global mute list; "
                       f"restrictions lifted in {lifted} group(s).")
                      if existed else
                      f"{display} was not on the global mute list.")
        return

    # -------------------------------------------- simple moderation actions
    if cmd == "mute":
        res = await manager.mute_user(chat, target_entity, seconds=seconds,
                                      desc="command mute")
    elif cmd == "unmute":
        res = await manager.unban_user(chat, target_entity, desc="command unmute")
    elif cmd == "ban":
        res = await manager.ban_user(chat, target_entity, desc="command ban")
    elif cmd == "unban":
        res = await manager.unban_user(chat, target_entity, desc="command unban")
    elif cmd == "kick":
        ban = await manager.ban_user(chat, target_entity, desc="command kick")
        if ban.ok:
            # unban right after = removed but free to rejoin later
            res = await manager.unban_user(chat, target_entity,
                                           desc="command kick (rejoin allowed)")
        else:
            res = ban
    elif cmd == "promote":
        res = await manager.promote_user(chat, target_entity, desc="command promote")
    elif cmd == "demote":
        res = await manager.demote_user(chat, target_entity, desc="command demote")
    else:
        return

    label = spec["label"]
    if res.ok:
        suffix = f" for {seconds}s" if (cmd == "mute" and seconds) else ""
        audit(manager, group, invoker, cmd, target_id, "ok")
        await respond(manager, event, f"{label}{suffix}: {display}")
    else:
        audit(manager, group, invoker, cmd, target_id, f"failed: {res.error}")
        await respond(manager, event, f"{label} failed: {res.error}")
