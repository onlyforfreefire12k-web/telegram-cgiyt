# Telegram Security Userbot

A production-ready **group security / moderation** system for Telegram,
built with Python 3.12, Telethon (MTProto), Flask and SQLite.

It lets a group owner connect their own Telegram account through a private
management bot, then continuously guards their groups against **rogue
administrators** (mass bans / mass deletions), enforces a **global mute
list**, supports a **trust-role hierarchy**, an **emergency lockdown**, and
keeps a **complete audit log** — while strictly respecting Telegram's
permission hierarchy.

> This is a **defensive** moderation tool. It contains **no** spam, mass
> messaging, flooding, raid or invitation automation, and it never acts
> outside groups where the connected account is a legitimate administrator.

---

## 1. Project tree

```
project/
├── bot.py              # Owner-facing management bot (+ secure /login flow)
├── userbot.py          # MTProto worker: monitoring, enforcement, protection
├── security.py         # Session encryption, thresholds, roles, alert format
├── admin_commands.py   # In-group moderation commands with permission gates
├── database.py         # SQLite layer (users/sessions/groups/admins/…)
├── config.py           # Env-driven configuration (no hardcoded secrets)
├── live.py             # Flask health server + worker supervisor (entrypoint)
├── requirements.txt
└── README.md
```

## 2. Requirements

* Python **3.12+**
* A Telegram account with **2FA recommended**, **API_ID / API_HASH**,
  a **bot token**, and your **numeric user id**

## 3. Getting API credentials (api_id / api_hash)

1. Open <https://my.telegram.org> and sign in with your phone number.
2. Choose **API development tools**.
3. Create an application (any name, e.g. `security-userbot`).
4. Copy the shown **api_id** (number) and **api_hash** (hex string).
5. Keep the api_hash secret — treat it like a password.

## 4. Creating the management bot

1. Open **@BotFather** in Telegram → `/newbot`.
2. Choose a name and username → copy the **bot token** (`123456:ABC…`).
3. (Recommended) `/setprivacy` → **Disable** is NOT needed; the bot only
   talks with you privately. No group membership required.
4. Start a chat with your new bot and press **Start**.

Your **OWNER_ID**: send any message to **@userinfobot** and copy the `Id`
number (digits only).

## 5. Environment variables

| Variable | Required | Description |
|---|---|---|
| `API_ID` | yes | from my.telegram.org |
| `API_HASH` | yes | from my.telegram.org |
| `BOT_TOKEN` | yes | from @BotFather |
| `OWNER_ID` | yes | your numeric Telegram user id |
| `SESSION_SECRET` | recommended | Fernet key for session encryption. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. If unset, a local key file is generated (sessions won't survive container wipes). |
| `PORT` | auto on Render | Flask bind port (default 10000) |
| `DATABASE_PATH` / `DATABASE_URL` | no | SQLite location (`sqlite:///path.db` also accepted) |
| `BAN_LIMIT_1` / `BAN_WINDOW_1` | no | default `5` bans / `60`s |
| `BAN_LIMIT_2` / `BAN_WINDOW_2` | no | default `15` bans / `300`s |
| `DELETE_LIMIT_1/2`, `DELETE_WINDOW_1/2` | no | mass-delete thresholds |
| `AUTO_DEMOTE_ON_MASS_BAN` | no | `1` (default) / `0` |
| `AUTO_BAN_ON_MASS_BAN` | no | `0` (default) / `1` |
| `AUTO_DEMOTE_ON_MASS_DELETE` | no | `0` (default) / `1` |
| `AUTO_LOCKDOWN_ON_MASS_BAN` | no | `0` (default) / `1` |
| `LOCKDOWN_RESTRICT_NEW_MEMBERS` | no | `1` (default) / `0` |
| `ADMIN_LOG_POLL_INTERVAL` | no | seconds, default `10` |
| `WARN_LIMIT`, `WARN_ACTION`, `WARN_MUTE_SECONDS` | no | warning escalation |
| `ALERT_TZ` | no | alert timestamp timezone (default `Asia/Kolkata`) |

Secrets never go into code or git — environment variables only.

## 6. Render deployment (exact steps)

1. Push this project to a **private** GitHub/GitLab repository.
2. Render dashboard → **New → Web Service** → connect the repo.
3. Settings:
   * **Runtime:** Python 3
   * **Build Command:** `pip install -r requirements.txt`
   * **Start Command:** `python live.py`
   * **Instance type:** Free is fine.
4. **Environment → Add Environment Variable**: add everything from section 5
   (`API_ID`, `API_HASH`, `BOT_TOKEN`, `OWNER_ID`, `SESSION_SECRET`, …).
5. (Recommended) **Disks → Add Disk** (≥1 GB) mounted at `/opt/render/project/src/data`
   so `data/security.db` and `data/security.log` survive redeploys. If you
   skip the disk, set `SESSION_SECRET` explicitly (mandatory then) and note
   the SQLite audit history resets on each deploy.
6. Deploy. Watch logs for
   `Flask health server listening on 0.0.0.0:10000`.
7. Verify: open `https://<your-service>.onrender.com/` →
   `Security Userbot Online`, and `/health` → JSON status.
8. Open Telegram → your management bot → `/login` and complete the flow.

Render free instances sleep on inactivity; HTTP hits and the internal
workers count as activity for this architecture.

## 7. Connecting your account (login flow)

In the private chat with your management bot:

```
/login
→ bot: Step 1/3 — send your phone number (+15551234567)
→ bot: Step 2/3 — send the Telegram sign-in code
→ bot: Step 3/3 — (only if 2FA is on) send your cloud password
→ bot: Login successful — Account: @you (123456789) · worker online
```

Security properties of this flow:

* your phone/code/password messages are **deleted immediately** after read;
* code & password exist only as local variables during one `sign_in` call;
* the MTProto session string is exported once, **encrypted with Fernet**,
  and written to SQLite — it is **never** shown in chat or logs;
* only the account whose id equals `OWNER_ID` may connect — any other
  account's session is **discarded instantly**;
* `/logout` calls `auth.logOut` (**server-side revocation**, visible in
  Telegram → Settings → Devices) and deletes the local encrypted copy.

## 8. Group permission requirements

Add your **account** (the one you connect via /login) as a **group
administrator** with:

| Capability | Required Telegram right |
|---|---|
| mute / unmute / ban / unban / kick / gmute enforcement | **Ban users** |
| promote / demote | **Add new admins** (Telegram additionally requires you to outrank or have promoted the target) |
| read admin audit log (rogue-admin detection) | any admin role (“Remain anonymous” optional) |
| delete messages of gmuted users | **Delete messages** recommended |

Grant the rights honestly via Telegram's admin settings — the system
verifies them at runtime and **refuses with a clear error** when a right
is missing. It never tries to bypass Telegram's permission model.

In each guarded group, either wait for the automatic scan (`/rescan` or
restart) or type `/install` in the group.

## 9. Commands

### Management bot (private chat, owner only)

| Command | Effect |
|---|---|
| `/login` | start MTProto authorization flow |
| `/logout` | revoke session server-side + delete locally |
| `/session` | connection & worker status (no credentials) |
| `/security` | thresholds, toggles, recent security events |
| `/groups` | monitored groups + lockdown state |
| `/rescan` | re-discover admin groups |
| `/cancel` | abort an in-progress login |

### In-group commands (trusted roles; reply to a user **or** pass @username/ID)

| Command | Min role | Effect |
|---|---|---|
| `/mute [duration]` / `/unmute` | MODERATOR | restrict sending (e.g. `/mute 30m`, permanent if omitted) |
| `/warn [reason]` / `/warnings` | MODERATOR | strike tracking, auto-action at `WARN_LIMIT` |
| `/ban` / `/unban` / `/kick` | TRUSTED_ADMIN | group ban / lift / remove-but-rejoinable |
| `/promote` / `/demote` | SECURITY_ADMIN | change Telegram admin status (hierarchy-checked) |
| `/gmute` / `/ungmute` | SECURITY_ADMIN | global mute list (applies in every configured group, on sight) |
| `/lockdown` / `/unlock` | SECURITY_ADMIN | emergency mode: stricter thresholds + new-member restriction |
| `/trust @user ROLE` / `/untrust @user` | SECURITY_ADMIN | manage trust roles (cannot outrank yourself) |
| `/install` / `/uninstall` | SECURITY_ADMIN | enable/disable protection for this group |
| `/security` | any trusted | per-group status |

The **owner** (typing from the connected account itself) implicitly holds
every permission; the owner can **never** be the target of a destructive
command — attempts are refused before any API call.

## 10. Test checklist

1. `python live.py` locally → `GET /health` returns `"status": "ok"`.
2. Bot `/login` → completes; `/session` shows masked phone; **no** codes
   or session strings appear in `data/security.log` (grep for your code to
   confirm absence).
3. In a test group (account is admin): reply to a member → `/mute`
   → member cannot send; `/unmute` restores.
4. `/trust @friend MODERATOR` → friend can `/mute`; cannot `/ban`.
5. Have a second admin ban 5 test members within 60 s → owner receives a
   `SECURITY ALERT` DM; if `AUTO_DEMOTE_ON_MASS_BAN=1` and hierarchy
   permits, the rogue admin is demoted; event appears under `/security`.
6. `/gmute @spammer` → user restricted in all configured groups where you
   hold ban rights; re-joining later re-applies automatically. `/ungmute`
   lifts.
7. `/lockdown` → new joiners are restricted; `/unlock` restores.
8. `/logout` → session disappears from Telegram → Settings → Devices.
9. Ask a **non-admin** member to try `/ban` → complete silence (no leak).
10. Try `/ban` on the owner yourself → refused with the owner-shield message.

## 11. Security notes — what the userbot can and cannot do

Telegram's admin hierarchy is enforced by Telegram itself; this system adds
honest pre-checks and never attempts circumvention.

**It can**

* moderate members/messages only in groups where the connected account is a
  legitimate admin with the matching right;
* demote **only** administrators the connected account is allowed to modify
  (creator can modify anyone; an admin with *Add admins* can typically
  modify only admins they promoted — Telegram decides, we respect it);
* read the admin audit log of those groups and alert the owner;
* restrict globally-muted users **on sight** in configured groups.

**It cannot**

* ban/demote the group **owner** or the configured **system owner**;
* modify admins promoted by the group owner when the connected account is
  not itself the owner (Telegram blocks it — the alert will say
  *“protection unavailable”* honestly instead of pretending);
* act in groups where the account has no admin rights — commands are
  refused with a clear error;
* bypass rate limits — FloodWait is honored, not fought;
* send messages on your behalf to users/groups (no DM automation, no
  announcements). Owner notifications always come from the **bot**.

**Never logged or displayed:** verification codes, 2FA passwords, session
strings, api_hash, bot token. Logs live in `data/security.log`; audit rows
in the `security_events` table; both contain ids, actions and timestamps
only.

**Responsible use:** run this on your own account, only in groups you
administer, and comply with Telegram's Terms of Service. Aggressive or
abusive automation of user accounts (spam, scraping, raids) violates
Telegram's ToS and is exactly what this project refuses to implement.
