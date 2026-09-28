"""
live.py — production entrypoint (`python live.py`, Render-compatible).

Responsibilities
----------------
* serve the Flask health endpoints on 0.0.0.0:$PORT  (GET /, GET /health);
* run the management bot worker (bot.py);
* run the userbot/security worker (userbot.py) when a session exists;
* keep everything alive in ONE process: Flask runs in a daemon thread,
  the asyncio/Telethon workers run on the main thread's event loop.

No gunicorn — this file is deliberately self-contained.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import threading
import time

from flask import Flask, jsonify

import config


# ---------------------------------------------------------------------------
# Logging — configured before anything else. Nothing secret is ever logged:
# no codes, no passwords, no session strings, no API hash (security.redact
# scrubs error text as defence-in-depth).
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    os.makedirs(os.path.dirname(os.path.abspath(config.LOG_FILE)), exist_ok=True)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s :: %(message)s")
    root = logging.getLogger()
    root.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))

    stdout = logging.StreamHandler()
    stdout.setFormatter(fmt)
    root.addHandler(stdout)

    try:
        file_handler = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError:
        # Read-only filesystems (some container tiers) must not kill the app.
        root.warning("Log file %s unavailable; continuing with stdout only.",
                     config.LOG_FILE)

    # Telethon/network stacks are noisy at INFO.
    logging.getLogger("telethon").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Shared runtime status (written by workers, read by the Flask thread)
# ---------------------------------------------------------------------------

STATUS: dict = {
    "started_at": int(time.time()),
    "bot": False,
    "userbot": False,
    "userbot_account": None,
}


# ---------------------------------------------------------------------------
# Flask health server
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():  # plain health text, per spec
        return "Security Userbot Online", 200, {"Content-Type": "text/plain"}

    @app.get("/health")
    def health():
        from database import db  # local import: DB ready after main() init
        uptime = int(time.time()) - int(STATUS["started_at"])
        payload = {
            "status": "ok",
            "uptime_seconds": uptime,
            "bot_worker": bool(STATUS["bot"]),
            "userbot_worker": bool(STATUS["userbot"]),
            "userbot_account": STATUS["userbot_account"],
            "monitored_groups": len(db.enabled_groups()),
            "lockdown_groups": len(db.locked_groups()),
            "global_mutes": len(db.list_gmutes()),
            "events_last_24h": db.count_events_since(int(time.time()) - 86400),
            "time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        }
        return jsonify(payload), 200

    return app


def run_flask(app: Flask) -> None:
    # Threaded mode is required: the health thread serves requests while the
    # main thread drives the asyncio Telegram workers.
    app.run(host=config.HOST, port=config.PORT, threaded=True,
            use_reloader=False)


# ---------------------------------------------------------------------------
# Async workers (management bot + userbot)
# ---------------------------------------------------------------------------

async def workers() -> None:
    # Local imports keep module import side-effect-light for tooling/tests.
    from database import db
    from security import SessionCipher
    from userbot import UserbotManager
    from bot import ManagementBot

    cipher = SessionCipher()

    # notifier is bound after the bot starts; until then messages go to logs
    notification_queue: asyncio.Queue[str] = asyncio.Queue()

    async def notifier(text: str) -> None:
        await notification_queue.put(text)

    userbot = UserbotManager(db, cipher, notifier, STATUS)
    mgmt = ManagementBot(db, cipher, userbot, STATUS)

    # Real notifier once the bot is online (flush queue in order).
    async def notifier_pump() -> None:
        while True:
            text = await notification_queue.get()
            await mgmt.notify_owner(text)

    await mgmt.start()
    pump = asyncio.create_task(notifier_pump(), name="notify-pump")

    # Auto-resume a previously stored (encrypted) session.
    row = db.get_session(config.OWNER_ID) or db.get_any_active_session()
    if row:
        ok, err = await userbot.start(int(row["user_id"]))
        if ok:
            await mgmt.notify_owner(
                "Security worker restarted automatically with the stored "
                f"(encrypted) session. Monitoring "
                f"{len(db.enabled_groups())} group(s).")
        else:
            await mgmt.notify_owner(f"Stored session could not be resumed: {err}")
    else:
        await mgmt.notify_owner(
            "Security Userbot online. No account connected yet — use /login.")

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass  # Windows: KeyboardInterrupt path below still applies

    await stop_event.wait()

    logging.getLogger("live").info("Shutdown signal received — stopping.")
    pump.cancel()
    await userbot.stop(revoke=False)   # session persists for next boot
    await mgmt.stop()


def main() -> None:
    setup_logging()
    log = logging.getLogger("live")

    problems = config.validate(strict=True)
    if problems:
        log.warning("Configuration incomplete — health server will run, "
                    "but Telegram workers refuse to start.")

    # Database first (schema bootstrap), then the web thread.
    import database  # noqa: F401  (instantiates + migrates on import)
    app = create_app()
    web = threading.Thread(target=run_flask, args=(app,),
                           name="flask-health", daemon=True)
    web.start()
    log.info("Flask health server listening on %s:%s", config.HOST, config.PORT)

    if problems:
        # Nothing else we can do safely without credentials; keep the
        # health endpoint alive so Render doesn't restart-loop the service.
        web.join()
        return

    try:
        asyncio.run(workers())
    except KeyboardInterrupt:
        pass
    log.info("live.py exiting.")


if __name__ == "__main__":
    main()
