import threading
import time
from datetime import datetime, timezone, timedelta
import requests
from waitress import serve

import config
from api_server import app, notify_callbacks
from db_manager import db_manager
from vault_manager import vault_manager

IST = timezone(timedelta(hours=5, minutes=30))


def send_telegram_admin_message(text):
    if not config.BOT_TOKEN or not config.ADMIN_IDS:
        return
    url = f"https://api.telegram.org/bot{config.BOT_TOKEN}/sendMessage"
    for aid in config.ADMIN_IDS:
        try:
            requests.post(
                url,
                json={"chat_id": aid, "text": text, "parse_mode": "HTML"},
                timeout=10
            )
        except Exception:
            pass


def start_nightly_digest_scheduler():
    """Roz raat 11:00 PM IST par Telegram par full cluster + Content Vault summary bhejta hai."""
    last_sent_date = None

    def _loop():
        nonlocal last_sent_date
        while True:
            try:
                now_ist = datetime.now(IST)
                today_str = now_ist.strftime("%Y-%m-%d")
                if now_ist.hour == config.NIGHTLY_DIGEST_HOUR_IST and last_sent_date != today_str:
                    last_sent_date = today_str
                    st = db_manager.get_cluster_stats()
                    vs = vault_manager.get_vault_summary()
                    shard_lines = "\n".join([
                        f"  • {s['label']}: {s.get('size_mb', 0)} MB ({s.get('users', 0)} Users)"
                        for s in (st.get("per_db") or [])
                    ]) or "  • No User DBs"
                    vshard_lines = "\n".join([
                        f"  • {s['label']}: {s.get('size_mb', 0)} MB ({s.get('full_banks', 0)} Tests)"
                        for s in (vs.get("per_shard") or [])
                    ]) or "  • Fallback Mode"

                    msg = (
                        f"<b>🌙 RWA NIGHTLY DIGEST ({today_str})</b>\n"
                        f"━━━━━━━━━━━━━━━━━━━━━━\n"
                        f"👥 <b>Total Users:</b> {st.get('total_users', 0)}\n"
                        f"🔥 <b>Active Today:</b> {st.get('active_today', 0)}\n"
                        f"📝 <b>Total Tests Given:</b> {st.get('total_tests', 0)}\n"
                        f"🚩 <b>Open Reports:</b> {st.get('open_reports', 0)}\n"
                        f"🔑 <b>Cloud Tokens:</b> {st.get('total_admin_tokens', 0)}\n\n"
                        f"☁️ <b>CONTENT CLOUD VAULT</b>\n"
                        f"  • Series Saved: <b>{vs.get('total_series', 0)}</b>\n"
                        f"  • Folders Saved: <b>{vs.get('total_folders', 0)}</b>\n"
                        f"  • Tests Listed: <b>{vs.get('total_listed_tests', 0)}</b>\n"
                        f"  • Full Q-Banks: <b>{vs.get('total_full_banks', 0)}</b> ({vs.get('total_questions_archived', 0)} Qs)\n\n"
                        f"🗄️ <b>User DB Shards ({st.get('connected_dbs', 0)}):</b>\n{shard_lines}\n\n"
                        f"📦 <b>Vault DB Shards ({vs.get('connected_vault_dbs', 0)}):</b>\n{vshard_lines}"
                    )
                    send_telegram_admin_message(msg)
            except Exception as e:
                print(f"⚠️ Nightly digest error: {e}")
            time.sleep(60)

    threading.Thread(target=_loop, daemon=True).start()


def boot_optional_telegram_bot():
    """Agar bot.py repo mein hai toh usko safely background thread mein start karta hai."""
    notify_callbacks["on_security_alert"] = lambda msg: send_telegram_admin_message(f"🛡️ <b>SECURITY ALERT</b>\n{msg}")
    try:
        import bot  # noqa: F401
        if hasattr(bot, "start_bot_polling"):
            threading.Thread(target=bot.start_bot_polling, daemon=True).start()
            print("✅ Telegram Bot polling started in background")
        elif hasattr(bot, "bot"):
            def _poll():
                while True:
                    try:
                        bot.bot.infinity_polling(timeout=30, long_polling_timeout=25)
                    except Exception as e:
                        print(f"⚠️ Bot polling retry: {e}")
                        time.sleep(5)
            threading.Thread(target=_poll, daemon=True).start()
            print("✅ Telegram Bot infinity_polling started in background")
    except ImportError:
        print("ℹ️ bot.py not present; running pure API + Telegram HTTP alerts mode.")
    except Exception as e:
        print(f"⚠️ Optional bot startup warning: {e}")


if __name__ == "__main__":
    # Fallback attach if user hasn't set dedicated CONTENT_MONGO_URI yet
    vault_manager.attach_fallback_dbs(db_manager.dbs)

    boot_optional_telegram_bot()
    start_nightly_digest_scheduler()

    print(
        f"🚀 Starting RWA Ultra High-Traffic Server on port {config.PORT} "
        f"(threads={config.WAITRESS_THREADS}, user_dbs={len(db_manager.dbs)}, vault_dbs={len(vault_manager.dbs)})"
    )
    serve(
        app,
        host="0.0.0.0",
        port=config.PORT,
        threads=config.WAITRESS_THREADS,
        connection_limit=500,
        channel_timeout=60
    )
