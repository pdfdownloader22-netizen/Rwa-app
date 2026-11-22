import time
import threading
from waitress import serve
import config
from api_server import app
from bot_handlers import bot


def run_telegram_bot():
    if not config.BOT_TOKEN:
        print("⚠️ BOT_TOKEN not set. Running API server only.")
        return

    print("🤖 Starting Telegram Admin Bot Polling...")
    while True:
        try:
            bot.remove_webhook()
            bot.infinity_polling(timeout=30, long_polling_timeout=25, skip_pending=True)
        except Exception as e:
            print(f"⚠️ Bot polling error (retrying in 5s): {e}")
            time.sleep(5)


if __name__ == "__main__":
    # Start Telegram Bot in background thread
    bot_thread = threading.Thread(target=run_telegram_bot, daemon=True)
    bot_thread.start()

    # Start Production HTTP API Server on Render PORT
    print(f"🚀 RWA Sky Pro Backend running on port {config.PORT}...")
    serve(app, host="0.0.0.0", port=config.PORT, threads=8)
