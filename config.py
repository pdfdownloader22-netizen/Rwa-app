import os

# Telegram Bot & Admin Config
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ADMIN_IDS = [
    int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
]
LOG_CHANNEL_ID = os.getenv("LOG_CHANNEL_ID", "")  # Optional: e.g. -1001234567890

# Web Admin Panel Login Password (Render Env Var mein set karein)
ADMIN_PANEL_KEY = os.getenv("ADMIN_PANEL_KEY", "RWA@2026")

# 4 MongoDB Accounts (Empty URIs automatically skip ho jayenge)
MONGO_URIS = [
    os.getenv("MONGO_URI_1", "").strip(),
    os.getenv("MONGO_URI_2", "").strip(),
    os.getenv("MONGO_URI_3", "").strip(),
    os.getenv("MONGO_URI_4", "").strip(),
]

# Database Name & Storage Threshold (in MB per 512MB Atlas Free Tier)
DB_NAME = os.getenv("DB_NAME", "rwa_sky_pro_db")
MAX_DB_SIZE_MB = float(os.getenv("MAX_DB_SIZE_MB", "420"))

# Server Config
PORT = int(os.getenv("PORT", "10000"))
