import os

# =========================================================
# TELEGRAM BOT & ADMIN CONFIG
# =========================================================
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = [
    int(x.strip())
    for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().lstrip("-").isdigit()
]
ADMIN_PANEL_KEY = os.getenv("ADMIN_PANEL_KEY", "RWA_MASTER_ADMIN_2026").strip()

# =========================================================
# 4-MONGODB AUTO-SHARDING CLUSTER
# =========================================================
DB_NAME = os.getenv("DB_NAME", "rwa_sky_pro_db").strip()
MAX_DB_SIZE_MB = float(os.getenv("MAX_DB_SIZE_MB", "420"))

MONGO_URIS = [
    (os.getenv("MONGO_URI_1") or os.getenv("MONGO_URI") or os.getenv("MONGODB_URI") or "").strip(),
    os.getenv("MONGO_URI_2", "").strip(),
    os.getenv("MONGO_URI_3", "").strip(),
    os.getenv("MONGO_URI_4", "").strip(),
]

# =========================================================
# 3-LAYER ULTRA SECURITY SHIELD CONFIG
# Render Environment mein yeh secrets zaroor set karein
# =========================================================
# Sirf inhi websites & admin panel ko server reply dega (comma-separated)
DEFAULT_ALLOWED_ORIGINS = ",".join([
    "https://pdfdownloader22-netizen.github.io",
    "https://rwawebportal-alt.github.io",
    "http://localhost:5500",
    "http://127.0.0.1:5500"
])

ALLOWED_ORIGINS = [
    o.strip().rstrip("/").lower()
    for o in os.getenv("ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS).split(",")
    if o.strip()
]

# Frontend (rwa-security.js) aur Backend dono mein EXACT same keys rahengi
API_SIGNING_SECRET = os.getenv("API_SIGNING_SECRET", "RWA_HMAC_SHIELD_2026_ULTRA_KEY_99").strip()
TRANSPORT_AES_KEY = os.getenv("TRANSPORT_AES_KEY", "RWA_E2E_AES256_TUNNEL_2026_KEY_77").strip()

# Sirf Render Backend par rahegi — MongoDB ke sensitive fields encrypt karne ke liye
DB_ENC_KEY = os.getenv("DB_ENC_KEY", "RWA_MONGO_AT_REST_FERNET_2026_KEY_55").strip()

# Security Limits
SIGNATURE_MAX_DRIFT_SEC = int(os.getenv("SIGNATURE_MAX_DRIFT_SEC", "90"))
ADMIN_SESSION_TTL_SEC = int(os.getenv("ADMIN_SESSION_TTL_SEC", "21600"))  # 6 hours
ADMIN_MAX_FAILS = 5
ADMIN_BAN_SECONDS = 1800  # 30 minutes
STRICT_SECURITY_ENABLED = os.getenv("STRICT_SECURITY_ENABLED", "1").strip() == "1"

# Diagnostics Targets
WORKER_PROXY_HEALTH_URL = os.getenv("WORKER_PROXY_HEALTH_URL", "https://test.src22420.workers.dev/").strip()
RWA_UPSTREAM_API_URL = os.getenv("RWA_UPSTREAM_API_URL", "https://rozgarapinew.teachx.in").strip()

PORT = int(os.getenv("PORT", "10000"))
