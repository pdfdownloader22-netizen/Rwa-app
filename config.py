import os
import re


def _collect_dynamic_mongo_uris(single_names, indexed_prefixes, list_env_name):
    """
    Dynamically collects unlimited MongoDB URIs from Render Environment Variables.
    Supports MONGO_URI_1..N, CONTENT_MONGO_URI_1..N, or comma/newline lists.
    """
    uris = []
    seen = set()

    def _add(raw_val):
        if not raw_val:
            return
        for part in re.split(r"[\n,]+", str(raw_val)):
            u = part.strip().strip('"').strip("'")
            if u and u not in seen and (u.startswith("mongodb://") or u.startswith("mongodb+srv://")):
                seen.add(u)
                uris.append(u)

    if list_env_name:
        _add(os.getenv(list_env_name, ""))

    indexed_matches = []
    for k, v in os.environ.items():
        if not v or not str(v).strip():
            continue
        for pref in indexed_prefixes:
            m = re.match(rf"^{re.escape(pref)}(\d+)$", k.strip(), re.IGNORECASE)
            if m:
                indexed_matches.append((int(m.group(1)), k, v))
                break

    indexed_matches.sort(key=lambda item: item[0])
    for _, _, v in indexed_matches:
        _add(v)

    for sk in single_names:
        _add(os.getenv(sk, ""))

    return uris


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
# UNLIMITED USER MONGODB AUTO-SHARDING CLUSTER
# =========================================================
DB_NAME = os.getenv("DB_NAME", "rwa_sky_pro_db").strip()
MAX_DB_SIZE_MB = float(os.getenv("MAX_DB_SIZE_MB", "420"))

MONGO_URIS = _collect_dynamic_mongo_uris(
    single_names=["MONGO_URI", "MONGODB_URI"],
    indexed_prefixes=["MONGO_URI_", "MONGODB_URI_"],
    list_env_name="MONGO_URIS"
)

# =========================================================
# UNLIMITED DEDICATED CONTENT VAULT MONGODB CLUSTER
# Hard cap at 450 MB per MongoDB shard!
# =========================================================
CONTENT_DB_NAME = os.getenv("CONTENT_DB_NAME", "rwa_content_vault_db").strip()
MAX_CONTENT_DB_SIZE_MB = float(os.getenv("MAX_CONTENT_DB_SIZE_MB", "450"))

CONTENT_MONGO_URIS = _collect_dynamic_mongo_uris(
    single_names=["CONTENT_MONGO_URI", "VAULT_MONGO_URI"],
    indexed_prefixes=["CONTENT_MONGO_URI_", "VAULT_MONGO_URI_"],
    list_env_name="CONTENT_MONGO_URIS"
)

# =========================================================
# 3-LAYER ULTRA SECURITY SHIELD CONFIG
# =========================================================
DEFAULT_ALLOWED_ORIGINS = ",".join([
    "https://pdfdownloader22-netizen.github.io",
    "https://rwawebportal-alt.github.io",
    "http://localhost:5500",
    "http://127.0.0.1:5500"
])

ALLOWED_ORIGINS = [
    o.strip().strip('"').strip("'").rstrip("/").lower()
    for o in os.getenv("ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS).split(",")
    if o.strip().strip('"').strip("'")
]

API_SIGNING_SECRET = os.getenv("API_SIGNING_SECRET", "RWA_HMAC_SHIELD_2026_ULTRA_KEY_99").strip()
TRANSPORT_AES_KEY = os.getenv("TRANSPORT_AES_KEY", "RWA_E2E_AES256_TUNNEL_2026_KEY_77").strip()
DB_ENC_KEY = os.getenv("DB_ENC_KEY", "RWA_MONGO_AT_REST_FERNET_2026_KEY_55").strip()

# Security & Performance Limits
SIGNATURE_MAX_DRIFT_SEC = int(os.getenv("SIGNATURE_MAX_DRIFT_SEC", "90"))
ADMIN_SESSION_TTL_SEC = int(os.getenv("ADMIN_SESSION_TTL_SEC", "21600"))
ADMIN_MAX_FAILS = 5
ADMIN_BAN_SECONDS = 1800
STRICT_SECURITY_ENABLED = os.getenv("STRICT_SECURITY_ENABLED", "1").strip() == "1"

# High-Traffic Server & Nightly Auto-Scan Schedule (11:00 PM - 12:00 AM IST)
WAITRESS_THREADS = int(os.getenv("WAITRESS_THREADS", "16"))
NIGHTLY_SCAN_START_HOUR_IST = int(os.getenv("NIGHTLY_SCAN_START_HOUR_IST", "23"))  # 11:00 PM IST
NIGHTLY_SCAN_END_HOUR_IST = int(os.getenv("NIGHTLY_SCAN_END_HOUR_IST", "0"))       # 12:00 AM IST
NIGHTLY_DIGEST_HOUR_IST = int(os.getenv("NIGHTLY_DIGEST_HOUR_IST", "23"))

# Upstream & Proxy Targets
WORKER_PROXY_HEALTH_URL = os.getenv("WORKER_PROXY_HEALTH_URL", "https://test.src22420.workers.dev/").strip()
WORKER_RAW_PROXY_URL = os.getenv("WORKER_RAW_PROXY_URL", "https://proplayer.allswbatch22.workers.dev/proxy?url=").strip()
RWA_UPSTREAM_API_URL = os.getenv("RWA_UPSTREAM_API_URL", "https://rozgarapinew.teachx.in").strip()

PORT = int(os.getenv("PORT", "10000"))
