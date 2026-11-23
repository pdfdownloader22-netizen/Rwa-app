import base64
import hashlib
import hmac
import json
import os
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import config


class CryptoShield:
    """
    1. Field-Level Encryption (At-Rest in MongoDB) using Fernet (AES-128-CBC + HMAC)
    2. End-to-End Transport Encryption (In-Transit) using AES-256-CBC (100% CryptoJS compatible)
    """

    def __init__(self):
        fernet_raw = hashlib.sha256(config.DB_ENC_KEY.encode("utf-8")).digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(fernet_raw))
        self.transport_key = hashlib.sha256(config.TRANSPORT_AES_KEY.encode("utf-8")).digest()

    # ---------- MONGODB FIELD-LEVEL ENCRYPTION (AT-REST) ----------
    def encrypt_field(self, value):
        if value is None:
            return ""
        s = str(value).strip()
        if not s or s == "N/A" or s.startswith("ENCv1:"):
            return s
        try:
            tok = self.fernet.encrypt(s.encode("utf-8")).decode("utf-8")
            return f"ENCv1:{tok}"
        except Exception:
            return s

    def decrypt_field(self, value):
        if value is None:
            return ""
        s = str(value).strip()
        if not s.startswith("ENCv1:"):
            return s
        try:
            raw = s[6:].encode("utf-8")
            return self.fernet.decrypt(raw).decode("utf-8")
        except (InvalidToken, Exception):
            return s

    # ---------- E2E TRANSPORT AES-256-CBC (IN-TRANSIT) ----------
    def encrypt_transport_dict(self, data_obj):
        plain_bytes = json.dumps(data_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plain_bytes) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.transport_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded) + encryptor.finalize()
        iv_b64 = base64.b64encode(iv).decode("utf-8")
        ct_b64 = base64.b64encode(ct).decode("utf-8")
        return {"enc": f"{iv_b64}:{ct_b64}", "v": 1}

    def decrypt_transport_payload(self, enc_str):
        if not enc_str or ":" not in str(enc_str):
            return None
        try:
            iv_b64, ct_b64 = str(enc_str).strip().split(":", 1)
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            cipher = Cipher(algorithms.AES(self.transport_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plain = unpadder.update(padded) + unpadder.finalize()
            return json.loads(plain.decode("utf-8"))
        except Exception:
            return None


class SecurityGuard:
    """
    Handles Strict Origin Whitelist, HMAC-SHA256 Signing, Rate Limiting,
    Admin Brute-Force Protection, Short-Lived Admin Tokens & JWT Expiry Inspection.
    """

    def __init__(self):
        self.rate_buckets = defaultdict(deque)
        self.admin_fails = defaultdict(list)
        self.admin_temp_bans = {}  # ip -> unban_ts

    def get_client_ip(self, req):
        xff = req.headers.get("X-Forwarded-For", "").strip()
        if xff:
            return xff.split(",")[0].strip()
        return (req.headers.get("X-Real-IP") or req.remote_addr or "0.0.0.0").strip()

    def parse_device_info(self, req):
        ua = (req.headers.get("User-Agent") or "").strip()
        ua_low = ua.lower()
        if "wv" in ua_low or "rwaapp" in ua_low:
            dtype = "Android App WebView"
        elif "android" in ua_low:
            dtype = "Android Mobile"
        elif "iphone" in ua_low or "ipad" in ua_low:
            dtype = "iOS Mobile"
        elif "windows" in ua_low:
            dtype = "Windows PC"
        elif "macintosh" in ua_low:
            dtype = "Mac PC"
        else:
            dtype = "Web Browser"
        return {
            "ip": self.get_client_ip(req),
            "device_type": dtype,
            "user_agent": ua[:180],
            "device_id": (req.headers.get("X-RWA-Device") or "")[:64]
        }

    # ---------- STRICT DOMAIN WHITELIST ----------
    def extract_request_origin(self, req):
        origin = (req.headers.get("Origin") or "").strip().rstrip("/").lower()
        if origin and origin != "null":
            return origin
        referer = (req.headers.get("Referer") or "").strip()
        if referer:
            try:
                p = urlparse(referer)
                if p.scheme and p.netloc:
                    return f"{p.scheme}://{p.netloc}".lower()
            except Exception:
                pass
        return ""

    def is_origin_allowed(self, req):
        if not config.STRICT_SECURITY_ENABLED:
            return True
        origin = self.extract_request_origin(req)
        if not origin:
            # Companion Android WebView / local file requests must still pass valid HMAC
            if req.headers.get("X-RWA-App") == "RWA-WEBVIEW":
                return True
            return False
        return origin in config.ALLOWED_ORIGINS

    # ---------- DYNAMIC HMAC-SHA256 SIGNATURE ----------
    def verify_hmac_signature(self, req, raw_body_str=""):
        if not config.STRICT_SECURITY_ENABLED:
            return True, "ok"
        ts_str = (req.headers.get("X-RWA-Ts") or "").strip()
        sig = (req.headers.get("X-RWA-Sign") or "").strip().lower()
        if not ts_str or not sig:
            return False, "Missing security signature"
        try:
            req_ts = int(ts_str)
        except ValueError:
            return False, "Invalid timestamp"

        now_ts = int(time.time())
        if abs(now_ts - req_ts) > config.SIGNATURE_MAX_DRIFT_SEC:
            return False, "Request expired (clock skew or replay)"

        msg = f"{req.method.upper()}:{req.path}:{ts_str}:{raw_body_str}"
        expected = hmac.new(
            config.API_SIGNING_SECRET.encode("utf-8"),
            msg.encode("utf-8"),
            hashlib.sha256
        ).hexdigest().lower()

        if not hmac.compare_digest(expected, sig):
            return False, "Invalid HMAC signature"
        return True, "ok"

    # ---------- PER-IP RATE LIMITER ----------
    def check_rate_limit(self, ip, bucket="general", max_req=75, window_sec=60):
        key = f"{bucket}:{ip}"
        now = time.time()
        dq = self.rate_buckets[key]
        while dq and (now - dq[0]) > window_sec:
            dq.popleft()
        if len(dq) >= max_req:
            return False
        dq.append(now)
        return True

    # ---------- ADMIN BRUTE-FORCE AUTO-BAN ----------
    def is_admin_bruteforce_banned(self, ip):
        unban_ts = self.admin_temp_bans.get(ip, 0)
        if unban_ts > time.time():
            return True, int(unban_ts - time.time())
        if ip in self.admin_temp_bans:
            del self.admin_temp_bans[ip]
        return False, 0

    def record_admin_fail(self, ip):
        now = time.time()
        fails = [t for t in self.admin_fails[ip] if (now - t) < 900]
        fails.append(now)
        self.admin_fails[ip] = fails
        if len(fails) >= config.ADMIN_MAX_FAILS:
            self.admin_temp_bans[ip] = now + config.ADMIN_BAN_SECONDS
            self.admin_fails[ip] = []
            return True
        return False

    def clear_admin_fails(self, ip):
        self.admin_fails.pop(ip, None)

    # ---------- SHORT-LIVED SIGNED ADMIN SESSION TOKEN ----------
    def issue_admin_session_token(self, ip):
        exp = int(time.time()) + config.ADMIN_SESSION_TTL_SEC
        payload = f"rwa_admin:{exp}:{ip}"
        sig = hmac.new(
            (config.ADMIN_PANEL_KEY + config.API_SIGNING_SECRET).encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        raw = f"{payload}:{sig}".encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("utf-8"), exp

    def verify_admin_session_token(self, token_b64):
        if not token_b64:
            return False
        try:
            decoded = base64.urlsafe_b64decode(token_b64.encode("utf-8")).decode("utf-8")
            parts = decoded.split(":")
            if len(parts) != 4 or parts[0] != "rwa_admin":
                return False
            exp = int(parts[1])
            ip = parts[2]
            sig = parts[3]
            if time.time() > exp:
                return False
            payload = f"rwa_admin:{exp}:{ip}"
            expected = hmac.new(
                (config.ADMIN_PANEL_KEY + config.API_SIGNING_SECRET).encode("utf-8"),
                payload.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, sig)
        except Exception:
            return False

    # ---------- JWT EXPIRY INSPECTOR (DEAD CLOUD TOKEN SCANNER) ----------
    @staticmethod
    def is_jwt_expired(jwt_str, grace_seconds=30):
        if not jwt_str or "." not in str(jwt_str):
            return True
        try:
            parts = str(jwt_str).strip().split(".")
            if len(parts) < 2:
                return True
            b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))
            exp = payload.get("exp")
            if exp is None:
                return False
            return time.time() > (int(exp) - grace_seconds)
        except Exception:
            return True


crypto_shield = CryptoShield()
security_guard = SecurityGuard()
