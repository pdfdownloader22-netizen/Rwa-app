import threading
import traceback
from functools import wraps
from flask import Flask, request, jsonify, g, make_response
import config
from db_manager import db_manager
from security_shield import crypto_shield, security_guard
from vault_manager import ram_cache, vault_manager

app = Flask(__name__)

# Attach fallback shared shard if dedicated CONTENT_MONGO_URI is not yet set
vault_manager.attach_fallback_dbs(db_manager.dbs)

# Clean Allowed Origins from Render Environment
config.ALLOWED_ORIGINS = [
    str(o).strip().strip('"').strip("'").rstrip("/").lower()
    for o in (config.ALLOWED_ORIGINS or [])
    if str(o).strip().strip('"').strip("'")
]

ALLOWED_HEADERS_STR = (
    "Content-Type, X-RWA-Ts, X-RWA-Sign, X-RWA-Enc, "
    "X-RWA-App, X-RWA-Device, X-Admin-Token, X-Admin-Key"
)

notify_callbacks = {
    "on_login": None,
    "on_report": None,
    "on_test_submit": None,
    "on_security_alert": None
}


def trigger_async(key, *args):
    fn = notify_callbacks.get(key)
    if callable(fn):
        threading.Thread(target=fn, args=args, daemon=True).start()


# =========================================================
# CRASH-PROOF MANUAL CORS HANDLER
# =========================================================
def _apply_cors_headers(resp):
    origin = (request.headers.get("Origin") or "").strip().rstrip("/")
    origin_low = origin.lower()
    if not config.STRICT_SECURITY_ENABLED:
        resp.headers["Access-Control-Allow-Origin"] = origin or "*"
    elif origin_low and origin_low in config.ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = ALLOWED_HEADERS_STR
    resp.headers["Access-Control-Max-Age"] = "600"
    return resp


@app.after_request
def attach_cors_after_request(resp):
    return _apply_cors_headers(resp)


@app.errorhandler(Exception)
def handle_unexpected_error(err):
    tb = traceback.format_exc()
    print(f"❌ API ERROR on {request.path}: {err}\n{tb}")
    try:
        db_manager.log_error("Backend500", str(err), user_id=getattr(g, "client_ip", "Server"), stack=tb[:1000])
    except Exception:
        pass
    resp = make_response(jsonify({"status": "error", "message": f"Server error: {str(err)[:180]}"}), 500)
    return _apply_cors_headers(resp)


# =========================================================
# E2E AES-256 ENCRYPTED REQUEST / RESPONSE HELPERS
# =========================================================
def get_req_json():
    raw = request.get_json(silent=True)
    if not isinstance(raw, dict):
        return {}
    if "enc" in raw and isinstance(raw["enc"], str):
        dec = crypto_shield.decrypt_transport_payload(raw["enc"])
        return dec if isinstance(dec, dict) else {}
    return raw


def sec_json(data_obj, status_code=200):
    use_enc = (request.headers.get("X-RWA-Enc") == "1")
    if use_enc:
        return jsonify(crypto_shield.encrypt_transport_dict(data_obj)), status_code
    return jsonify(data_obj), status_code


# =========================================================
# GLOBAL 3-LAYER SECURITY MIDDLEWARE
# =========================================================
@app.before_request
def enforce_ultra_security_shield():
    if request.method == "OPTIONS":
        resp = make_response("", 204)
        return _apply_cors_headers(resp)

    if request.path == "/":
        return None

    if not request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "Forbidden"}), 403

    ip = security_guard.get_client_ip(request)
    g.client_ip = ip
    g.device_info = security_guard.parse_device_info(request)

    is_admin_route = request.path.startswith("/api/admin/")

    # High-traffic friendly Per-IP Rate Limiter
    if request.path == "/api/login":
        allowed = security_guard.check_rate_limit(ip, bucket="login", max_req=20, window_sec=300)
    elif is_admin_route:
        allowed = security_guard.check_rate_limit(ip, bucket="admin", max_req=180, window_sec=60)
    else:
        allowed = security_guard.check_rate_limit(ip, bucket="general", max_req=160, window_sec=60)

    if not allowed:
        db_manager.log_error("RateLimiter", f"Rate limit exceeded on {request.path}", user_id=ip)
        trigger_async("on_security_alert", f"🚨 Rate Limit Alert\nIP: {ip}\nPath: {request.path}")
        return jsonify({"status": "error", "message": "Too many requests. Slow down."}), 429

    # Direct IP Ban Check (cached in RAM)
    if not is_admin_route:
        banned, ban_reason = db_manager.is_ip_banned(ip)
        if banned:
            return sec_json({"status": "error", "ip_banned": True, "message": ban_reason or "Access denied."}, 403)

    # Strict Origin Whitelist
    if not security_guard.is_origin_allowed(request):
        origin_seen = security_guard.extract_request_origin(request) or "Unknown/Direct"
        db_manager.log_error("OriginShield", f"Blocked unauthorized origin: {origin_seen} on {request.path}", user_id=ip)
        return jsonify({"status": "error", "message": f"Unauthorized origin: {origin_seen}"}), 403

    # Dynamic HMAC-SHA256 Request Signature Check
    raw_body_str = request.get_data(cache=True, as_text=True) or ""
    ok_sig, sig_err = security_guard.verify_hmac_signature(request, raw_body_str)
    if not ok_sig:
        db_manager.log_error("HMACShield", f"Rejected {request.path}: {sig_err}", user_id=ip)
        return jsonify({"status": "error", "message": f"Security check failed: {sig_err}"}), 403

    return None


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ip = getattr(g, "client_ip", security_guard.get_client_ip(request))
        banned, wait_sec = security_guard.is_admin_bruteforce_banned(ip)
        if banned:
            return sec_json({"status": "error", "message": f"IP temporarily banned ({wait_sec}s left)"}, 403)

        sess_tok = (request.headers.get("X-Admin-Token") or "").strip()
        if sess_tok and security_guard.verify_admin_session_token(sess_tok):
            return fn(*args, **kwargs)

        provided_key = (request.headers.get("X-Admin-Key") or "").strip()
        if provided_key and provided_key == config.ADMIN_PANEL_KEY:
            return fn(*args, **kwargs)

        return sec_json({"status": "error", "message": "Admin session expired or unauthorized"}, 401)
    return wrapper


# =========================================================
# MINIMAL HEALTH PROBE (RENDER / UPTIMEROBOT)
# =========================================================
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "online",
        "shield": "active",
        "user_dbs": len(db_manager.dbs),
        "vault_dbs": len(vault_manager.dbs)
    }), 200


# =========================================================
# STUDENT / WEBSITE SECURED APIs
# =========================================================
@app.route("/api/portal/status", methods=["GET"])
def api_portal_status():
    uid = request.args.get("user_id", "").strip()
    settings = db_manager.get_portal_settings()
    notices = db_manager.get_active_notices(limit=10)
    scheduled = db_manager.get_scheduled_mocks()

    blocked, reason, unread_cnt = False, "", 0
    if uid:
        u_cache_key = f"ustatus:{uid}"
        u_cached = ram_cache.get(u_cache_key)
        if u_cached is not None:
            blocked, reason, unread_cnt = u_cached
        else:
            blocked, reason = db_manager.is_user_blocked(uid)
            inbox = db_manager.get_user_inbox(uid, limit=20)
            unread_cnt = sum(1 for m in inbox if not m.get("read"))
            ram_cache.set(u_cache_key, (blocked, reason, unread_cnt), ttl_sec=15)

    return sec_json({
        "status": "success",
        "maintenance_mode": settings["maintenance_mode"],
        "maintenance_message": settings["maintenance_message"],
        "app_version": settings.get("app_version", "v4.0"),
        "kill_switches": settings.get("kill_switches", {}),
        "promo_popup": settings.get("promo_popup", {}),
        "user_blocked": blocked,
        "block_reason": reason,
        "notices": notices,
        "unread_messages": unread_cnt,
        "scheduled_mocks": scheduled
    })


@app.route("/api/get_tokens", methods=["GET"])
def api_get_tokens():
    tokens = db_manager.get_all_admin_tokens(for_admin=False)
    return sec_json({"status": "success", "count": len(tokens), "tokens": tokens})


@app.route("/api/login", methods=["POST"])
def api_login():
    payload = get_req_json()
    if not payload:
        return sec_json({"status": "error", "message": "Empty or corrupted payload"}, 400)

    settings = db_manager.get_portal_settings()
    if not payload.get("silent_sync", False) and not settings.get("kill_switches", {}).get("new_login", True):
        return sec_json({"status": "error", "message": "New logins are temporarily paused by Admin."}, 403)

    user_doc, shard_label, session_id = db_manager.upsert_user_login(payload, device_info=getattr(g, "device_info", {}))
    if not user_doc:
        return sec_json({"status": "error", "message": "Database unavailable"}, 503)

    if not payload.get("silent_sync", False):
        trigger_async("on_login", user_doc, shard_label)

    return sec_json({
        "status": "success",
        "shard": shard_label,
        "user_id": user_doc.get("user_id"),
        "session_id": session_id,
        "vip_badge": user_doc.get("vip_badge", ""),
        "weekly_xp": user_doc.get("weekly_xp", 0),
        "blocked": bool(user_doc.get("is_blocked", False)),
        "block_reason": user_doc.get("block_reason", "")
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    data = get_req_json()
    uid = str(data.get("user_id") or "").strip()
    reason = str(data.get("reason") or "User logged out from portal")
    if not uid:
        return sec_json({"status": "error", "message": "user_id required"}, 400)
    ok = db_manager.set_user_logged_out(uid, reason=reason)
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/heartbeat", methods=["POST"])
def api_heartbeat():
    data = get_req_json()
    uid = str(data.get("user_id") or "").strip()
    page = str(data.get("current_page") or "Browsing")
    sid = str(data.get("session_id") or "")
    res = db_manager.record_user_heartbeat(uid, page, sid, device_info=getattr(g, "device_info", {}))
    return sec_json({"status": "success", **res})


@app.route("/api/user/courses", methods=["POST"])
def api_user_courses():
    data = get_req_json()
    uid = data.get("user_id")
    courses = data.get("courses", [])
    if not uid:
        return sec_json({"status": "error", "message": "user_id required"}, 400)
    ok = db_manager.save_user_courses(uid, courses)
    return sec_json({"status": "success" if ok else "error", "saved_count": len(courses)})


@app.route("/api/activity", methods=["POST"])
def api_activity():
    data = get_req_json()
    uid = data.get("user_id")
    if not uid:
        return sec_json({"status": "error", "message": "user_id required"}, 400)
    db_manager.log_activity(uid, data.get("action", "VIEW"), data.get("detail", ""), data.get("meta", {}))
    return sec_json({"status": "success"})


@app.route("/api/sync/push", methods=["POST"])
def api_sync_push():
    data = get_req_json()
    uid = data.get("user_id")
    if not uid:
        return sec_json({"status": "error", "message": "user_id required"}, 400)
    ok = db_manager.push_user_sync(uid, data)
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/sync/pull", methods=["GET"])
def api_sync_pull():
    uid = request.args.get("user_id", "").strip()
    if not uid:
        return sec_json({"status": "error", "message": "user_id required"}, 400)
    sync_data = db_manager.pull_user_sync(uid)
    test_history = db_manager.get_user_test_history(uid, limit=60)
    inbox = db_manager.get_user_inbox(uid, limit=25)
    blocked, reason = db_manager.is_user_blocked(uid)
    return sec_json({
        "status": "success",
        "blocked": blocked,
        "block_reason": reason,
        "sync": sync_data,
        "test_history": test_history,
        "inbox": inbox
    })


@app.route("/api/user/inbox", methods=["GET"])
def api_user_inbox():
    uid = request.args.get("user_id", "").strip()
    if not uid:
        return sec_json({"status": "error", "message": "user_id required"}, 400)
    return sec_json({
        "status": "success",
        "messages": db_manager.get_user_inbox(uid, limit=25),
        "notices": db_manager.get_active_notices(limit=10)
    })


@app.route("/api/user/inbox/read", methods=["POST"])
def api_user_inbox_read():
    data = get_req_json()
    uid = str(data.get("user_id") or "").strip()
    if uid:
        db_manager.mark_user_inbox_read(uid)
        ram_cache.invalidate_prefix(f"ustatus:{uid}")
    return sec_json({"status": "success"})


@app.route("/api/test/submit", methods=["POST"])
def api_test_submit():
    data = get_req_json()
    if not data.get("user_id") or not data.get("test_id"):
        return sec_json({"status": "error", "message": "user_id and test_id required"}, 400)
    res = db_manager.save_test_attempt(data)
    if not res:
        return sec_json({"status": "error", "message": "Could not save attempt"}, 500)
    trigger_async("on_test_submit", res["attempt"], res["leaderboard"])
    return sec_json({
        "status": "success",
        "attempt": res["attempt"],
        "leaderboard": res["leaderboard"],
        "xp_earned": res.get("xp_earned", 0),
        "xp_info": res.get("xp_info")
    })


@app.route("/api/test/leaderboard", methods=["GET"])
def api_test_leaderboard():
    test_id = request.args.get("test_id", "").strip()
    user_id = request.args.get("user_id", "").strip()
    if not test_id:
        return sec_json({"status": "error", "message": "test_id required"}, 400)
    return sec_json({"status": "success", "leaderboard": db_manager.get_test_leaderboard(test_id, user_id or None)})


@app.route("/api/test/history", methods=["GET"])
def api_test_history():
    uid = request.args.get("user_id", "").strip()
    if not uid:
        return sec_json({"status": "error", "message": "user_id required"}, 400)
    return sec_json({"status": "success", "history": db_manager.get_user_test_history(uid, limit=60)})


# =========================================================
# WEEKLY XP LEAGUE & 1-V-1 FRIEND CHALLENGE APIs
# =========================================================
@app.route("/api/xp/league", methods=["GET"])
def api_xp_league():
    uid = request.args.get("user_id", "").strip()
    return sec_json({"status": "success", "league": db_manager.get_weekly_xp_league(uid or None, limit=25)})


@app.route("/api/xp/add", methods=["POST"])
def api_xp_add():
    data = get_req_json()
    uid = str(data.get("user_id") or "").strip()
    pts = int(data.get("points") or 0)
    reason = str(data.get("reason") or "Study Activity")
    if not uid or pts <= 0:
        return sec_json({"status": "error", "message": "user_id and positive points required"}, 400)
    res = db_manager.add_user_xp(uid, pts, reason)
    return sec_json({"status": "success" if res else "error", "xp": res})


@app.route("/api/challenge/create", methods=["POST"])
def api_challenge_create():
    data = get_req_json()
    if not data.get("test_id"):
        return sec_json({"status": "error", "message": "test_id required"}, 400)
    ch = db_manager.create_friend_challenge(data)
    if not ch:
        return sec_json({"status": "error", "message": "Could not create challenge"}, 500)
    return sec_json({"status": "success", "challenge": ch})


@app.route("/api/challenge/<cid>", methods=["GET"])
def api_challenge_get(cid):
    ch = db_manager.get_friend_challenge(cid)
    if not ch:
        return sec_json({"status": "error", "message": "Challenge not found"}, 404)
    return sec_json({"status": "success", "challenge": ch})


@app.route("/api/challenge/<cid>/complete", methods=["POST"])
def api_challenge_complete(cid):
    data = get_req_json()
    ch = db_manager.complete_friend_challenge(cid, data)
    if not ch:
        return sec_json({"status": "error", "message": "Challenge not found"}, 404)
    return sec_json({"status": "success", "challenge": ch})


# =========================================================
# DEDICATED CLOUD CONTENT VAULT APIs (AUTO-SAVE + ZERO 502 FALLBACK)
# =========================================================
@app.route("/api/vault/sync_series", methods=["POST"])
def api_vault_sync_series():
    data = get_req_json()
    cnt = vault_manager.upsert_series_batch(data.get("series") or [])
    return sec_json({"status": "success", "saved": cnt})


@app.route("/api/vault/series", methods=["GET"])
def api_vault_get_series():
    return sec_json({"status": "success", "series": vault_manager.get_all_series()})


@app.route("/api/vault/sync_folders", methods=["POST"])
def api_vault_sync_folders():
    data = get_req_json()
    cnt = vault_manager.upsert_folders_batch(data.get("series_id", ""), data.get("folders") or [])
    return sec_json({"status": "success", "saved": cnt})


@app.route("/api/vault/folders", methods=["GET"])
def api_vault_get_folders():
    sid = request.args.get("series_id", "").strip()
    return sec_json({"status": "success", "folders": vault_manager.get_series_folders(sid)})


@app.route("/api/vault/sync_titles", methods=["POST"])
def api_vault_sync_titles():
    data = get_req_json()
    cnt = vault_manager.upsert_test_titles_batch(
        data.get("series_id", ""),
        data.get("subject_id", "-1"),
        data.get("tests") or []
    )
    return sec_json({"status": "success", "saved": cnt})


@app.route("/api/vault/titles", methods=["GET"])
def api_vault_get_titles():
    sid = request.args.get("series_id", "").strip()
    sub_id = request.args.get("subject_id", "-1").strip()
    return sec_json({"status": "success", "tests": vault_manager.get_test_titles(sid, sub_id)})


@app.route("/api/vault/save_test", methods=["POST"])
def api_vault_save_test():
    data = get_req_json()
    res = vault_manager.save_full_test_payload(data)
    return sec_json({"status": "success" if res.get("saved") else "error", **res})


@app.route("/api/vault/test/<test_id>", methods=["GET"])
def api_vault_get_test(test_id):
    doc = vault_manager.get_full_test_payload(test_id)
    if not doc:
        return sec_json({"status": "not_found"}, 404)
    return sec_json({"status": "success", "test_data": doc})


# =========================================================
# CONTENT HUB, NOTICES, REPORTS & ERROR LOGGING
# =========================================================
@app.route("/api/content/daily_quiz", methods=["GET"])
def api_content_daily_quiz():
    return sec_json({"status": "success", "quiz": db_manager.get_daily_quiz()})


@app.route("/api/content/ca_capsules", methods=["GET"])
def api_content_ca_capsules():
    return sec_json({"status": "success", "capsules": db_manager.get_ca_capsules(limit=25)})


@app.route("/api/content/scheduled_mocks", methods=["GET"])
def api_content_scheduled_mocks():
    return sec_json({"status": "success", "mocks": db_manager.get_scheduled_mocks()})


@app.route("/api/notices", methods=["GET"])
def api_notices():
    return sec_json({"status": "success", "notices": db_manager.get_active_notices(limit=15)})


@app.route("/api/report", methods=["POST"])
def api_report():
    data = get_req_json()
    rep = db_manager.save_report(data)
    if not rep:
        return sec_json({"status": "error", "message": "Database unavailable"}, 503)
    trigger_async("on_report", rep)
    return sec_json({"status": "success", "report_id": rep["report_id"]})


@app.route("/api/error_log", methods=["POST"])
def api_error_log():
    data = get_req_json()
    db_manager.log_error(
        source=data.get("source", "Frontend"),
        message=data.get("message", "Unknown Error"),
        user_id=data.get("user_id", "Guest"),
        stack=data.get("stack", ""),
        meta=data.get("meta", {})
    )
    return sec_json({"status": "success"})


# =========================================================
# ULTRA-PRO WEB ADMIN PANEL SECURED APIs
# =========================================================
@app.route("/api/admin/auth", methods=["POST"])
def api_admin_auth():
    ip = getattr(g, "client_ip", security_guard.get_client_ip(request))
    banned, wait_sec = security_guard.is_admin_bruteforce_banned(ip)
    if banned:
        return sec_json({"status": "error", "message": f"Too many wrong attempts! Try after {wait_sec}s."}, 403)

    data = get_req_json()
    key = str(data.get("admin_key") or request.headers.get("X-Admin-Key") or "").strip()

    if key != config.ADMIN_PANEL_KEY:
        now_banned = security_guard.record_admin_fail(ip)
        db_manager.log_error("AdminAuthFail", f"Wrong Admin Key attempt from IP {ip}", user_id=ip)
        if now_banned:
            trigger_async("on_security_alert", f"🚨 ADMIN BRUTE-FORCE AUTO-BAN\nIP: {ip} banned for 30 mins after 5 wrong keys!")
            return sec_json({"status": "error", "message": "5 wrong attempts! IP auto-banned for 30 minutes."}, 403)
        return sec_json({"status": "error", "message": "Wrong Admin Key!"}, 401)

    security_guard.clear_admin_fails(ip)
    token, exp = security_guard.issue_admin_session_token(ip)
    db_manager.log_admin_action("ADMIN_LOGIN", f"Admin unlocked panel from {ip}", ip=ip)
    return sec_json({"status": "success", "admin_token": token, "expires_at": exp})


@app.route("/api/admin/stats", methods=["GET"])
@require_admin
def api_admin_stats():
    return sec_json({"status": "success", "stats": db_manager.get_cluster_stats()})


@app.route("/api/admin/vault/summary", methods=["GET"])
@require_admin
def api_admin_vault_summary():
    return sec_json({"status": "success", "summary": vault_manager.get_vault_summary()})


@app.route("/api/admin/vault/series", methods=["GET"])
@require_admin
def api_admin_vault_series():
    return sec_json({"status": "success", "series": vault_manager.get_all_series()})


@app.route("/api/admin/vault/folders/<series_id>", methods=["GET"])
@require_admin
def api_admin_vault_folders(series_id):
    return sec_json({"status": "success", "folders": vault_manager.get_series_folders(series_id)})


@app.route("/api/admin/vault/titles/<series_id>", methods=["GET"])
@require_admin
def api_admin_vault_titles(series_id):
    sub_id = request.args.get("subject_id", "-1").strip()
    return sec_json({"status": "success", "tests": vault_manager.get_test_titles(series_id, sub_id)})


@app.route("/api/admin/vault/test/<test_id>", methods=["GET", "DELETE"])
@require_admin
def api_admin_vault_test(test_id):
    if request.method == "DELETE":
        ok = vault_manager.delete_test_from_vault(test_id)
        if ok:
            db_manager.log_admin_action("DELETE_VAULT_TEST", f"Deleted Test #{test_id} from Cloud Vault")
        return sec_json({"status": "success" if ok else "error"})
    doc = vault_manager.get_full_test_payload(test_id)
    if not doc:
        return sec_json({"status": "error", "message": "Full question bank not archived yet for this test."}, 404)
    return sec_json({"status": "success", "test_data": doc})


@app.route("/api/admin/vault/series/<series_id>", methods=["DELETE"])
@require_admin
def api_admin_vault_delete_series(series_id):
    ok = vault_manager.delete_series_from_vault(series_id)
    if ok:
        db_manager.log_admin_action("DELETE_VAULT_SERIES", f"Deleted Series #{series_id} from Cloud Vault")
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/cache/flush", methods=["POST"])
@require_admin
def api_admin_cache_flush():
    cleared = ram_cache.clear_all()
    db_manager.log_admin_action("FLUSH_RAM_CACHE", f"Cleared {cleared} cached keys")
    return sec_json({"status": "success", "cleared_keys": cleared})


@app.route("/api/admin/radar", methods=["GET"])
@require_admin
def api_admin_radar():
    return sec_json({"status": "success", "live_users": db_manager.get_live_radar_users(180)})


@app.route("/api/admin/users", methods=["GET"])
@require_admin
def api_admin_users():
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(50, max(5, int(request.args.get("per_page", 15))))
    q = request.args.get("q", "").strip()
    fmode = request.args.get("filter", "all").strip()
    users, total = db_manager.get_all_users_paginated(page=page, per_page=per_page, query=q, filter_mode=fmode)
    return sec_json({"status": "success", "users": users, "total": total, "page": page, "per_page": per_page})


@app.route("/api/admin/user/<uid>", methods=["GET"])
@require_admin
def api_admin_user_detail(uid):
    dossier = db_manager.get_user_full_dossier(uid)
    if not dossier:
        return sec_json({"status": "error", "message": "User not found"}, 404)
    return sec_json({"status": "success", "dossier": dossier})


@app.route("/api/admin/user/block", methods=["POST"])
@require_admin
def api_admin_user_block():
    data = get_req_json()
    ok = db_manager.set_user_blocked(data.get("user_id", ""), bool(data.get("blocked", True)), data.get("reason", ""))
    ram_cache.invalidate_prefix(f"ustatus:{data.get('user_id', '')}")
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/user/force_logout", methods=["POST"])
@require_admin
def api_admin_force_logout():
    data = get_req_json()
    ok = db_manager.force_logout_user(data.get("user_id", ""))
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/user/vip", methods=["POST"])
@require_admin
def api_admin_user_vip():
    data = get_req_json()
    ok = db_manager.set_user_vip_badge(data.get("user_id", ""), data.get("badge", ""))
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/user/message", methods=["POST"])
@require_admin
def api_admin_user_message():
    data = get_req_json()
    res = db_manager.send_personal_message(data.get("user_id", ""), data.get("title", ""), data.get("message", ""))
    ram_cache.invalidate_prefix(f"ustatus:{data.get('user_id', '')}")
    return sec_json({"status": "success" if res else "error", "msg": res})


@app.route("/api/admin/broadcast", methods=["POST"])
@require_admin
def api_admin_broadcast():
    data = get_req_json()
    cnt = db_manager.send_targeted_broadcast(
        data.get("target_group", "all"),
        data.get("title", "Announcement"),
        data.get("message", ""),
        data.get("state_filter", "")
    )
    ram_cache.invalidate_prefix("ustatus:")
    return sec_json({"status": "success", "sent_count": cnt})


@app.route("/api/admin/activities", methods=["GET"])
@require_admin
def api_admin_activities():
    limit = min(100, int(request.args.get("limit", 45)))
    return sec_json({"status": "success", "activities": db_manager.get_recent_global_activities(limit=limit)})


@app.route("/api/admin/top_performers", methods=["GET"])
@require_admin
def api_admin_top_performers():
    return sec_json({"status": "success", "performers": db_manager.get_top_performers(25)})


@app.route("/api/admin/test_analytics", methods=["GET"])
@require_admin
def api_admin_test_analytics():
    return sec_json({"status": "success", "tests": db_manager.get_test_analytics(30)})


@app.route("/api/admin/test_attempt/<aid>", methods=["DELETE"])
@require_admin
def api_admin_delete_attempt(aid):
    ok = db_manager.delete_test_attempt(aid)
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/tokens", methods=["GET", "POST", "DELETE"])
@require_admin
def api_admin_tokens():
    if request.method == "GET":
        return sec_json({"status": "success", "tokens": db_manager.get_all_admin_tokens(for_admin=True)})
    data = get_req_json()
    if request.method == "POST":
        ok = db_manager.add_admin_token(data.get("user_id", ""), data.get("token", ""), data.get("label", "Cloud Server"))
        return sec_json({"status": "success" if ok else "error"})
    if request.method == "DELETE":
        ok = db_manager.delete_admin_token(user_id=data.get("user_id", ""), token=data.get("token", ""))
        return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/tokens/clean_dead", methods=["POST"])
@require_admin
def api_admin_clean_dead_tokens():
    res = db_manager.scan_and_clean_dead_tokens()
    return sec_json({"status": "success", **res})


@app.route("/api/admin/settings", methods=["GET", "POST"])
@require_admin
def api_admin_settings():
    if request.method == "GET":
        return sec_json({"status": "success", "settings": db_manager.get_portal_settings()})
    data = get_req_json()
    updated = db_manager.update_portal_settings(data)
    return sec_json({"status": "success", "settings": updated})


@app.route("/api/admin/notices", methods=["GET", "POST"])
@require_admin
def api_admin_notices():
    if request.method == "GET":
        return sec_json({"status": "success", "notices": db_manager.get_active_notices(limit=25)})
    data = get_req_json()
    res = db_manager.add_notice(data.get("title", ""), data.get("message", ""), data.get("level", "info"))
    return sec_json({"status": "success" if res else "error", "notice": res})


@app.route("/api/admin/notices/<nid>", methods=["DELETE"])
@require_admin
def api_admin_delete_notice(nid):
    ok = db_manager.delete_notice(nid)
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/reports", methods=["GET"])
@require_admin
def api_admin_reports():
    return sec_json({"status": "success", "reports": db_manager.get_reports(limit=40)})


@app.route("/api/admin/reports/<rid>/resolve", methods=["POST"])
@require_admin
def api_admin_resolve_report(rid):
    data = get_req_json()
    ok = db_manager.reply_and_resolve_report(rid, data.get("reply", ""))
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/daily_quiz", methods=["GET", "POST"])
@require_admin
def api_admin_daily_quiz():
    if request.method == "GET":
        return sec_json({"status": "success", "quiz": db_manager.get_daily_quiz()})
    data = get_req_json()
    ok = db_manager.publish_daily_quiz(data.get("questions", []), data.get("title", "Daily 5-Min Rapid Quiz"))
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/ca_capsules", methods=["GET", "POST"])
@require_admin
def api_admin_ca_capsules():
    if request.method == "GET":
        return sec_json({"status": "success", "capsules": db_manager.get_ca_capsules(30)})
    data = get_req_json()
    res = db_manager.add_ca_capsule(data.get("title", ""), data.get("points", []), data.get("category", "Current Affairs"))
    return sec_json({"status": "success" if res else "error", "capsule": res})


@app.route("/api/admin/ca_capsules/<cid>", methods=["DELETE"])
@require_admin
def api_admin_delete_ca(cid):
    ok = db_manager.delete_ca_capsule(cid)
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/scheduled_mocks", methods=["GET", "POST"])
@require_admin
def api_admin_scheduled_mocks():
    if request.method == "GET":
        return sec_json({"status": "success", "mocks": db_manager.get_scheduled_mocks()})
    data = get_req_json()
    res = db_manager.save_scheduled_mock(data)
    return sec_json({"status": "success" if res else "error", "mock": res})


@app.route("/api/admin/scheduled_mocks/<sid>", methods=["DELETE"])
@require_admin
def api_admin_delete_scheduled_mock(sid):
    ok = db_manager.delete_scheduled_mock(sid)
    return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/banned_ips", methods=["GET", "POST", "DELETE"])
@require_admin
def api_admin_banned_ips():
    if request.method == "GET":
        return sec_json({"status": "success", "ips": db_manager.get_banned_ips()})
    data = get_req_json()
    if request.method == "POST":
        ok = db_manager.ban_ip(data.get("ip", ""), data.get("reason", "Banned by Admin"), data.get("user_id", ""))
        return sec_json({"status": "success" if ok else "error"})
    if request.method == "DELETE":
        ok = db_manager.unban_ip(data.get("ip", ""))
        return sec_json({"status": "success" if ok else "error"})


@app.route("/api/admin/errors", methods=["GET", "DELETE"])
@require_admin
def api_admin_errors():
    if request.method == "GET":
        return sec_json({"status": "success", "errors": db_manager.get_error_logs(limit=60)})
    deleted = db_manager.clear_error_logs()
    return sec_json({"status": "success", "deleted": deleted})


@app.route("/api/admin/clean_old_logs", methods=["POST"])
@require_admin
def api_admin_clean_old_logs():
    data = get_req_json()
    days = int(data.get("days", 30))
    res = db_manager.clean_old_logs(days)
    return sec_json({"status": "success", **res})


@app.route("/api/admin/audit_logs", methods=["GET"])
@require_admin
def api_admin_audit_logs():
    return sec_json({"status": "success", "logs": db_manager.get_admin_audit_logs(60)})


@app.route("/api/admin/diagnostics", methods=["GET"])
@require_admin
def api_admin_diagnostics():
    return sec_json({"status": "success", "diag": db_manager.run_system_diagnostics()})


@app.route("/api/admin/export_csv", methods=["GET"])
@require_admin
def api_admin_export_csv():
    return sec_json({"status": "success", "csv": db_manager.export_users_csv_text()})


@app.route("/api/admin/backup", methods=["GET"])
@require_admin
def api_admin_backup():
    return sec_json(db_manager.export_full_backup())
