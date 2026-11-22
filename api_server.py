import threading
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import config
from db_manager import db_manager

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

notify_callbacks = {
    "on_login": None,
    "on_report": None,
    "on_test_submit": None
}


def trigger_async(key, *args):
    fn = notify_callbacks.get(key)
    if callable(fn):
        threading.Thread(target=fn, args=args, daemon=True).start()


def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        provided = (
            request.headers.get("X-Admin-Key")
            or request.args.get("key")
            or (request.get_json(silent=True) or {}).get("admin_key")
            or ""
        ).strip()
        if not provided or provided != config.ADMIN_PANEL_KEY:
            return jsonify({"status": "error", "message": "Unauthorized Admin Key"}), 401
        return fn(*args, **kwargs)
    return wrapper


# =========================================================
# HEALTH & PORTAL STATUS (MAINTENANCE + BLOCK CHECK)
# =========================================================
@app.route("/", methods=["GET"])
def home():
    stats = db_manager.get_cluster_stats()
    return jsonify({
        "status": "online",
        "service": "RWA Sky Pro Portal Backend (4-MongoDB Cluster)",
        "connected_dbs": stats["connected_dbs"],
        "total_users": stats["total_users"],
        "maintenance_mode": stats["settings"]["maintenance_mode"]
    })


@app.route("/api/portal/status", methods=["GET"])
def api_portal_status():
    uid = request.args.get("user_id", "").strip()
    settings = db_manager.get_portal_settings()
    blocked, reason = db_manager.is_user_blocked(uid) if uid else (False, "")
    notices = db_manager.get_active_notices(limit=10)
    return jsonify({
        "status": "success",
        "maintenance_mode": settings["maintenance_mode"],
        "maintenance_message": settings["maintenance_message"],
        "user_blocked": blocked,
        "block_reason": reason,
        "notices": notices
    })


# =========================================================
# OLD ENDPOINTS (100% COMPATIBLE WITH EXISTING WEBSITE)
# =========================================================
@app.route("/api/get_tokens", methods=["GET"])
def api_get_tokens():
    tokens = db_manager.get_all_admin_tokens()
    return jsonify({"status": "success", "count": len(tokens), "tokens": tokens})


@app.route("/api/login", methods=["POST"])
def api_login():
    payload = request.get_json(silent=True) or {}
    if not payload:
        return jsonify({"status": "error", "message": "Empty payload"}), 400

    user_doc, shard_label = db_manager.upsert_user_login(payload)
    if not user_doc:
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

    trigger_async("on_login", user_doc, shard_label)
    return jsonify({
        "status": "success",
        "shard": shard_label,
        "user_id": user_doc.get("user_id"),
        "blocked": bool(user_doc.get("is_blocked", False)),
        "block_reason": user_doc.get("block_reason", "")
    })


# =========================================================
# STUDENT PRO ENDPOINTS
# =========================================================
@app.route("/api/user/courses", methods=["POST"])
def api_user_courses():
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    courses = data.get("courses", [])
    if not uid:
        return jsonify({"status": "error", "message": "user_id required"}), 400
    ok = db_manager.save_user_courses(uid, courses)
    return jsonify({"status": "success" if ok else "error", "saved_count": len(courses)})


@app.route("/api/activity", methods=["POST"])
def api_activity():
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    if not uid:
        return jsonify({"status": "error", "message": "user_id required"}), 400
    db_manager.log_activity(uid, data.get("action", "VIEW"), data.get("detail", ""), data.get("meta", {}))
    return jsonify({"status": "success"})


@app.route("/api/sync/push", methods=["POST"])
def api_sync_push():
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id")
    if not uid:
        return jsonify({"status": "error", "message": "user_id required"}), 400
    ok = db_manager.push_user_sync(uid, data)
    return jsonify({"status": "success" if ok else "error"})


@app.route("/api/sync/pull", methods=["GET"])
def api_sync_pull():
    uid = request.args.get("user_id", "").strip()
    if not uid:
        return jsonify({"status": "error", "message": "user_id required"}), 400
    sync_data = db_manager.pull_user_sync(uid)
    test_history = db_manager.get_user_test_history(uid, limit=30)
    blocked, reason = db_manager.is_user_blocked(uid)
    return jsonify({
        "status": "success",
        "blocked": blocked,
        "block_reason": reason,
        "sync": sync_data,
        "test_history": test_history
    })


@app.route("/api/test/submit", methods=["POST"])
def api_test_submit():
    data = request.get_json(silent=True) or {}
    if not data.get("user_id") or not data.get("test_id"):
        return jsonify({"status": "error", "message": "user_id and test_id required"}), 400
    res = db_manager.save_test_attempt(data)
    if not res:
        return jsonify({"status": "error", "message": "Could not save attempt"}), 500
    trigger_async("on_test_submit", res["attempt"], res["leaderboard"])
    return jsonify({"status": "success", "attempt": res["attempt"], "leaderboard": res["leaderboard"]})


@app.route("/api/test/leaderboard", methods=["GET"])
def api_test_leaderboard():
    test_id = request.args.get("test_id", "").strip()
    user_id = request.args.get("user_id", "").strip()
    if not test_id:
        return jsonify({"status": "error", "message": "test_id required"}), 400
    return jsonify({"status": "success", "leaderboard": db_manager.get_test_leaderboard(test_id, user_id or None)})


@app.route("/api/test/history", methods=["GET"])
def api_test_history():
    uid = request.args.get("user_id", "").strip()
    if not uid:
        return jsonify({"status": "error", "message": "user_id required"}), 400
    return jsonify({"status": "success", "history": db_manager.get_user_test_history(uid, limit=50)})


@app.route("/api/notices", methods=["GET"])
def api_notices():
    return jsonify({"status": "success", "notices": db_manager.get_active_notices(limit=15)})


@app.route("/api/report", methods=["POST"])
def api_report():
    data = request.get_json(silent=True) or {}
    rep = db_manager.save_report(data)
    if not rep:
        return jsonify({"status": "error", "message": "Database unavailable"}), 503
    trigger_async("on_report", rep)
    return jsonify({"status": "success", "report_id": rep["report_id"]})


@app.route("/api/error_log", methods=["POST"])
def api_error_log():
    data = request.get_json(silent=True) or {}
    db_manager.log_error(
        source=data.get("source", "Frontend"),
        message=data.get("message", "Unknown Error"),
        user_id=data.get("user_id", "Guest"),
        stack=data.get("stack", ""),
        meta=data.get("meta", {})
    )
    return jsonify({"status": "success"})


# =========================================================
# WEB ADMIN PANEL SECURED APIs (X-Admin-Key)
# =========================================================
@app.route("/api/admin/auth", methods=["POST"])
@require_admin
def api_admin_auth():
    return jsonify({"status": "success", "message": "Authenticated"})


@app.route("/api/admin/stats", methods=["GET"])
@require_admin
def api_admin_stats():
    return jsonify({"status": "success", "stats": db_manager.get_cluster_stats()})


@app.route("/api/admin/users", methods=["GET"])
@require_admin
def api_admin_users():
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(50, max(5, int(request.args.get("per_page", 15))))
    q = request.args.get("q", "").strip()
    fmode = request.args.get("filter", "all").strip()
    users, total = db_manager.get_all_users_paginated(page=page, per_page=per_page, query=q, filter_mode=fmode)
    return jsonify({
        "status": "success",
        "users": users,
        "total": total,
        "page": page,
        "per_page": per_page
    })


@app.route("/api/admin/user/<uid>", methods=["GET"])
@require_admin
def api_admin_user_detail(uid):
    dossier = db_manager.get_user_full_dossier(uid)
    if not dossier:
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "success", "dossier": dossier})


@app.route("/api/admin/user/block", methods=["POST"])
@require_admin
def api_admin_user_block():
    data = request.get_json(silent=True) or {}
    uid = data.get("user_id", "")
    blocked = bool(data.get("blocked", True))
    reason = data.get("reason", "")
    ok = db_manager.set_user_blocked(uid, blocked, reason)
    if not ok:
        return jsonify({"status": "error", "message": "User not found"}), 404
    return jsonify({"status": "success", "blocked": blocked})


@app.route("/api/admin/activities", methods=["GET"])
@require_admin
def api_admin_activities():
    limit = min(100, int(request.args.get("limit", 40)))
    return jsonify({"status": "success", "activities": db_manager.get_recent_global_activities(limit=limit)})


@app.route("/api/admin/tokens", methods=["GET", "POST", "DELETE"])
@require_admin
def api_admin_tokens():
    if request.method == "GET":
        return jsonify({"status": "success", "tokens": db_manager.get_all_admin_tokens()})
    data = request.get_json(silent=True) or {}
    if request.method == "POST":
        ok = db_manager.add_admin_token(data.get("user_id", ""), data.get("token", ""), data.get("label", "Cloud Server"))
        return jsonify({"status": "success" if ok else "error"})
    if request.method == "DELETE":
        ok = db_manager.delete_admin_token(user_id=data.get("user_id", ""), token=data.get("token", ""))
        return jsonify({"status": "success" if ok else "error"})


@app.route("/api/admin/settings", methods=["GET", "POST"])
@require_admin
def api_admin_settings():
    if request.method == "GET":
        return jsonify({"status": "success", "settings": db_manager.get_portal_settings()})
    data = request.get_json(silent=True) or {}
    updated = db_manager.update_portal_settings(data)
    return jsonify({"status": "success", "settings": updated})


@app.route("/api/admin/notices", methods=["GET", "POST"])
@require_admin
def api_admin_notices():
    if request.method == "GET":
        return jsonify({"status": "success", "notices": db_manager.get_active_notices(limit=25)})
    data = request.get_json(silent=True) or {}
    res = db_manager.add_notice(data.get("title", ""), data.get("message", ""), data.get("level", "info"))
    return jsonify({"status": "success" if res else "error", "notice": res})


@app.route("/api/admin/notices/<nid>", methods=["DELETE"])
@require_admin
def api_admin_delete_notice(nid):
    ok = db_manager.delete_notice(nid)
    return jsonify({"status": "success" if ok else "error"})


@app.route("/api/admin/reports", methods=["GET"])
@require_admin
def api_admin_reports():
    return jsonify({"status": "success", "reports": db_manager.get_reports(limit=40)})


@app.route("/api/admin/reports/<rid>/resolve", methods=["POST"])
@require_admin
def api_admin_resolve_report(rid):
    ok = db_manager.resolve_report(rid)
    return jsonify({"status": "success" if ok else "error"})


@app.route("/api/admin/errors", methods=["GET", "DELETE"])
@require_admin
def api_admin_errors():
    if request.method == "GET":
        return jsonify({"status": "success", "errors": db_manager.get_error_logs(limit=50)})
    deleted = db_manager.clear_error_logs()
    return jsonify({"status": "success", "deleted": deleted})


@app.route("/api/admin/backup", methods=["GET"])
@require_admin
def api_admin_backup():
    return jsonify(db_manager.export_full_backup())
