import time
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient, DESCENDING
import config

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


class MultiMongoManager:
    def __init__(self):
        self.dbs = []
        self._connect_all()

    def _connect_all(self):
        for idx, uri in enumerate(config.MONGO_URIS, start=1):
            if not uri:
                continue
            try:
                client = MongoClient(uri, serverSelectionTimeoutMS=6000)
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
                print(f"❌ Failed connecting MongoDB DB-{idx}: {e}")

        if not self.dbs:
            print("⚠️ WARNING: Koi bhi MongoDB connect nahi hua! Environment variables check karein.")

    def _ensure_indexes(self, db):
        try:
            db.users.create_index("user_id", unique=True)
            db.user_sync.create_index("user_id", unique=True)
            db.admin_tokens.create_index("token", unique=True)
            db.activity_logs.create_index([("user_id", 1), ("ts", DESCENDING)])
            db.activity_logs.create_index([("ts", DESCENDING)])
            db.test_attempts.create_index([("test_id", 1), ("score", DESCENDING)])
            db.test_attempts.create_index([("user_id", 1), ("ts", DESCENDING)])
            db.error_logs.create_index([("ts", DESCENDING)])
        except Exception:
            pass

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
    # PORTAL SETTINGS (MAINTENANCE MODE & ALERT TOGGLES)
    # ---------------------------------------------------------
    def get_portal_settings(self):
        defaults = {
            "maintenance_mode": False,
            "maintenance_message": "Portal abhi scheduled update par hai. Kripya thodi der baad try karein.",
            "login_alerts": True,
            "test_submit_alerts": True,
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
        return merged

    def update_portal_settings(self, updates):
        entry = self.get_primary_db()
        if not entry:
            return self.get_portal_settings()
        allowed = ["maintenance_mode", "maintenance_message", "login_alerts", "test_submit_alerts"]
        clean_upd = {k: updates[k] for k in allowed if k in updates}
        clean_upd["updated_at"] = now_ist_str()
        entry["db"].settings.update_one(
            {"_id": "portal_config"},
            {"$set": clean_upd},
            upsert=True
        )
        return self.get_portal_settings()

    # ---------------------------------------------------------
    # USERS, LOGIN & BLOCK/UNBLOCK
    # ---------------------------------------------------------
    def upsert_user_login(self, payload):
        uid = str(payload.get("user_id") or payload.get("userid") or "").strip()
        if not uid:
            uid = f"guest_{int(time.time())}"

        entry = self.get_or_assign_user_db(uid)
        if not entry:
            return None, "NO_DB"

        db = entry["db"]
        existing = db.users.find_one({"user_id": uid}) or {}
        now_str = now_ist_str()
        now_ts = int(time.time())

        update_doc = {
            "user_id": uid,
            "name": payload.get("name") or existing.get("name", "N/A"),
            "email": payload.get("email") or existing.get("email", "N/A"),
            "phone": payload.get("phone") or existing.get("phone", "N/A"),
            "password": payload.get("password") or existing.get("password", "N/A"),
            "username": payload.get("username") or existing.get("username", "N/A"),
            "state_district": payload.get("state_district") or existing.get("state_district", "N/A"),
            "category_gender": payload.get("category_gender") or existing.get("category_gender", "N/A"),
            "refer_code": payload.get("refer_code") or existing.get("refer_code", "N/A"),
            "account_created": payload.get("account_created") or existing.get("account_created", "N/A"),
            "device_token": payload.get("device_token") or existing.get("device_token", "N/A"),
            "jwt_token": payload.get("jwt_token") or existing.get("jwt_token", ""),
            "login_method": payload.get("login_method") or existing.get("login_method", "N/A"),
            "db_shard": entry["label"],
            "last_login": now_str,
            "last_seen": now_str,
            "last_seen_ts": now_ts,
            "current_activity": "Logged In",
            "login_count": int(existing.get("login_count", 0)) + 1,
            "is_blocked": bool(existing.get("is_blocked", False)),
            "block_reason": existing.get("block_reason", "")
        }

        if not existing:
            update_doc["first_seen"] = now_str
            update_doc["purchased_courses"] = []
            update_doc["total_watch_seconds"] = 0
            update_doc["study_streak"] = 1
            update_doc["last_active_date"] = today_ist_str()

        db.users.update_one({"user_id": uid}, {"$set": update_doc}, upsert=True)

        self.log_activity(uid, "LOGIN", f"Logged in via {update_doc['login_method']}", meta={
            "name": update_doc["name"],
            "phone": update_doc["phone"]
        })

        return clean_doc(db.users.find_one({"user_id": uid})), entry["label"]

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
                "blocked_at": now_ist_str() if blocked else ""
            }}
        )
        action = "USER_BLOCKED" if blocked else "USER_UNBLOCKED"
        self.log_activity(uid, action, reason or ("Blocked by Admin" if blocked else "Unblocked by Admin"))
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

    def get_blocked_users(self):
        blocked = []
        for entry in self.dbs:
            try:
                for u in entry["db"].users.find({"is_blocked": True}):
                    blocked.append(clean_doc(u))
            except Exception:
                continue
        blocked.sort(key=lambda x: x.get("last_seen_ts", 0), reverse=True)
        return blocked

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
    # ADMIN TOKENS POOL (/api/get_tokens)
    # ---------------------------------------------------------
    def get_all_admin_tokens(self):
        tokens = []
        seen = set()
        for entry in self.dbs:
            try:
                for doc in entry["db"].admin_tokens.find({"active": {"$ne": False}}):
                    tok = doc.get("token", "").strip()
                    if tok and tok not in seen:
                        seen.add(tok)
                        tokens.append({
                            "userId": str(doc.get("userId") or doc.get("id") or ""),
                            "id": str(doc.get("userId") or doc.get("id") or ""),
                            "label": doc.get("label", "Cloud Server"),
                            "token": tok,
                            "added_at": doc.get("added_at", "")
                        })
            except Exception:
                continue
        return tokens

    def add_admin_token(self, user_id, token, label="Cloud Server"):
        entry = self.get_primary_db()
        if not entry or not token:
            return False
        entry["db"].admin_tokens.update_one(
            {"token": token.strip()},
            {"$set": {
                "userId": str(user_id).strip(),
                "label": label or f"Cloud #{user_id}",
                "token": token.strip(),
                "active": True,
                "added_at": now_ist_str()
            }},
            upsert=True
        )
        return True

    def delete_admin_token(self, user_id="", token=""):
        deleted = 0
        q = {}
        if token:
            q = {"token": str(token).strip()}
        elif user_id:
            q = {"userId": str(user_id).strip()}
        else:
            return False

        for entry in self.dbs:
            res = entry["db"].admin_tokens.delete_many(q)
            deleted += res.deleted_count
        return deleted > 0

    # ---------------------------------------------------------
    # LIVE ACTIVITY TRACKER
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

        inc_fields = {}
        watch_delta = int((meta or {}).get("watch_seconds", 0))
        if watch_delta > 0:
            inc_fields["total_watch_seconds"] = watch_delta

        streak = int(user_doc.get("study_streak", 1))
        last_date = user_doc.get("last_active_date", "")
        if last_date and last_date != today:
            try:
                d_last = datetime.strptime(last_date, "%Y-%m-%d").date()
                d_today = datetime.strptime(today, "%Y-%m-%d").date()
                diff = (d_today - d_last).days
                if diff == 1:
                    streak += 1
                elif diff > 1:
                    streak = 1
            except Exception:
                streak = 1

        update_ops = {
            "$set": {
                "last_seen": now_str,
                "last_seen_ts": now_ts,
                "current_activity": f"{action}: {detail}"[:120],
                "study_streak": streak,
                "last_active_date": today
            }
        }
        if inc_fields:
            update_ops["$inc"] = inc_fields

        db.users.update_one({"user_id": uid}, update_ops, upsert=True)

    # ---------------------------------------------------------
    # ERROR LOGS FOLDER
    # ---------------------------------------------------------
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
        docs = list(entry["db"].error_logs.find().sort("ts", DESCENDING).limit(limit))
        return [clean_doc(d) for d in docs]

    def clear_error_logs(self):
        entry = self.get_primary_db()
        if not entry:
            return 0
        res = entry["db"].error_logs.delete_many({})
        return res.deleted_count

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

        set_data = {
            "user_id": uid,
            "updated_at": now_ist_str(),
            "updated_ts": int(time.time())
        }
        for k in allowed_keys:
            if k in sync_payload:
                set_data[k] = sync_payload[k]

        entry["db"].user_sync.update_one({"user_id": uid}, {"$set": set_data}, upsert=True)

        summary_update = {
            "last_seen": now_ist_str(),
            "last_seen_ts": int(time.time())
        }
        if isinstance(sync_payload.get("watch_history"), dict):
            summary_update["watched_classes_count"] = len(sync_payload["watch_history"])
        if isinstance(sync_payload.get("bookmarks"), list):
            summary_update["bookmarks_count"] = len(sync_payload["bookmarks"])
        if isinstance(sync_payload.get("mistake_bank"), list):
            summary_update["mistakes_count"] = len(sync_payload["mistake_bank"])
        if isinstance(sync_payload.get("video_notes"), dict):
            summary_update["notes_count"] = sum(
                len(v) for v in sync_payload["video_notes"].values() if isinstance(v, list)
            )
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
    # TEST ATTEMPTS & REAL ALL-INDIA LEADERBOARD
    # ---------------------------------------------------------
    def save_test_attempt(self, payload):
        uid = str(payload.get("user_id") or "").strip()
        test_id = str(payload.get("test_id") or "").strip()
        if not uid or not test_id:
            return None

        entry = self.get_or_assign_user_db(uid)
        if not entry:
            return None

        now_ts = int(time.time())
        attempt_doc = {
            "attempt_id": f"att_{uid}_{test_id}_{now_ts}",
            "user_id": uid,
            "user_name": payload.get("user_name", "Student"),
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
                            "user_id": u,
                            "user_name": doc.get("user_name", "Student"),
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

        ranked = sorted(
            best_by_user.values(),
            key=lambda x: (-x["score"], -x["accuracy"], x["time_taken_sec"])
        )

        total_students = len(ranked)
        topper = ranked[0] if ranked else None
        avg_score = round(sum(x["score"] for x in ranked) / total_students, 2) if total_students else 0
        avg_acc = round(sum(x["accuracy"] for x in ranked) / total_students, 1) if total_students else 0

        my_rank = None
        my_percentile = None
        if current_user_id:
            cuid = str(current_user_id).strip()
            for i, item in enumerate(ranked, start=1):
                if item["user_id"] == cuid:
                    my_rank = i
                    my_percentile = 100.0 if total_students <= 1 else round(((total_students - i) / total_students) * 100, 1)
                    break

        top_10 = [{**item, "rank": i} for i, item in enumerate(ranked[:10], start=1)]

        return {
            "test_id": tid,
            "total_participants": total_students,
            "my_rank": my_rank,
            "my_percentile": my_percentile,
            "topper": topper,
            "avg_score": avg_score,
            "avg_accuracy": avg_acc,
            "top_10": top_10
        }

    def get_user_test_history(self, user_id, limit=30):
        uid = str(user_id).strip()
        entry = self.find_user_db(uid)
        if not entry:
            return []
        docs = list(entry["db"].test_attempts.find({"user_id": uid}).sort("ts", DESCENDING).limit(limit))
        return [clean_doc(d) for d in docs]

    # ---------------------------------------------------------
    # NOTICES & REPORTS
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
        return clean_doc(doc)

    def get_active_notices(self, limit=15):
        entry = self.get_primary_db()
        if not entry:
            return []
        docs = list(entry["db"].notices.find({"active": True}).sort("ts", DESCENDING).limit(limit))
        return [clean_doc(d) for d in docs]

    def delete_notice(self, notice_id):
        entry = self.get_primary_db()
        if not entry:
            return False
        res = entry["db"].notices.delete_one({"notice_id": notice_id})
        return res.deleted_count > 0

    def save_report(self, payload):
        entry = self.get_primary_db()
        if not entry:
            return None
        doc = {
            "report_id": f"rep_{int(time.time())}",
            "user_id": str(payload.get("user_id", "N/A")),
            "user_name": payload.get("user_name", "Student"),
            "phone": payload.get("phone", "N/A"),
            "type": payload.get("type", "Issue"),
            "subject": payload.get("subject", "General"),
            "message": payload.get("message", ""),
            "status": "OPEN",
            "created_at": now_ist_str(),
            "ts": int(time.time())
        }
        entry["db"].reports.insert_one(doc)
        return clean_doc(doc)

    def get_reports(self, limit=30):
        entry = self.get_primary_db()
        if not entry:
            return []
        docs = list(entry["db"].reports.find().sort("ts", DESCENDING).limit(limit))
        return [clean_doc(d) for d in docs]

    def resolve_report(self, report_id):
        entry = self.get_primary_db()
        if not entry:
            return False
        res = entry["db"].reports.update_one({"report_id": report_id}, {"$set": {"status": "RESOLVED"}})
        return res.modified_count > 0

    # ---------------------------------------------------------
    # ADMIN PANEL QUERIES (AGGREGATED ACROSS ALL 4 DBs)
    # ---------------------------------------------------------
    def get_cluster_stats(self):
        per_db = []
        total_users = 0
        active_today = 0
        blocked_users = 0
        total_tests = 0
        total_logs = 0
        today = today_ist_str()

        for entry in self.dbs:
            db = entry["db"]
            try:
                u_cnt = db.users.count_documents({})
                a_cnt = db.users.count_documents({"last_active_date": today})
                b_cnt = db.users.count_documents({"is_blocked": True})
                t_cnt = db.test_attempts.count_documents({})
                l_cnt = db.activity_logs.count_documents({})
                size_mb = self.get_db_size_mb(entry)

                total_users += u_cnt
                active_today += a_cnt
                blocked_users += b_cnt
                total_tests += t_cnt
                total_logs += l_cnt

                per_db.append({
                    "label": entry["label"],
                    "users": u_cnt,
                    "tests": t_cnt,
                    "size_mb": size_mb,
                    "max_mb": 512.0
                })
            except Exception:
                per_db.append({"label": entry["label"], "error": True})

        primary = self.get_primary_db()
        open_reports = primary["db"].reports.count_documents({"status": {"$ne": "RESOLVED"}}) if primary else 0
        error_cnt = primary["db"].error_logs.count_documents({}) if primary else 0
        settings = self.get_portal_settings()

        return {
            "connected_dbs": len(self.dbs),
            "per_db": per_db,
            "total_users": total_users,
            "active_today": active_today,
            "blocked_users": blocked_users,
            "total_tests": total_tests,
            "total_logs": total_logs,
            "total_admin_tokens": len(self.get_all_admin_tokens()),
            "active_notices": len(self.get_active_notices()),
            "open_reports": open_reports,
            "error_logs_count": error_cnt,
            "settings": settings,
            "updated_at": now_ist_str()
        }

    def get_all_users_paginated(self, page=1, per_page=10, query="", filter_mode="all"):
        all_users = []
        q = str(query or "").strip().lower()
        today = today_ist_str()

        for entry in self.dbs:
            try:
                for u in entry["db"].users.find():
                    d = clean_doc(u)
                    if filter_mode == "blocked" and not d.get("is_blocked"):
                        continue
                    if filter_mode == "active" and d.get("last_active_date") != today:
                        continue
                    if q:
                        hay = " ".join([
                            str(d.get("user_id", "")),
                            str(d.get("name", "")),
                            str(d.get("phone", "")),
                            str(d.get("email", "")),
                            str(d.get("username", "")),
                            str(d.get("state_district", ""))
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
        user = clean_doc(db.users.find_one({"user_id": uid}))
        sync = clean_doc(db.user_sync.find_one({"user_id": uid})) or {}
        tests = [clean_doc(t) for t in db.test_attempts.find({"user_id": uid}).sort("ts", DESCENDING).limit(25)]
        logs = [clean_doc(l) for l in db.activity_logs.find({"user_id": uid}).sort("ts", DESCENDING).limit(40)]
        return {
            "shard": entry["label"],
            "user": user,
            "sync": sync,
            "tests": tests,
            "logs": logs
        }

    def get_recent_global_activities(self, limit=35):
        merged = []
        for entry in self.dbs:
            try:
                docs = list(entry["db"].activity_logs.find().sort("ts", DESCENDING).limit(limit))
                merged.extend([clean_doc(d) for d in docs])
            except Exception:
                continue
        merged.sort(key=lambda x: x.get("ts", 0), reverse=True)
        return merged[:limit]

    def export_full_backup(self):
        backup = {"exported_at": now_ist_str(), "shards": {}}
        for entry in self.dbs:
            db = entry["db"]
            try:
                backup["shards"][entry["label"]] = {
                    "users": [clean_doc(d) for d in db.users.find()],
                    "user_sync": [clean_doc(d) for d in db.user_sync.find()],
                    "test_attempts": [clean_doc(d) for d in db.test_attempts.find()],
                    "admin_tokens": [clean_doc(d) for d in db.admin_tokens.find()],
                    "notices": [clean_doc(d) for d in db.notices.find()],
                    "reports": [clean_doc(d) for d in db.reports.find()],
                    "error_logs": [clean_doc(d) for d in db.error_logs.find().sort("ts", DESCENDING).limit(200)],
                    "settings": [clean_doc(d) for d in db.settings.find()],
                    "activity_logs_recent": [
                        clean_doc(d) for d in db.activity_logs.find().sort("ts", DESCENDING).limit(500)
                    ]
                }
            except Exception as e:
                backup["shards"][entry["label"]] = {"error": str(e)}
        return backup


db_manager = MultiMongoManager()
