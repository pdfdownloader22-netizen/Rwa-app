import hashlib
import json
import threading
import time
from datetime import datetime, timezone, timedelta
from pymongo import MongoClient, DESCENDING
import config

IST = timezone(timedelta(hours=5, minutes=30))


def _now_ist_str():
    return datetime.now(IST).strftime("%d-%m-%Y %I:%M:%S %p")


def _clean_doc(doc):
    if not doc:
        return doc
    d = dict(doc)
    if "_id" in d:
        d["_id"] = str(d["_id"])
    return d


# =========================================================
# THREAD-SAFE IN-MEMORY RAM CACHE (HIGH-TRAFFIC ANTI-CRASH)
# =========================================================
class ThreadSafeTTLCache:
    def __init__(self, max_items=600):
        self._store = {}
        self._lock = threading.RLock()
        self._max_items = max_items
        self.hits = 0
        self.misses = 0

    def get(self, key):
        now = time.time()
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                self.misses += 1
                return None
            exp, val = entry
            if now > exp:
                self._store.pop(key, None)
                self.misses += 1
                return None
            self.hits += 1
            return val

    def set(self, key, val, ttl_sec=60):
        now = time.time()
        with self._lock:
            if len(self._store) >= self._max_items:
                expired_keys = [k for k, (e, _) in self._store.items() if now > e]
                for k in expired_keys:
                    self._store.pop(k, None)
                if len(self._store) >= self._max_items:
                    oldest_key = min(self._store.items(), key=lambda item: item[1][0])[0]
                    self._store.pop(oldest_key, None)
            self._store[key] = (now + ttl_sec, val)

    def invalidate_prefix(self, prefix):
        with self._lock:
            for k in list(self._store.keys()):
                if str(k).startswith(prefix):
                    self._store.pop(k, None)

    def clear_all(self):
        with self._lock:
            cnt = len(self._store)
            self._store.clear()
            return cnt

    def stats(self):
        with self._lock:
            return {
                "cached_keys": len(self._store),
                "hits": self.hits,
                "misses": self.misses
            }


ram_cache = ThreadSafeTTLCache(max_items=800)


# =========================================================
# UNLIMITED CONTENT MONGODB VAULT MANAGER (ZERO DUPLICATES)
# =========================================================
class ContentVaultManager:
    def __init__(self):
        self.dbs = []
        self.connection_errors = []
        self.using_dedicated = False
        self._connect_all()

    def _connect_all(self):
        self.connection_errors = []
        for idx, uri in enumerate(config.CONTENT_MONGO_URIS, start=1):
            if not uri:
                continue
            try:
                client = MongoClient(
                    uri,
                    maxPoolSize=50,
                    minPoolSize=2,
                    serverSelectionTimeoutMS=10000,
                    connectTimeoutMS=10000,
                    socketTimeoutMS=15000,
                    retryWrites=True,
                    tls=True,
                    tlsAllowInvalidCertificates=True
                )
                client.admin.command("ping")
                db = client[config.CONTENT_DB_NAME]
                self._ensure_indexes(db)
                self.dbs.append({
                    "index": idx,
                    "label": f"VAULT-DB-{idx}",
                    "client": client,
                    "db": db,
                })
                self.using_dedicated = True
                print(f"✅ Connected to Content Vault MongoDB VAULT-DB-{idx}")
            except Exception as e:
                err_msg = f"VAULT-DB-{idx}: {e}"
                self.connection_errors.append(err_msg)
                print(f"❌ Failed connecting Content Vault {err_msg}")

    def attach_fallback_dbs(self, user_dbs):
        """
        Agar user ne abhi tak alag CONTENT_MONGO_URI set nahi kiya hai,
        toh existing cluster fallback ke roop mein kaam karega taaki kuch crash na ho.
        """
        if self.dbs or not user_dbs:
            return
        for entry in user_dbs:
            try:
                self._ensure_indexes(entry["db"])
                self.dbs.append({
                    "index": entry["index"],
                    "label": f"SHARED-{entry['label']}",
                    "client": entry["client"],
                    "db": entry["db"]
                })
            except Exception:
                continue
        if self.dbs:
            print("ℹ️ Content Vault running in fallback shared-shard mode until CONTENT_MONGO_URI is added.")

    def _ensure_indexes(self, db):
        try:
            db.vault_series.create_index("series_id", unique=True)
            db.vault_folders.create_index([("series_id", 1), ("subject_id", 1)], unique=True)
            db.vault_test_titles.create_index("test_id", unique=True)
            db.vault_test_titles.create_index([("series_id", 1), ("subject_id", 1)])
            db.vault_test_data.create_index("test_id", unique=True)
            db.vault_test_data.create_index("series_id")
        except Exception:
            pass

    def get_primary_db(self):
        return self.dbs[0] if self.dbs else None

    def get_db_size_mb(self, db_entry):
        try:
            stats = db_entry["db"].command("dbStats")
            used_bytes = stats.get("dataSize", 0) + stats.get("indexSize", 0)
            return round(used_bytes / (1024 * 1024), 2)
        except Exception:
            return 0.0

    def pick_best_shard(self):
        if not self.dbs:
            return None
        best = self.dbs[0]
        min_mb = float("inf")
        for entry in self.dbs:
            mb = self.get_db_size_mb(entry)
            if mb < config.MAX_CONTENT_DB_SIZE_MB:
                return entry
            if mb < min_mb:
                min_mb = mb
                best = entry
        return best

    def _find_test_data_shard(self, test_id):
        tid = str(test_id).strip()
        for entry in self.dbs:
            try:
                if entry["db"].vault_test_data.find_one({"test_id": tid}, {"_id": 1}):
                    return entry
            except Exception:
                continue
        return None

    @staticmethod
    def _compute_content_hash(sections, questions):
        raw = json.dumps(
            {"sections": sections or [], "questions": questions or []},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    # ---------------------------------------------------------
    # 1. TEST SERIES CATALOG (ZERO DUPLICATES)
    # ---------------------------------------------------------
    def upsert_series_batch(self, series_list):
        primary = self.get_primary_db()
        if not primary or not isinstance(series_list, list) or not series_list:
            return 0
        db = primary["db"]
        now_str = _now_ist_str()
        now_ts = int(time.time())
        saved = 0

        for item in series_list:
            if not isinstance(item, dict):
                continue
            sid = str(item.get("id") or item.get("series_id") or "").strip()
            if not sid:
                continue
            title = str(item.get("title") or f"Test Series #{sid}").strip()
            doc = {
                "series_id": sid,
                "id": sid,
                "title": title,
                "logo": str(item.get("logo") or "").replace("\\/", "/"),
                "offer_price": item.get("offer_price", 0),
                "freetest": str(item.get("freetest") or "0"),
                "paidtest": str(item.get("paidtest") or item.get("total_tests") or item.get("test_count") or "0"),
                "updated_at": now_str,
                "ts": now_ts
            }
            try:
                db.vault_series.update_one(
                    {"series_id": sid},
                    {"$set": doc, "$setOnInsert": {"first_saved_at": now_str}},
                    upsert=True
                )
                saved += 1
            except Exception:
                continue

        if saved > 0:
            ram_cache.invalidate_prefix("vault_series")
            ram_cache.invalidate_prefix("vault_summary")
        return saved

    def get_all_series(self):
        cached = ram_cache.get("vault_series:all")
        if cached is not None:
            return cached
        primary = self.get_primary_db()
        if not primary:
            return []
        try:
            docs = [_clean_doc(d) for d in primary["db"].vault_series.find().sort("ts", DESCENDING)]
            # Attach saved tests count per series
            counts_map = {}
            full_map = {}
            for t in primary["db"].vault_test_titles.find({}, {"series_id": 1, "has_full_bank": 1}):
                s = str(t.get("series_id") or "")
                counts_map[s] = counts_map.get(s, 0) + 1
                if t.get("has_full_bank"):
                    full_map[s] = full_map.get(s, 0) + 1
            for d in docs:
                sid = str(d.get("series_id") or d.get("id") or "")
                d["saved_tests_count"] = counts_map.get(sid, 0)
                d["saved_full_banks"] = full_map.get(sid, 0)
            ram_cache.set("vault_series:all", docs, ttl_sec=60)
            return docs
        except Exception:
            return []

    # ---------------------------------------------------------
    # 2. SERIES FOLDERS / SUBJECTS (ZERO DUPLICATES)
    # ---------------------------------------------------------
    def upsert_folders_batch(self, series_id, folders_list):
        primary = self.get_primary_db()
        sid = str(series_id or "").strip()
        if not primary or not sid or not isinstance(folders_list, list):
            return 0
        db = primary["db"]
        now_str = _now_ist_str()
        now_ts = int(time.time())
        saved = 0

        for f in folders_list:
            if not isinstance(f, dict):
                continue
            sub_id = str(f.get("subjectid") or f.get("subject_id") or f.get("id") or "").strip()
            if not sub_id:
                continue
            doc = {
                "series_id": sid,
                "subject_id": sub_id,
                "subjectid": sub_id,
                "subject_name": str(f.get("subject_name") or f.get("name") or f"Folder #{sub_id}").strip(),
                "subject_logo": str(f.get("subject_logo") or "").replace("\\/", "/"),
                "updated_at": now_str,
                "ts": now_ts
            }
            try:
                db.vault_folders.update_one(
                    {"series_id": sid, "subject_id": sub_id},
                    {"$set": doc, "$setOnInsert": {"first_saved_at": now_str}},
                    upsert=True
                )
                saved += 1
            except Exception:
                continue

        if saved > 0:
            ram_cache.invalidate_prefix(f"vault_folders:{sid}")
            ram_cache.invalidate_prefix("vault_summary")
        return saved

    def get_series_folders(self, series_id):
        sid = str(series_id or "").strip()
        cache_key = f"vault_folders:{sid}"
        cached = ram_cache.get(cache_key)
        if cached is not None:
            return cached
        primary = self.get_primary_db()
        if not primary or not sid:
            return []
        try:
            docs = [_clean_doc(d) for d in primary["db"].vault_folders.find({"series_id": sid}).sort("ts", 1)]
            ram_cache.set(cache_key, docs, ttl_sec=60)
            return docs
        except Exception:
            return []

    # ---------------------------------------------------------
    # 3. TEST TITLES LIST (ZERO DUPLICATES)
    # ---------------------------------------------------------
    def upsert_test_titles_batch(self, series_id, subject_id, tests_list):
        primary = self.get_primary_db()
        sid = str(series_id or "").strip()
        sub_id = str(subject_id or "-1").strip()
        if not primary or not isinstance(tests_list, list):
            return 0
        db = primary["db"]
        now_str = _now_ist_str()
        now_ts = int(time.time())
        saved = 0

        for t in tests_list:
            if not isinstance(t, dict):
                continue
            tid = str(t.get("id") or t.get("test_id") or "").strip()
            if not tid:
                continue
            doc = {
                "test_id": tid,
                "id": tid,
                "series_id": sid or str(t.get("test_series_id") or t.get("seriesId") or ""),
                "test_series_id": sid or str(t.get("test_series_id") or t.get("seriesId") or ""),
                "subject_id": sub_id,
                "title": str(t.get("title") or f"Mock Test #{tid}").strip(),
                "time": str(t.get("time") or "60"),
                "questions": str(t.get("questions") or "0"),
                "marks": str(t.get("marks") or "100"),
                "restrict_part_switching": str(t.get("restrict_part_switching") or "0"),
                "show_sectionselector": str(t.get("show_sectionselector") or "0"),
                "pdf_url": str(t.get("resolvedPdf") or t.get("pdf_url") or ""),
                "test_questions_url": str(t.get("test_questions_url") or t.get("questions_url") or ""),
                "updated_at": now_str,
                "ts": now_ts
            }
            try:
                db.vault_test_titles.update_one(
                    {"test_id": tid},
                    {
                        "$set": doc,
                        "$setOnInsert": {
                            "has_full_bank": False,
                            "saved_questions_count": 0,
                            "first_saved_at": now_str
                        }
                    },
                    upsert=True
                )
                saved += 1
            except Exception:
                continue

        if saved > 0:
            ram_cache.invalidate_prefix(f"vault_titles:{sid}")
            ram_cache.invalidate_prefix("vault_summary")
        return saved

    def get_test_titles(self, series_id, subject_id="-1"):
        sid = str(series_id or "").strip()
        sub_id = str(subject_id or "-1").strip()
        cache_key = f"vault_titles:{sid}:{sub_id}"
        cached = ram_cache.get(cache_key)
        if cached is not None:
            return cached
        primary = self.get_primary_db()
        if not primary or not sid:
            return []
        try:
            q = {"series_id": sid}
            if sub_id and sub_id != "-1":
                q["subject_id"] = sub_id
            docs = [_clean_doc(d) for d in primary["db"].vault_test_titles.find(q).sort("ts", 1)]
            ram_cache.set(cache_key, docs, ttl_sec=60)
            return docs
        except Exception:
            return []

    # ---------------------------------------------------------
    # 4. FULL TEST TERMS + QUESTIONS VAULT (AUTO-SHARDED, ZERO DUPLICATES)
    # ---------------------------------------------------------
    def save_full_test_payload(self, payload):
        tid = str(payload.get("test_id") or "").strip()
        questions = payload.get("questions") or []
        if not tid or not isinstance(questions, list) or len(questions) == 0:
            return {"saved": False, "reason": "invalid_payload"}

        sections = payload.get("sections") or []
        terms_meta = payload.get("terms_meta") or {}
        page_props_meta = payload.get("page_props_meta") or {}
        series_id = str(payload.get("series_id") or terms_meta.get("test_series_id") or "").strip()
        subject_id = str(payload.get("subject_id") or "-1").strip()
        title = str(payload.get("title") or terms_meta.get("title") or f"Test #{tid}").strip()

        new_hash = self._compute_content_hash(sections, questions)
        existing_shard = self._find_test_data_shard(tid)

        if existing_shard:
            existing_doc = existing_shard["db"].vault_test_data.find_one({"test_id": tid}, {"content_hash": 1})
            if existing_doc and existing_doc.get("content_hash") == new_hash:
                # Exact same updated JSON already saved -> ZERO duplicate write!
                return {"saved": True, "dedup_skipped": True, "shard": existing_shard["label"], "questions_count": len(questions)}
            target_shard = existing_shard
        else:
            target_shard = self.pick_best_shard()

        if not target_shard:
            return {"saved": False, "reason": "no_vault_db"}

        now_str = _now_ist_str()
        now_ts = int(time.time())
        doc = {
            "test_id": tid,
            "series_id": series_id,
            "subject_id": subject_id,
            "title": title,
            "terms_meta": terms_meta,
            "page_props_meta": page_props_meta,
            "sections": sections,
            "questions": questions,
            "questions_count": len(questions),
            "sections_count": len(sections),
            "content_hash": new_hash,
            "vault_shard": target_shard["label"],
            "updated_at": now_str,
            "ts": now_ts
        }

        try:
            target_shard["db"].vault_test_data.update_one(
                {"test_id": tid},
                {"$set": doc, "$setOnInsert": {"first_saved_at": now_str}},
                upsert=True
            )

            # Also keep catalog index updated on primary vault DB
            primary = self.get_primary_db()
            if primary:
                primary["db"].vault_test_titles.update_one(
                    {"test_id": tid},
                    {
                        "$set": {
                            "test_id": tid,
                            "id": tid,
                            "series_id": series_id,
                            "test_series_id": series_id,
                            "subject_id": subject_id,
                            "title": title,
                            "time": str(terms_meta.get("time") or "60"),
                            "questions": str(len(questions)),
                            "marks": str(terms_meta.get("marks") or (len(questions) * 2)),
                            "has_full_bank": True,
                            "saved_questions_count": len(questions),
                            "vault_shard": target_shard["label"],
                            "updated_at": now_str,
                            "ts": now_ts
                        }
                    },
                    upsert=True
                )

            ram_cache.invalidate_prefix(f"vault_test:{tid}")
            ram_cache.invalidate_prefix(f"vault_titles:{series_id}")
            ram_cache.invalidate_prefix("vault_series")
            ram_cache.invalidate_prefix("vault_summary")

            return {
                "saved": True,
                "dedup_skipped": False,
                "shard": target_shard["label"],
                "questions_count": len(questions)
            }
        except Exception as e:
            return {"saved": False, "reason": str(e)[:150]}

    def get_full_test_payload(self, test_id):
        tid = str(test_id or "").strip()
        if not tid:
            return None
        cache_key = f"vault_test:{tid}"
        cached = ram_cache.get(cache_key)
        if cached is not None:
            return cached

        for entry in self.dbs:
            try:
                doc = entry["db"].vault_test_data.find_one({"test_id": tid})
                if doc:
                    cleaned = _clean_doc(doc)
                    ram_cache.set(cache_key, cleaned, ttl_sec=300)
                    return cleaned
            except Exception:
                continue
        return None

    def delete_test_from_vault(self, test_id):
        tid = str(test_id or "").strip()
        if not tid:
            return False
        deleted = 0
        for entry in self.dbs:
            try:
                deleted += entry["db"].vault_test_data.delete_many({"test_id": tid}).deleted_count
                deleted += entry["db"].vault_test_titles.delete_many({"test_id": tid}).deleted_count
            except Exception:
                continue
        ram_cache.invalidate_prefix("vault_")
        return deleted > 0

    def delete_series_from_vault(self, series_id):
        sid = str(series_id or "").strip()
        if not sid:
            return False
        deleted = 0
        for entry in self.dbs:
            try:
                deleted += entry["db"].vault_series.delete_many({"series_id": sid}).deleted_count
                deleted += entry["db"].vault_folders.delete_many({"series_id": sid}).deleted_count
                deleted += entry["db"].vault_test_titles.delete_many({"series_id": sid}).deleted_count
                deleted += entry["db"].vault_test_data.delete_many({"series_id": sid}).deleted_count
            except Exception:
                continue
        ram_cache.invalidate_prefix("vault_")
        return deleted > 0

    # ---------------------------------------------------------
    # 5. DIRECT SUMMARY DASHBOARD FOR ADMIN PANEL
    # ---------------------------------------------------------
    def get_vault_summary(self):
        cached = ram_cache.get("vault_summary:main")
        if cached is not None:
            return cached

        primary = self.get_primary_db()
        total_series = 0
        total_folders = 0
        total_listed_tests = 0
        total_full_banks = 0
        total_questions_archived = 0
        per_shard = []

        if primary:
            try:
                total_series = primary["db"].vault_series.count_documents({})
                total_folders = primary["db"].vault_folders.count_documents({})
                total_listed_tests = primary["db"].vault_test_titles.count_documents({})
            except Exception:
                pass

        for entry in self.dbs:
            db = entry["db"]
            try:
                fb_cnt = db.vault_test_data.count_documents({})
                agg = list(db.vault_test_data.aggregate([
                    {"$group": {"_id": None, "total_q": {"$sum": "$questions_count"}}}
                ]))
                q_cnt = int(agg[0]["total_q"]) if agg else 0
                mb = self.get_db_size_mb(entry)
                total_full_banks += fb_cnt
                total_questions_archived += q_cnt
                per_shard.append({
                    "label": entry["label"],
                    "full_banks": fb_cnt,
                    "questions": q_cnt,
                    "size_mb": mb,
                    "max_mb": 512.0
                })
            except Exception:
                per_shard.append({"label": entry["label"], "error": True})

        summary = {
            "using_dedicated": self.using_dedicated,
            "connected_vault_dbs": len(self.dbs),
            "connection_errors": self.connection_errors,
            "total_series": total_series,
            "total_folders": total_folders,
            "total_listed_tests": total_listed_tests,
            "total_full_banks": total_full_banks,
            "total_questions_archived": total_questions_archived,
            "per_shard": per_shard,
            "ram_cache": ram_cache.stats(),
            "updated_at": _now_ist_str()
        }
        ram_cache.set("vault_summary:main", summary, ttl_sec=30)
        return summary


vault_manager = ContentVaultManager()
