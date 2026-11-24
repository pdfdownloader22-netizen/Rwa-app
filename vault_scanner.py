import base64
import json
import re
import threading
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import quote
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import config
from db_manager import db_manager
from vault_manager import vault_manager

IST = timezone(timedelta(hours=5, minutes=30))
APPX_AES_KEY = b"638udh3829162018"

RWA_HEADERS = {
    "Client-Service": "Appx",
    "Auth-Key": "appxapi",
    "source": "website",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36"
}


def _now_ist():
    return datetime.now(IST)


def _now_ist_str():
    return _now_ist().strftime("%d-%m-%Y %I:%M:%S %p")


def decrypt_appx_url(enc_str):
    if not enc_str or not isinstance(enc_str, str):
        return ""
    s = enc_str.strip()
    if s.startswith("http"):
        return s.replace("\\/", "/")
    if ":" not in s:
        return s.replace("\\/", "/")
    try:
        cipher_b64, iv_b64 = s.split(":", 1)
        ct = base64.b64decode(cipher_b64.replace("\\/", "/"))
        iv = base64.b64decode(iv_b64)
        cipher = Cipher(algorithms.AES(APPX_AES_KEY), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()
        cleaned = re.sub(r"[\x00-\x1F\x7F]", "", plain.decode("utf-8", errors="ignore")).strip()
        return cleaned.replace("\\/", "/")
    except Exception:
        return ""


class CloudVaultScanner:
    def __init__(self):
        self._lock = threading.RLock()
        self._thread = None
        self._stop_flag = False
        self.alert_callback = None
        self.next_build_id = "TDvVxPHlB8LGPavKJeaEV"
        self.state = self._make_idle_state()

    def _make_idle_state(self):
        return {
            "running": False,
            "status": "IDLE",  # IDLE | RUNNING | RETRYING | PAUSED_STORAGE_FULL | STOPPED | COMPLETED
            "mode": "none",    # nightly | manual
            "started_at": "",
            "finished_at": "",
            "current_phase": "Waiting for 11:00 PM IST or Admin trigger",
            "current_series": "",
            "current_test": "",
            "series_total": 0,
            "series_done": 0,
            "folders_found": 0,
            "tests_found": 0,
            "tests_newly_saved": 0,
            "tests_skipped_existing": 0,
            "errors_queued": 0,
            "retried_recovered": 0,
            "permanent_errors": 0,
            "progress_percent": 0,
            "last_message": "Idle",
            "logs": []
        }

    def _log(self, msg):
        line = f"[{_now_ist().strftime('%I:%M:%S %p')}] {msg}"
        with self._lock:
            self.state["last_message"] = msg
            self.state["logs"].insert(0, line)
            self.state["logs"] = self.state["logs"][:30]
        print(f"☁️ [VaultScanner] {msg}")

    def _notify_admin(self, text):
        if callable(self.alert_callback):
            try:
                self.alert_callback(text)
            except Exception:
                pass

    def get_status(self):
        with self._lock:
            return dict(self.state)

    def start_scan(self, mode="manual"):
        with self._lock:
            if self.state["running"]:
                return False, "Scan pehle se chal raha hai!"
            if not vault_manager.has_available_storage():
                self.state["status"] = "PAUSED_STORAGE_FULL"
                self.state["last_message"] = f"All Content Vault DBs reached {config.MAX_CONTENT_DB_SIZE_MB} MB limit! Add a new CONTENT_MONGO_URI_N."
                return False, self.state["last_message"]

            self._stop_flag = False
            self.state = self._make_idle_state()
            self.state["running"] = True
            self.state["status"] = "RUNNING"
            self.state["mode"] = mode
            self.state["started_at"] = _now_ist_str()
            self.state["current_phase"] = "Initializing..."

            self._thread = threading.Thread(target=self._run_scan_worker, args=(mode,), daemon=True)
            self._thread.start()
            return True, f"Cloud Vault {mode} scan started!"

    def stop_scan(self):
        with self._lock:
            if not self.state["running"]:
                return False, "Koi scan abhi nahi chal raha."
            self._stop_flag = True
            self.state["current_phase"] = "Stopping cleanly..."
            return True, "Stop signal bhej diya gaya hai."

    # ---------------------------------------------------------
    # UPSTREAM FETCH HELPERS (WITH TOKEN POOL + BUILD ID DISCOVERY)
    # ---------------------------------------------------------
    def _get_live_auth(self):
        tokens = db_manager.get_all_admin_tokens(for_admin=False)
        if tokens:
            t = tokens[0]
            return str(t.get("token") or ""), str(t.get("userId") or "2321546")
        return "", "2321546"

    def _refresh_next_build_id(self):
        try:
            r = requests.get("https://rojgarwithankit.co.in/", timeout=10, headers={"User-Agent": RWA_HEADERS["User-Agent"]})
            if r.ok:
                m = re.search(r'"buildId"\s*:\s*"([^"]+)"', r.text)
                if m and m.group(1):
                    self.next_build_id = m.group(1).strip()
        except Exception:
            pass

    def _fetch_rwa_api(self, endpoint, auth_token, uid):
        url = f"{config.RWA_UPSTREAM_API_URL}{endpoint}"
        headers = {**RWA_HEADERS, "User-ID": uid}
        if auth_token:
            headers["Authorization"] = auth_token
        try:
            r = requests.get(url, headers=headers, timeout=12)
            if r.ok:
                return r.json()
        except Exception:
            pass

        # Fallback via dedicated worker
        try:
            base_url_enc = quote(config.RWA_UPSTREAM_API_URL + "/", safe="")
            cookie_str = f"base_url={base_url_enc}; Authorization={auth_token}; User-ID={uid}"
            wurl = (
                f"{config.WORKER_PROXY_HEALTH_URL}?url={quote(url, safe='')}"
                f"&cookie={quote(cookie_str, safe='')}&token={quote(auth_token, safe='')}"
                f"&uid={quote(uid, safe='')}&base_url={base_url_enc}"
            )
            r = requests.get(wurl, timeout=15)
            if r.ok:
                return r.json()
        except Exception:
            pass
        return None

    def _fetch_terms_json(self, series_id, test_id, auth_token, uid):
        targets = [
            f"https://rojgarwithankit.co.in/_next/data/{self.next_build_id}/test-series/{series_id}/test-ssc/{test_id}/terms.json?id={series_id}&testId={test_id}",
            f"https://rojgarwithankit.co.in/_next/data/{self.next_build_id}/test-series/{series_id}/test-ssc/{test_id}/attempt.json?id={series_id}&testId={test_id}"
        ]
        base_url_enc = quote(config.RWA_UPSTREAM_API_URL + "/", safe="")
        cookie_str = f"base_url={base_url_enc}; Authorization={auth_token}; User-ID={uid}"

        for target in targets:
            # 1. Direct fetch with cookies
            try:
                r = requests.get(target, headers={"User-Agent": RWA_HEADERS["User-Agent"], "Cookie": cookie_str}, timeout=12)
                if r.ok:
                    j = r.json()
                    if isinstance(j, dict) and j.get("pageProps"):
                        return j
            except Exception:
                pass

            # 2. Dedicated worker fallback
            try:
                wurl = (
                    f"{config.WORKER_PROXY_HEALTH_URL}?url={quote(target, safe='')}"
                    f"&cookie={quote(cookie_str, safe='')}&token={quote(auth_token, safe='')}"
                    f"&uid={quote(uid, safe='')}&base_url={base_url_enc}"
                )
                r = requests.get(wurl, timeout=14)
                if r.ok:
                    j = r.json()
                    if isinstance(j, dict) and j.get("pageProps"):
                        return j
            except Exception:
                pass
        return None

    def _fetch_questions_json(self, q_url):
        if not q_url:
            return []
        for candidate in [q_url, f"{config.WORKER_RAW_PROXY_URL}{quote(q_url, safe='')}"]:
            try:
                r = requests.get(candidate, headers={"User-Agent": RWA_HEADERS["User-Agent"]}, timeout=15)
                if r.ok:
                    j = r.json()
                    if isinstance(j, list) and len(j) > 0:
                        return j
                    if isinstance(j, dict):
                        arr = j.get("data") or j.get("questions") or []
                        if isinstance(arr, list) and len(arr) > 0:
                            return arr
            except Exception:
                continue
        return []

    def _fetch_and_archive_single_test(self, series_id, subject_id, test_obj, auth_token, uid):
        tid = str(test_obj.get("id") or test_obj.get("test_id") or "").strip()
        title = str(test_obj.get("title") or f"Test #{tid}").strip()

        raw_terms = self._fetch_terms_json(series_id, tid, auth_token, uid)
        exact_meta = {}
        ordered_sections = []
        loaded_questions = []

        if raw_terms and isinstance(raw_terms.get("pageProps"), dict):
            pp = raw_terms["pageProps"]
            exact_meta = pp.get("test") or {}
            raw_secs = (
                pp.get("testSections")
                or pp.get("test_sections")
                or exact_meta.get("testSections")
                or exact_meta.get("test_sections")
                or []
            )
            for idx, sec in enumerate(raw_secs):
                if not isinstance(sec, dict):
                    continue
                sid = str(sec.get("section_id") or sec.get("id") or sec.get("subjectid") or (idx + 1)).strip()
                sname = str(sec.get("section_title") or sec.get("section_name") or sec.get("title") or f"Section {sid}").strip()
                ordered_sections.append({
                    "secId": sid,
                    "name": sname,
                    "partTitle": str(sec.get("part_title") or "").strip(),
                    "rawIsOptional": str(sec.get("is_optional") or "0") == "1",
                    "fixedTiming": float(sec.get("fixed_timing") or 0),
                    "cutoffScore": float(sec.get("cutoff_score") or 0),
                    "numberOfQuestions": int(sec.get("numberOfQuestions") or sec.get("no_of_questions") or 0),
                    "maximumMarks": float(sec.get("maximumMarks") or sec.get("max_marks") or 0),
                    "optGroup": sec.get("optional_group") or "A",
                    "orderIndex": idx
                })
                if isinstance(sec.get("questions"), list) and sec["questions"]:
                    for q in sec["questions"]:
                        loaded_questions.append({**q, "section_id": sid, "section_name": sname})

        if not loaded_questions:
            raw_q_field = (
                exact_meta.get("test_questions_url")
                or exact_meta.get("test_questions_url_2")
                or test_obj.get("test_questions_url")
                or test_obj.get("questions_url")
                or ""
            )
            q_url = decrypt_appx_url(str(raw_q_field))
            loaded_questions = self._fetch_questions_json(q_url)

        if not loaded_questions:
            return {"ok": False, "reason": "terms/questions fetch failed"}

        payload = {
            "test_id": tid,
            "series_id": str(series_id),
            "subject_id": str(subject_id),
            "title": exact_meta.get("title") or title,
            "terms_meta": {
                "title": exact_meta.get("title") or title,
                "time": str(exact_meta.get("time") or test_obj.get("time") or "60"),
                "marks": str(exact_meta.get("marks") or test_obj.get("marks") or ""),
                "restrict_part_switching": str(exact_meta.get("restrict_part_switching") or test_obj.get("restrict_part_switching") or "0"),
                "show_sectionselector": str(exact_meta.get("show_sectionselector") or test_obj.get("show_sectionselector") or "0"),
                "maximumsection": str(exact_meta.get("maximumsection") or ""),
                "minimumsection": str(exact_meta.get("minimumsection") or ""),
                "language": str(exact_meta.get("language") or ""),
                "pdf_url": decrypt_appx_url(str(exact_meta.get("pdf_url") or test_obj.get("pdf_url") or ""))
            },
            "page_props_meta": {"buildId": self.next_build_id},
            "sections": ordered_sections,
            "questions": loaded_questions
        }
        save_res = vault_manager.save_full_test_payload(payload)
        if save_res.get("storage_full"):
            return {"ok": False, "storage_full": True, "reason": save_res.get("reason")}
        if save_res.get("saved"):
            return {"ok": True, "dedup_skipped": save_res.get("dedup_skipped", False), "shard": save_res.get("shard", "")}
        return {"ok": False, "reason": save_res.get("reason", "save_error")}

    def _should_stop_for_window(self, mode):
        if self._stop_flag:
            return True
        # Nightly automatic run stops cleanly once 12:00 AM IST passes (hour != 23)
        if mode == "nightly" and _now_ist().hour != config.NIGHTLY_SCAN_START_HOUR_IST:
            return True
        return False

    # ---------------------------------------------------------
    # MAIN SCAN WORKER (DISCOVER NEW -> ARCHIVE -> RETRY FAILED)
    # ---------------------------------------------------------
    def _run_scan_worker(self, mode):
        failed_queue = []
        storage_full_hit = False

        try:
            self._log(f"Started {mode.upper()} Cloud Vault Scan...")
            auth_token, uid = self._get_live_auth()
            self._refresh_next_build_id()

            # 1. Fetch ALL Test Series pages dynamically (0, 10, 20, ...)
            with self._lock:
                self.state["current_phase"] = "Fetching Test Series Catalog..."
            all_series = []
            seen_sids = set()
            for start in range(0, 200, 10):
                if self._should_stop_for_window(mode):
                    break
                j = self._fetch_rwa_api(f"/get/test_series?start={start}&search=&client_api_url=&exam_id=", auth_token, uid)
                arr = (j.get("data") if isinstance(j, dict) else None) or []
                if not isinstance(arr, list) or len(arr) == 0:
                    break
                new_in_page = 0
                for s in arr:
                    sid = str(s.get("id") or "").strip()
                    if sid and sid not in seen_sids:
                        seen_sids.add(sid)
                        all_series.append(s)
                        new_in_page += 1
                if new_in_page == 0:
                    break
                time.sleep(0.25)

            if all_series:
                vault_manager.upsert_series_batch(all_series)

            with self._lock:
                self.state["series_total"] = len(all_series)
            self._log(f"Found {len(all_series)} Test Series. Scanning folders & new tests...")

            # 2. Loop through every Series -> Folders -> Tests
            for s_idx, series in enumerate(all_series, start=1):
                if self._should_stop_for_window(mode):
                    break
                if not vault_manager.has_available_storage():
                    storage_full_hit = True
                    break

                sid = str(series.get("id") or "").strip()
                stitle = str(series.get("title") or f"Series #{sid}").strip()
                with self._lock:
                    self.state["current_phase"] = f"Scanning Series {s_idx}/{len(all_series)}"
                    self.state["current_series"] = f"{stitle} (#{sid})"
                    self.state["series_done"] = s_idx - 1
                    self.state["progress_percent"] = int(((s_idx - 1) / max(1, len(all_series))) * 90)

                f_json = self._fetch_rwa_api(f"/get/testseries_subjects?testseries_id={sid}", auth_token, uid)
                folders = (f_json.get("data") if isinstance(f_json, dict) else None) or []
                if not isinstance(folders, list) or len(folders) == 0:
                    folders = [{"subjectid": "-1", "subject_name": stitle}]
                else:
                    vault_manager.upsert_folders_batch(sid, folders)
                    with self._lock:
                        self.state["folders_found"] += len(folders)

                for folder in folders:
                    if self._should_stop_for_window(mode) or storage_full_hit:
                        break
                    sub_id = str(folder.get("subjectid") or "-1").strip()
                    t_json = self._fetch_rwa_api(
                        f"/get/test_titlev2?testseriesid={sid}&subject_id={sub_id}&chapter_id=-1&userid={uid}&search=&start=-1",
                        auth_token, uid
                    )
                    tests = (
                        (t_json.get("data") if isinstance(t_json, dict) else None)
                        or (t_json.get("test_titles") if isinstance(t_json, dict) else None)
                        or []
                    )
                    if not isinstance(tests, list) or not tests:
                        continue

                    vault_manager.upsert_test_titles_batch(sid, sub_id, tests)
                    with self._lock:
                        self.state["tests_found"] += len(tests)

                    for t_obj in tests:
                        if self._should_stop_for_window(mode):
                            break
                        tid = str(t_obj.get("id") or "").strip()
                        ttitle = str(t_obj.get("title") or f"Test #{tid}").strip()
                        if not tid:
                            continue

                        # ZERO-DUPLICATE FAST SKIP: already saved in Vault!
                        if vault_manager.has_full_test(tid):
                            with self._lock:
                                self.state["tests_skipped_existing"] += 1
                            continue

                        # Check 450 MB hard cap BEFORE fetching
                        if not vault_manager.has_available_storage():
                            storage_full_hit = True
                            break

                        with self._lock:
                            self.state["current_test"] = f"{ttitle} (#{tid})"

                        res = self._fetch_and_archive_single_test(sid, sub_id, t_obj, auth_token, uid)
                        if res.get("storage_full"):
                            storage_full_hit = True
                            break
                        if res.get("ok"):
                            with self._lock:
                                if res.get("dedup_skipped"):
                                    self.state["tests_skipped_existing"] += 1
                                else:
                                    self.state["tests_newly_saved"] += 1
                            self._log(f"✅ Saved: {ttitle} (#{tid}) -> {res.get('shard')}")
                        else:
                            failed_queue.append((sid, sub_id, t_obj))
                            with self._lock:
                                self.state["errors_queued"] = len(failed_queue)
                            self._log(f"⚠️ Queued for retry: {ttitle} (#{tid}) ({res.get('reason')})")

                        time.sleep(0.35)

                with self._lock:
                    self.state["series_done"] = s_idx
                    self.state["progress_percent"] = int((s_idx / max(1, len(all_series))) * 90)

            # 3. END-OF-SCAN AUTOMATIC RETRY PASS FOR ALL FAILED TESTS
            if failed_queue and not storage_full_hit and not self._should_stop_for_window(mode):
                with self._lock:
                    self.state["status"] = "RETRYING"
                    self.state["current_phase"] = f"Retrying {len(failed_queue)} failed tests..."
                self._log(f"🔄 Starting Retry Pass for {len(failed_queue)} failed test(s)...")
                self._refresh_next_build_id()
                time.sleep(2.0)

                still_failed = 0
                for idx, (sid, sub_id, t_obj) in enumerate(failed_queue, start=1):
                    if self._should_stop_for_window(mode):
                        break
                    if not vault_manager.has_available_storage():
                        storage_full_hit = True
                        break
                    tid = str(t_obj.get("id") or "").strip()
                    ttitle = str(t_obj.get("title") or f"Test #{tid}").strip()
                    with self._lock:
                        self.state["current_test"] = f"[Retry {idx}/{len(failed_queue)}] {ttitle}"
                        self.state["progress_percent"] = 90 + int((idx / max(1, len(failed_queue))) * 10)

                    res = self._fetch_and_archive_single_test(sid, sub_id, t_obj, auth_token, uid)
                    if res.get("storage_full"):
                        storage_full_hit = True
                        break
                    if res.get("ok"):
                        with self._lock:
                            self.state["tests_newly_saved"] += 1
                            self.state["retried_recovered"] += 1
                        self._log(f"✅ Retry Success: {ttitle} (#{tid})")
                    else:
                        still_failed += 1
                        with self._lock:
                            self.state["permanent_errors"] = still_failed
                        self._log(f"❌ Retry Failed: {ttitle} (#{tid})")
                    time.sleep(0.6)

            # 4. FINALIZE STATUS
            with self._lock:
                self.state["running"] = False
                self.state["finished_at"] = _now_ist_str()
                if storage_full_hit:
                    self.state["status"] = "PAUSED_STORAGE_FULL"
                    self.state["current_phase"] = f"Paused: All Vault DBs hit {config.MAX_CONTENT_DB_SIZE_MB} MB limit!"
                    msg = (
                        f"🚨 <b>CONTENT VAULT 450 MB FULL!</b>\n"
                        f"Sabhi Content MongoDB shards {config.MAX_CONTENT_DB_SIZE_MB} MB tak bhar gaye hain.\n"
                        f"Scan ruk gaya hai — Render Environment mein naya <code>CONTENT_MONGO_URI_N</code> add karein!"
                    )
                    self._log("🛑 Paused: All Content Vault DBs reached 450 MB limit. Waiting for new DB URI.")
                    self._notify_admin(msg)
                elif self._stop_flag:
                    self.state["status"] = "STOPPED"
                    self.state["current_phase"] = "Stopped by Admin"
                    self._log("⏹ Scan stopped by Admin.")
                else:
                    self.state["status"] = "COMPLETED"
                    self.state["progress_percent"] = 100
                    saved_cnt = self.state["tests_newly_saved"]
                    if saved_cnt == 0:
                        self.state["current_phase"] = "Up-to-date! No new tests found — waiting for next cycle."
                        self._log("✅ Scan Complete: Koi naya test nahi mila. Waiting for next 11 PM or Admin button.")
                    else:
                        self.state["current_phase"] = f"Completed! {saved_cnt} new test(s) archived."
                        self._log(f"✅ Scan Complete: {saved_cnt} new tests saved, {self.state['retried_recovered']} recovered on retry.")
                        self._notify_admin(
                            f"☁️ <b>Cloud Vault {mode.upper()} Scan Complete</b>\n"
                            f"• New Tests Saved: <b>{saved_cnt}</b>\n"
                            f"• Already Saved (Skipped): <b>{self.state['tests_skipped_existing']}</b>\n"
                            f"• Retried & Recovered: <b>{self.state['retried_recovered']}</b>\n"
                            f"• Remaining Errors: <b>{self.state['permanent_errors']}</b>"
                        )

        except Exception as e:
            with self._lock:
                self.state["running"] = False
                self.state["status"] = "STOPPED"
                self.state["finished_at"] = _now_ist_str()
                self.state["current_phase"] = f"Error: {str(e)[:120]}"
            self._log(f"❌ Unexpected scanner error: {e}")


vault_scanner = CloudVaultScanner()
