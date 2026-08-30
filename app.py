# -*- coding: utf-8 -*-
"""نظام محاسبة المقاولات المتكامل - تطبيق الويب"""
from datetime import date, datetime, timedelta
from functools import wraps
import collections
import json
import os
import re
import sys
import threading
import time

from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for, flash)
from urllib.parse import urlsplit
from werkzeug.security import check_password_hash, generate_password_hash

import database as db
import excel_tools as xl
import pdf_tools as px

db.migrate()

ROLES = {"admin": "مدير النظام", "accountant": "محاسب", "viewer": "مشاهدة فقط"}
ENTRY_TYPES = ["عادي", "افتتاحي", "ترحيل", "تسوية", "إقفال"]

if getattr(sys, "frozen", False):
    _RES_DIR = sys._MEIPASS
else:
    _RES_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__,
            template_folder=os.path.join(_RES_DIR, "templates"),
            static_folder=os.path.join(_RES_DIR, "static"))
app.secret_key = db.load_secret()
app.permanent_session_lifetime = timedelta(hours=12)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    JSON_AS_ASCII=False,
    TEMPLATES_AUTO_RELOAD=True,
)
# عند الاستضافة عبر HTTPS (مثل PythonAnywhere) نفعّل تفعيل الكوكيز الآمن + HSTS
FORCE_HTTPS = db.get_setting("force_https", "0") == "1"
if FORCE_HTTPS:
    app.config["SESSION_COOKIE_SECURE"] = True

# ------------------------------------------------------------------
# أمان: معدل محاولات الدخول + ترويسات
# ------------------------------------------------------------------
_login_attempts = collections.defaultdict(lambda: collections.deque())
LOGIN_MAX = 5
LOGIN_WINDOW = 300


def _check_rate_limit(ip):
    now = time.time()
    attempts = _login_attempts[ip]
    while attempts and attempts[0] < now - LOGIN_WINDOW:
        attempts.popleft()
    return len(attempts) < LOGIN_MAX


def _record_login_attempt(ip):
    _login_attempts[ip].append(time.time())


@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'"
    )
    if FORCE_HTTPS:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # منع التخزين المؤقت لملفات التصدير حتى لا يعيد المتصفح ملفات قديمة
    # (مثلاً يفتح إكسل بدل PDF أو العكس) — كل تحميل ملف يعمل طلبًا جديدًا.
    if response.headers.get("Content-Disposition", "").startswith("attachment"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# ------------------------------------------------------------------
# حماية CSRF: نسمح فقط بالطلبات من نفس الموقع (Same-Origin)
# ------------------------------------------------------------------
def _is_same_origin():
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    if origin:
        return urlsplit(origin).netloc.lower() == request.host.lower()
    if referer:
        return urlsplit(referer).netloc.lower() == request.host.lower()
    # بدون Origin أو Referer (أدوات سطر الأوامر/الاختبارات) يُسمح
    return True


# ------------------------------------------------------------------
# وضع القفل للاستضافة: مستخدم واحد فقط + تعطيل الإعدادات والمستخدمين
# ------------------------------------------------------------------
LOCKDOWN_ENDPOINTS = {"settings", "reset_all_data", "users", "users_new",
                      "users_role", "users_password", "users_delete"}


def _lockdown_on():
    return db.get_setting("security_lockdown", "0") == "1"


def _lockdown_username():
    return db.get_setting("lockdown_username", "admin")


def _sanitize(value):
    if not isinstance(value, str):
        return value
    value = value.strip()
    value = re.sub(r'<script[^>]*>.*?</script>', '', value, flags=re.IGNORECASE | re.DOTALL)
    value = re.sub(r'on\w+\s*=', '', value, flags=re.IGNORECASE)
    return value


@app.context_processor
def _inject_globals():
    u = getattr(g, "user", None) or {}
    return {
        "user": u,
        "company_name": db.get_setting("company_name", "شركة المقاولات"),
        "role_name": ROLES.get(u.get("role", ""), ""),
        "lockdown": _lockdown_on(),
        "get_setting": db.get_setting,
    }


@app.before_request
def before():
    # حماية CSRF: رفض أي طلب تغيير state من مصدر خارجي
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not _is_same_origin():
            if request.path.startswith("/api/"):
                return jsonify(error="طلب من مصدر غير مصرّح به"), 403
            flash("تم رفض الطلب: مصدر غير مصرّح به", "err")
            return redirect("/")
    allowed = {"login", "static"}
    if request.endpoint in allowed:
        return None
    uid = session.get("uid")
    g.user = db.query_one("SELECT * FROM users WHERE id=?", (uid,)) if uid else None
    if g.user is None:
        if request.path.startswith("/api/"):
            return jsonify(error="انتهت الجلسة، يرجى تسجيل الدخول"), 401
        return redirect(url_for("login"))
    # وضع القفل: تعطيل صفحة الإعدادات وإدارة المستخدمين (حتى للمدير)
    if _lockdown_on() and request.endpoint in LOCKDOWN_ENDPOINTS:
        flash("الإعدادات وإدارة المستخدمين مقفلة على هذه النسخة — تواصل مع المزوّد لضبطها.", "err")
        return redirect("/")
    try:
        db.auto_monthly_backup()
    except Exception:
        pass
    return None


def can_write():
    return g.user["role"] in ("admin", "accountant")


def can_admin():
    return g.user["role"] == "admin"


def require_write(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not can_write():
            if request.path.startswith("/api/"):
                return jsonify(error="ليست لديك صلاحية الإضافة أو التعديل"), 403
            flash("ليست لديك صلاحية القيام بهذه العملية", "err")
            return redirect(request.referrer or "/")
        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not can_admin():
            if request.path.startswith("/api/"):
                return jsonify(error="هذه العملية للمدير فقط"), 403
            flash("هذه العملية للمدير فقط", "err")
            return redirect(request.referrer or "/")
        return f(*args, **kwargs)
    return wrapper


# ------------------------------------------------------------------
# الدخول والخروج
# ------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "0.0.0.0"
        if not _check_rate_limit(ip):
            error = "محاولات كثيرة، يرجى الانتظار 5 دقائق"
        else:
            username = _sanitize(request.form.get("username", ""))
            password = request.form.get("password", "")
            user = db.query_one("SELECT * FROM users WHERE username=?", (username,))
            if _lockdown_on() and username != _lockdown_username():
                # في وضع القفل يُسمح بحساب واحد فقط
                _record_login_attempt(ip)
                error = "الحساب غير مفعّل — تم تفعيل حساب واحد فقط على هذه النسخة"
            elif user and check_password_hash(user["password_hash"], password):
                session.clear()
                session.permanent = True
                session["uid"] = user["id"]
                db.audit(user["username"], "دخول", "تسجيل دخول ناجح")
                return redirect(url_for("dashboard"))
            else:
                _record_login_attempt(ip)
                error = "اسم المستخدم أو كلمة المرور غير صحيحة"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    if hasattr(g, "user") and g.user:
        db.audit(g.user["username"], "خروج", "تسجيل خروج")
    session.clear()
    return redirect(url_for("login"))


# ------------------------------------------------------------------
# لوحة التحكم
# ------------------------------------------------------------------
@app.route("/")
def dashboard():
    projects = db.query("SELECT * FROM projects ORDER BY id DESC")

    total_contracts = 0
    total_costs = 0
    total_received = 0
    active = 0
    for p in projects:
        c = db.query_one("SELECT contract_value FROM contracts WHERE project_id=?", (p["id"],))
        cv = c["contract_value"] if c else 0
        tc = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM project_costs WHERE project_id=?", (p["id"],))
        tr = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM client_payments WHERE project_id=?", (p["id"],))
        total_contracts += cv or 0
        total_costs += tc["s"] or 0
        total_received += tr["s"] or 0
        if p["status"] in ("جاري", "تحضيري"):
            active += 1

    kpis = {
        "projects": len(projects),
        "active": active,
        "contracts": total_contracts,
        "costs": total_costs,
        "received": total_received,
        "profit": total_contracts - total_costs,
    }

    # المشاريع مع بياناتها
    project_rows = []
    for p in projects:
        c = db.query_one("SELECT contract_value FROM contracts WHERE project_id=?", (p["id"],))
        cv = c["contract_value"] if c else 0
        tc = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM project_costs WHERE project_id=?", (p["id"],))
        tr = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM client_payments WHERE project_id=?", (p["id"],))
        tc = tc["s"] or 0
        tr = tr["s"] or 0
        progress = round((tc / cv * 100), 1) if cv else 0
        budget = db.query_one("SELECT COALESCE(SUM(total),0) s FROM budget_items WHERE project_id=?",
                              (p["id"],))["s"] or 0
        project_rows.append({**p, "contract_value": cv or 0, "total_cost": tc, "received": tr,
                             "profit": (cv or 0) - tc, "progress": progress, "budget": budget})

    # ===== التنبيهات الذكية =====
    alerts = []

    due_inv = db.query("SELECT COUNT(*) c FROM supplier_invoices WHERE paid=0 AND amount>0")
    if due_inv and due_inv[0]["c"]:
        alerts.append(("invoice", f"لديك {due_inv[0]['c']} فاتورة مورد غير مسددة"))

    overdue = db.query("SELECT COUNT(*) c FROM supplier_invoices WHERE paid=0 AND amount>0 "
                       "AND due_date != '' AND due_date < ?", (date.today().isoformat(),))
    if overdue and overdue[0]["c"]:
        alerts.append(("invoice", f"{overdue[0]['c']} فاتورة مورد متأخرة تاريخ استحقاقها — راجعها الآن"))

    due_today = db.query("SELECT COUNT(*) c FROM supplier_invoices WHERE paid=0 AND amount>0 "
                         "AND due_date = ?", (date.today().isoformat(),))
    if due_today and due_today[0]["c"]:
        alerts.append(("invoice", f"{due_today[0]['c']} فاتورة مورد تستحق اليوم"))

    low_stock = db.query("SELECT m.name, m.unit, COALESCE(SUM(sm.quantity),0) q "
                         "FROM materials m LEFT JOIN stock_movements sm ON sm.material_id=m.id "
                         "WHERE m.min_stock > 0 GROUP BY m.id HAVING q < m.min_stock")
    for m in low_stock[:5]:
        alerts.append(("stock", f"المخزون منخفض: {m['name']} ({m['q']:g} {m['unit'] or ''}) دون الحد الأدنى"))

    today = datetime.now().date().isoformat()
    overdue = db.query("SELECT id, name, end_date FROM projects "
                       "WHERE status NOT IN ('مكتمل','ملغي') AND end_date <> '' AND end_date < ?",
                       (today,))
    for p in overdue:
        alerts.append(("project", f"مشروع \"{p['name']}\" تجاوز تاريخ الانتهاء ({p['end_date']})"))

    soon = db.query("SELECT id, name, end_date FROM projects "
                    "WHERE status NOT IN ('مكتمل','ملغي') AND end_date <> '' AND end_date >= ? AND end_date <= ?",
                    (today, (datetime.now() + timedelta(days=30)).date().isoformat()))
    for p in soon:
        alerts.append(("project", f"مشروع \"{p['name']}\" يقترب من تاريخ الانتهاء ({p['end_date']})"))

    ret_due = db.query("SELECT p.id, p.name, c.retention_release_date, "
                       "COALESCE((SELECT SUM(i.retention_amount) FROM interim_payments i "
                       "WHERE i.project_id=p.id AND i.retention_release=0),0) r "
                       "FROM projects p LEFT JOIN contracts c ON c.project_id=p.id "
                       "WHERE c.retention_release_date <> '' AND c.retention_release_date < ?",
                       (today,))
    for p in ret_due:
        if p["r"] > 0:
            alerts.append(("retention", f"مشروع \"{p['name']}\": ضمان {p['r']:,.2f} مستحق التحرير"))

    for pr in project_rows:
        if pr["budget"] > 0 and pr["total_cost"] > pr["budget"]:
            alerts.append(("budget", f"مشروع \"{pr['name']}\" تجاوز ميزانيته التقديرية"))

    alerts = alerts[:12]

    return render_template("dashboard.html", kpis=kpis, projects=project_rows, alerts=alerts)


# ------------------------------------------------------------------
# المسارات المشتركة / API لعناصر القوائم المنسدلة
# ------------------------------------------------------------------


# ==================================================================
# السجلات الرئيسية (Generic CRUD عبر قالب موحّد)
# ==================================================================
# نعرّف المواصفات لكل جدول
REGISTRY = {
    "clients": ("العملاء", ["الاسم", "الشركة", "الهاتف", "البريد", "الرقم الضريبي"],
                ["name", "company", "phone", "email", "tax_no"],
                ["name", "company", "phone", "email", "address", "tax_no", "notes"], "🤝"),
    "suppliers": ("الموردون", ["الاسم", "الشركة", "الهاتف", "الرقم الضريبي", "شروط الدفع"],
                  ["name", "company", "phone", "tax_no", "payment_terms"],
                  ["name", "company", "phone", "email", "address", "tax_no", "payment_terms", "notes"], "🏭"),
    "subcontractors": ("مقاولو الباطن", ["الاسم", "التخصص", "الهاتف", "الرقم الضريبي"],
                       ["name", "trade", "phone", "tax_no"],
                       ["name", "phone", "email", "address", "trade", "tax_no", "payment_terms", "notes"], "🧑‍🏭"),
    "workers": ("العمالة", ["الاسم", "الوظيفة", "الهاتف", "أجر يومي", "راتب شهري", "الحالة"],
                ["name", "job", "phone", "daily_rate", "monthly_salary", "status"],
                ["name", "job", "phone", "daily_rate", "monthly_salary", "ssn", "status", "notes"], "👷"),
    "equipment": ("المعدات", ["الاسم", "رقم اللوحة", "الفئة", "تكلفة الشراء", "الحالة"],
                  ["name", "license_no", "category", "purchase_cost", "status"],
                  ["name", "license_no", "category", "purchase_cost", "depreciation_rate", "status", "site", "notes"], "🚜"),
    "materials": ("المواد والأصناف", ["الاسم", "الوحدة", "الفئة", "سعر التكلفة", "حد أدنى"],
                  ["name", "unit", "category", "cost_price", "min_stock"],
                  ["name", "unit", "category", "cost_price", "min_stock", "notes"], "🧱"),
}


@app.route("/<table>")
def registry_list(table):
    if table not in REGISTRY:
        abort(404)
    title, cols, colkeys, fields, icon = REGISTRY[table]
    items = db.query(f"SELECT * FROM {table} ORDER BY id DESC")
    return render_template("registry_list.html", table=table, title=title, cols=cols,
                           colkeys=colkeys, items=items, icon=icon, fields=fields)


@app.route("/<table>/new", methods=["GET", "POST"])
@require_write
def registry_new(table):
    if table not in REGISTRY:
        abort(404)
    title, cols, colkeys, fields, icon = REGISTRY[table]
    if request.method == "POST":
        data = {}
        for f in fields:
            data[f] = _sanitize(request.form.get(f, ""))
        cols_sql = ", ".join(data.keys())
        vals_sql = ", ".join("?" for _ in data)
        rid = db.execute(f"INSERT INTO {table} ({cols_sql}) VALUES ({vals_sql})",
                         tuple(data.values()))
        db.audit(g.user["username"], "إضافة", f"{title}: #{rid}")
        flash("تمت الإضافة بنجاح", "ok")
        return redirect(url_for("registry_list", table=table))
    return render_template("registry_form.html", table=table, title=title, fields=fields,
                           item={}, is_edit=False)


@app.route("/<table>/<int:rid>/edit", methods=["GET", "POST"])
@require_write
def registry_edit(table, rid):
    if table not in REGISTRY:
        abort(404)
    title, cols, colkeys, fields, icon = REGISTRY[table]
    item = db.query_one(f"SELECT * FROM {table} WHERE id=?", (rid,))
    if not item:
        abort(404)
    if request.method == "POST":
        data = {f: _sanitize(request.form.get(f, "")) for f in fields}
        sets = ", ".join(f"{k}=?" for k in data)
        db.execute(f"UPDATE {table} SET {sets} WHERE id=?", (*data.values(), rid))
        db.audit(g.user["username"], "تعديل", f"{title}: #{rid}")
        flash("تم التعديل بنجاح", "ok")
        return redirect(url_for("registry_list", table=table))
    return render_template("registry_form.html", table=table, title=title, fields=fields,
                           item=item, is_edit=True)


@app.route("/<table>/<int:rid>/delete", methods=["POST"])
@require_write
def registry_delete(table, rid):
    if table not in REGISTRY:
        abort(404)
    title = REGISTRY[table][0]
    db.execute(f"DELETE FROM {table} WHERE id=?", (rid,))
    db.audit(g.user["username"], "حذف", f"{title}: #{rid}")
    flash("تم الحذف", "ok")
    return redirect(url_for("registry_list", table=table))


# ------------------------------------------------------------------
# أدوات مشتركة
# ------------------------------------------------------------------
def _num(x):
    try:
        return float(x) if x not in ("", None) else 0.0
    except (ValueError, TypeError):
        return 0.0


def _gen_number(prefix, table, col="payment_no"):
    rows = db.query(f"SELECT {col} AS v FROM {table} WHERE {col} LIKE ?", (f"{prefix}-%",))
    mx = 0
    pfix = f"{prefix}-"
    for r in rows:
        s = str(r["v"] or "")
        if s.startswith(pfix):
            try:
                mx = max(mx, int(s[len(pfix):]))
            except ValueError:
                pass
    return f"{pfix}{mx + 1:04d}"


@app.context_processor
def _reg_utils():
    def status_class(s):
        return {"جاري": "status-jari", "مكتمل": "status-mukmal", "مؤجل": "status-mawquf",
                "ملغي": "status-mulghy", "تحضيري": "status-tajhizy"}.get(s, "")
    def gset(key, default=""):
        return db.get_setting(key, default)
    return {"status_class": status_class, "num": lambda n: f"{_num(n):,.2f}",
            "get_setting": gset, "can_write": can_write, "can_admin": can_admin}


# ==================================================================
# الترحيل التلقائي للدفاتر (العمليات ← قيود يومية متوازنة)
# ==================================================================
AUTO_CASH = "1101"   # الصندوق
AUTO_BANK = "1102"   # البنوك


def _acc_id(acc_no):
    a = db.query_one("SELECT id FROM accounts WHERE acc_no=?", (acc_no,))
    return a["id"] if a else None


def _purge_source(source_type, source_id):
    """حذف القيود المرتبطة بمصدر معين (لا يترك بنودًا يتيمة في الأستاذ)."""
    ids = [r["id"] for r in db.query(
        "SELECT id FROM journal_entries WHERE source_type=? AND source_id=?",
        (source_type, int(source_id or 0)))]
    if ids:
        marks = ",".join("?" for _ in ids)
        db.execute(f"DELETE FROM journal_lines WHERE entry_id IN ({marks})", tuple(ids))
        db.execute(f"DELETE FROM journal_entries WHERE id IN ({marks})", tuple(ids))


def _post_journal(prefix, desc, edate, lines, pid=None, source_type="", source_id=0, etype="ترحيل"):
    """ينشئ قيدًا متوازنًا تلقائيًا. lines = قائمة (acc_no, debit, credit).
    يرجع رسالة خطأ عند الفشل أو None عند النجاح."""
    if not edate:
        edate = datetime.now().strftime("%Y-%m-%d")
    final = []
    for acc_no, d, c in lines:
        aid = _acc_id(acc_no)
        if aid is None:
            return f"الحساب {acc_no} غير موجود في دليل الحسابات — تم الحفظ دون ترحيل"
        final.append((aid, _num(d), _num(c)))
    td = sum(x[1] for x in final)
    tc = sum(x[2] for x in final)
    if abs(td - tc) > 0.01:
        return f"القيد غير متوازن (مدين {td:,.2f} ≠ دائن {tc:,.2f}) — تم الحفظ دون ترحيل"
    mvno = db.next_number(prefix, "journal_entries", "movement_no")
    eid = db.execute(
        "INSERT INTO journal_entries (movement_no, entry_date, description, project_id, status, "
        "entry_type, created_by, source_type, source_id) VALUES (?,?,?,?,?,?,?,?,?)",
        (mvno, edate, desc, pid, "posted", etype, g.user["id"], source_type, int(source_id or 0)))
    for aid, d, c in final:
        db.execute("INSERT INTO journal_lines (entry_id, account_id, debit, credit) VALUES (?,?,?,?)",
                   (eid, aid, d, c))
    db.audit(g.user["username"], "ترحيل تلقائي", f"{desc} ({mvno})")
    return None


def _cost_account(cost_type):
    return {"مواد": "5101", "عمالة": "5102", "معدات": "5103",
            "مقاول باطن": "5104"}.get(cost_type, "5105")


# ==================================================================
# المشاريع
# ==================================================================
@app.route("/projects")
def projects():
    rows = db.query("SELECT * FROM projects ORDER BY id DESC")
    clients = {c["id"]: c["name"] for c in db.query("SELECT id,name FROM clients")}
    for p in rows:
        c = db.query_one("SELECT contract_value FROM contracts WHERE project_id=?", (p["id"],))
        tc = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM project_costs WHERE project_id=?", (p["id"],))
        tr = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM client_payments WHERE project_id=?", (p["id"],))
        cv = c["contract_value"] if c else 0
        p["client_name"] = clients.get(p["client_id"], "-")
        p["contract_value"] = cv or 0
        p["total_cost"] = tc["s"] or 0
        p["received"] = tr["s"] or 0
        p["profit"] = (cv or 0) - (tc["s"] or 0)
        p["progress"] = round((tc["s"] or 0) / cv * 100, 1) if cv else 0
    return render_template("projects.html", projects=rows,
                           clients=db.query("SELECT id,name FROM clients ORDER BY name"))


@app.route("/projects/new", methods=["GET", "POST"])
@require_write
def projects_new():
    if request.method == "POST":
        data = {
            "name": _sanitize(request.form.get("name", "")),
            "client_id": request.form.get("client_id") or None,
            "project_type": _sanitize(request.form.get("project_type", "مباني")),
            "location": _sanitize(request.form.get("location", "")),
            "engineer": _sanitize(request.form.get("engineer", "")),
            "supervisor": _sanitize(request.form.get("supervisor", "")),
            "start_date": _sanitize(request.form.get("start_date", "")),
            "end_date": _sanitize(request.form.get("end_date", "")),
            "status": _sanitize(request.form.get("status", "تحضيري")),
            "notes": _sanitize(request.form.get("notes", "")),
        }
        if not data["name"]:
            flash("اسم المشروع مطلوب", "err")
            return redirect(request.referrer or "/projects/new")
        pid = db.execute(
            "INSERT INTO projects (name, client_id, project_type, location, engineer, supervisor, "
            "start_date, end_date, status, notes) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (data["name"], data["client_id"], data["project_type"], data["location"],
             data["engineer"], data["supervisor"], data["start_date"], data["end_date"],
             data["status"], data["notes"]))
        db.audit(g.user["username"], "إضافة مشروع", f"#{pid} {data['name']}")
        flash("تم إنشاء المشروع", "ok")
        return redirect(url_for("project_view", pid=pid))
    return render_template("project_form.html", project={}, is_edit=False,
                           clients=db.query("SELECT id,name FROM clients ORDER BY name"))


@app.route("/projects/<int:pid>")
def project_view(pid):
    p = db.query_one("SELECT * FROM projects WHERE id=?", (pid,))
    if not p:
        abort(404)
    clients = {c["id"]: c["name"] for c in db.query("SELECT id,name FROM clients")}
    p["client_name"] = clients.get(p["client_id"], "-")
    contract = db.query_one("SELECT * FROM contracts WHERE project_id=?", (pid,))
    boq = db.query("SELECT * FROM boq_items WHERE project_id=? ORDER BY sort_order, id", (pid,))
    costs = db.query("SELECT * FROM project_costs WHERE project_id=? ORDER BY id DESC", (pid,))
    payments = db.query("SELECT * FROM interim_payments WHERE project_id=? ORDER BY id DESC", (pid,))
    receipts = db.query("SELECT * FROM client_payments WHERE project_id=? ORDER BY id DESC", (pid,))

    boq_total = sum(_num(b["total"]) for b in boq)
    cost_total = sum(_num(c["amount"]) for c in costs)
    received_total = sum(_num(r["amount"]) for r in receipts)
    contract_value = contract["contract_value"] if contract else 0

    budget = db.query("SELECT * FROM budget_items WHERE project_id=? ORDER BY sort_order, id", (pid,))
    budget_total = sum(_num(b["total"]) for b in budget)

    return render_template("project_view.html", p=p, contract=contract, boq=boq,
                           costs=costs, payments=payments, receipts=receipts,
                           boq_total=boq_total, cost_total=cost_total,
                           received_total=received_total, contract_value=contract_value,
                           profit=contract_value - cost_total,
                           progress=round(cost_total / contract_value * 100, 1) if contract_value else 0,
                           budget=budget, budget_total=budget_total)


@app.route("/projects/<int:pid>/edit", methods=["GET", "POST"])
@require_write
def project_edit(pid):
    p = db.query_one("SELECT * FROM projects WHERE id=?", (pid,))
    if not p:
        abort(404)
    if request.method == "POST":
        data = {
            "name": _sanitize(request.form.get("name", "")),
            "client_id": request.form.get("client_id") or None,
            "project_type": _sanitize(request.form.get("project_type", "مباني")),
            "location": _sanitize(request.form.get("location", "")),
            "engineer": _sanitize(request.form.get("engineer", "")),
            "supervisor": _sanitize(request.form.get("supervisor", "")),
            "start_date": _sanitize(request.form.get("start_date", "")),
            "end_date": _sanitize(request.form.get("end_date", "")),
            "status": _sanitize(request.form.get("status", "تحضيري")),
            "notes": _sanitize(request.form.get("notes", "")),
        }
        db.execute("UPDATE projects SET name=?, client_id=?, project_type=?, location=?, "
                   "engineer=?, supervisor=?, start_date=?, end_date=?, status=?, notes=? WHERE id=?",
                   (*list(data.values()), pid))
        db.audit(g.user["username"], "تعديل مشروع", f"#{pid}")
        flash("تم حفظ التعديلات", "ok")
        return redirect(url_for("project_view", pid=pid))
    return render_template("project_form.html", project=p, is_edit=True,
                           clients=db.query("SELECT id,name FROM clients ORDER BY name"))


@app.route("/projects/<int:pid>/delete", methods=["POST"])
@require_write
def project_delete(pid):
    name = db.query_one("SELECT name FROM projects WHERE id=?", (pid,))
    name = name["name"] if name else f"#{pid}"
    # الحذف الشجري: نمسح الجداول المرتبطة قبل المشروع (لكل الجداول التي تحتوي FK)
    db.execute("DELETE FROM journal_lines WHERE entry_id IN "
               "(SELECT id FROM journal_entries WHERE project_id=?)", (pid,))
    db.execute("DELETE FROM journal_entries WHERE project_id=?", (pid,))
    db.execute("DELETE FROM stock_movements WHERE project_id=?", (pid,))
    db.execute("DELETE FROM boq_items WHERE project_id=?", (pid,))
    db.execute("DELETE FROM interim_payments WHERE project_id=?", (pid,))
    db.execute("DELETE FROM client_payments WHERE project_id=?", (pid,))
    db.execute("DELETE FROM project_costs WHERE project_id=?", (pid,))
    db.execute("DELETE FROM contracts WHERE project_id=?", (pid,))
    db.execute("DELETE FROM projects WHERE id=?", (pid,))
    db.audit(g.user["username"], "حذف مشروع (شجري)", f"{name} #{pid}")
    flash(f"تم حذف المشروع «{name}» مع كامل متعلقاته (العقد، البنود، المستخلصات، الدفعات، التكاليف، المخزون، القيود)", "ok")
    return redirect(url_for("projects"))


# ==================================================================
# العقود
# ==================================================================
@app.route("/contracts")
def contracts():
    rows = db.query("SELECT * FROM contracts ORDER BY id DESC")
    projects = {p["id"]: {"name": p["name"], "client_name": ""} for p in db.query("SELECT id,name FROM projects")}
    clients = {c["id"]: c["name"] for c in db.query("SELECT id,name FROM clients")}
    projm = {p["id"]: p for p in db.query("SELECT * FROM projects")}
    for c in rows:
        pr = projm.get(c["project_id"])
        c["project_name"] = pr["name"] if pr else "-"
        c["client_name"] = clients.get(pr["client_id"], "-") if pr else "-"
    return render_template("contracts.html", contracts=rows,
                           projects=db.query("SELECT * FROM projects ORDER BY id DESC"))


@app.route("/projects/<int:pid>/contract/delete", methods=["POST"])
@require_admin
def contract_delete(pid):
    c = db.query_one("SELECT * FROM contracts WHERE project_id=?", (pid,))
    if not c:
        abort(404)
    confirm = _sanitize(request.form.get("confirm", ""))
    if confirm.lower() != "نعم":
        flash("لم يتم حذف العقد — يجب كتابة كلمة تأكيد", "err")
        return redirect(url_for("project_view", pid=pid))
    # حذف بنود الكميات المرتبطة بالعقد ثم العقد نفسه
    db.execute("DELETE FROM boq_items WHERE project_id=?", (pid,))
    db.execute("DELETE FROM contracts WHERE project_id=?", (pid,))
    db.audit(g.user["username"], "حذف عقد", f"مشروع #{pid} — {c.get('contract_no') or ''}")
    flash("تم حذف العقد وبنوده (إجراء نهائي لا يمكن التراجع)", "ok")
    return redirect(url_for("contracts"))


@app.route("/projects/<int:pid>/contract", methods=["GET", "POST"])
@require_write
def contract_edit(pid):
    p = db.query_one("SELECT * FROM projects WHERE id=?", (pid,))
    if not p:
        abort(404)
    c = db.query_one("SELECT * FROM contracts WHERE project_id=?", (pid,))
    if request.method == "POST":
        cv = _num(request.form.get("contract_value", 0))
        adv_pct = _num(request.form.get("advance_percent", 0))
        adv_amt = _num(request.form.get("advance_amount", 0)) or (cv * adv_pct / 100)
        ret_pct = _num(request.form.get("retention_percent",
                                        db.get_setting("contract_default_retention", "5")))
        ret_amt = _num(request.form.get("retention_amount", 0)) or (cv * ret_pct / 100)
        data = {
            "project_id": pid,
            "contract_no": _sanitize(request.form.get("contract_no", "")),
            "contract_date": _sanitize(request.form.get("contract_date", "")),
            "contract_value": cv,
            "advance_percent": adv_pct,
            "advance_amount": adv_amt,
            "retention_percent": ret_pct,
            "retention_amount": ret_amt,
            "retention_release_date": _sanitize(request.form.get("retention_release_date", "")),
            "duration_days": int(_num(request.form.get("duration_days", 0))),
            "terms": _sanitize(request.form.get("terms", "")),
        }
        if c:
            db.execute("UPDATE contracts SET contract_no=?, contract_date=?, contract_value=?, "
                       "advance_percent=?, advance_amount=?, retention_percent=?, retention_amount=?, "
                       "retention_release_date=?, duration_days=?, terms=? WHERE project_id=?",
                       (data["contract_no"], data["contract_date"], data["contract_value"],
                        data["advance_percent"], data["advance_amount"], data["retention_percent"],
                        data["retention_amount"], data["retention_release_date"],
                        data["duration_days"], data["terms"], pid))
        else:
            db.execute("INSERT INTO contracts (project_id, contract_no, contract_date, contract_value, "
                       "advance_percent, advance_amount, retention_percent, retention_amount, "
                       "retention_release_date, duration_days, terms) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                       (pid, data["contract_no"], data["contract_date"], data["contract_value"],
                        data["advance_percent"], data["advance_amount"], data["retention_percent"],
                        data["retention_amount"], data["retention_release_date"],
                        data["duration_days"], data["terms"]))
        db.audit(g.user["username"], "حفظ عقد", f"مشروع #{pid}")
        flash("تم حفظ العقد", "ok")
        return redirect(url_for("project_view", pid=pid))
    return render_template("contract_form.html", p=p, contract=c,
                           default_ret=db.get_setting("contract_default_retention", "5"))


# ------------------------------------------------------------------
# بنود الكميات (BoQ)
# ------------------------------------------------------------------
@app.route("/projects/<int:pid>/boq", methods=["POST"])
@require_write
def boq_add(pid):
    total = _num(request.form.get("quantity", 0)) * _num(request.form.get("unit_price", 0))
    db.execute("INSERT INTO boq_items (project_id, item_no, description, unit, quantity, unit_price, total, sort_order) "
               "VALUES (?,?,?,?,?,?,?,?)",
               (pid, _sanitize(request.form.get("item_no", "")),
                _sanitize(request.form.get("description", "")),
                _sanitize(request.form.get("unit", "")),
                _num(request.form.get("quantity", 0)),
                _num(request.form.get("unit_price", 0)), total,
                int(_num(request.form.get("sort_order", 0)))))
    db.audit(g.user["username"], "إضافة بند BoQ", f"مشروع #{pid}")
    flash("تمت إضافة البند", "ok")
    return redirect(url_for("project_view", pid=pid) + "#boq")


@app.route("/boq/<int:bid>/delete", methods=["POST"])
@require_write
def boq_delete(bid):
    b = db.query_one("SELECT project_id FROM boq_items WHERE id=?", (bid,))
    if b:
        db.execute("DELETE FROM boq_items WHERE id=?", (bid,))
        db.audit(g.user["username"], "حذف بند BoQ", f"#{bid}")
        flash("تم حذف البند", "ok")
        return redirect(url_for("project_view", pid=b["project_id"]) + "#boq")
    return redirect(url_for("projects"))


@app.route("/boq/<int:bid>/edit", methods=["POST"])
@require_write
def boq_edit(bid):
    b = db.query_one("SELECT * FROM boq_items WHERE id=?", (bid,))
    if not b:
        abort(404)
    qty = _num(request.form.get("quantity", b["quantity"]))
    up = _num(request.form.get("unit_price", b["unit_price"]))
    db.execute("UPDATE boq_items SET item_no=?, description=?, unit=?, quantity=?, unit_price=?, total=?, "
               "sort_order=? WHERE id=?",
               (_sanitize(request.form.get("item_no", b["item_no"])),
                _sanitize(request.form.get("description", b["description"])),
                _sanitize(request.form.get("unit", b["unit"])),
                qty, up, qty * up,
                int(_num(request.form.get("sort_order", b["sort_order"]))),
                bid))
    db.audit(g.user["username"], "تعديل بند BoQ", f"#{bid}")
    flash("تم تعديل البند", "ok")
    return redirect(url_for("project_view", pid=b["project_id"]) + "#boq")


# ==================================================================
# المستخلصات
# ==================================================================
@app.route("/interim")
def interim():
    rows = db.query("SELECT * FROM interim_payments ORDER BY id DESC")
    projm = {p["id"]: p["name"] for p in db.query("SELECT id,name FROM projects")}
    for r in rows:
        r["project_name"] = projm.get(r["project_id"], "-")
    # إجماليات
    total_work = sum(_num(r["work_value"]) for r in rows)
    total_net = sum(_num(r["net_payment"]) for r in rows)
    total_recv = sum(_num(r["actual_received"]) for r in rows)
    return render_template("interim.html", rows=rows, projm=projm,
                           total_work=total_work, total_net=total_net, total_recv=total_recv,
                           projects=db.query("SELECT * FROM projects ORDER BY id DESC"))


@app.route("/interim/new", methods=["GET", "POST"])
@require_write
def interim_new():
    projects = db.query("SELECT * FROM projects ORDER BY id DESC")
    pdata = {p["id"]: p for p in projects}
    if request.method == "POST":
        pid = int(request.form.get("project_id", 0))
        c = db.query_one("SELECT * FROM contracts WHERE project_id=?", (pid,))
        default_ret = c["retention_percent"] if c else _num(db.get_setting("contract_default_retention", "5"))
        pn = _sanitize(request.form.get("payment_no", "")) or _gen_number("مستخلص", "interim_payments")
        work_value = _num(request.form.get("work_value", 0))
        ret_pct = _num(request.form.get("retention_percent", default_ret))
        ret_amt = _num(request.form.get("retention_amount", 0)) or (work_value * ret_pct / 100)
        previous = sum(_num(r["net_payment"]) for r in db.query(
            "SELECT net_payment FROM interim_payments WHERE project_id=?", (pid,)))
        prior_work = sum(_num(r["work_value"]) for r in db.query(
            "SELECT work_value FROM interim_payments WHERE project_id=?", (pid,)))
        if c and prior_work + work_value > c["contract_value"]:
            flash("تحذير: تجاوزت قيمة الأعمال المنفذة سقف العقد!", "warn")
        net = work_value - ret_amt
        iid = db.execute("INSERT INTO interim_payments (project_id, payment_no, payment_date, description, "
                         "work_value, retention_percent, retention_amount, previous_payments, net_payment, "
                         "status, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                         (pid, pn, _sanitize(request.form.get("payment_date", "")),
                          _sanitize(request.form.get("description", "")),
                          work_value, ret_pct, ret_amt, previous, net,
                          _sanitize(request.form.get("status", "مقدم")),
                          _sanitize(request.form.get("notes", ""))))
        if request.form.get("auto_post") and work_value > 0:
            err = _post_journal("IN", f"مستخلص {pn}", _sanitize(request.form.get("payment_date", "")),
                                [("1201", net, 0), ("2104", ret_amt, 0), ("4101", 0, work_value)],
                                pid=pid, source_type="INTERIM", source_id=iid)
            if err:
                flash(err, "err")
        db.audit(g.user["username"], "إضافة مستخلص", f"مشروع #{pid}")
        flash("تمت إضافة المستخلص", "ok")
        return redirect(url_for("interim"))
    return render_template("interim_form.html", projects=projects)


@app.route("/interim/<int:iid>/receive", methods=["POST"])
@require_write
def interim_receive(iid):
    i = db.query_one("SELECT * FROM interim_payments WHERE id=?", (iid,))
    if i:
        amt = _num(request.form.get("amount", 0))
        rdate = _sanitize(request.form.get("receive_date", ""))
        db.execute("UPDATE interim_payments SET actual_received=?, receive_date=?, status=? WHERE id=?",
                   (amt, rdate, "محصل" if amt > 0 else i["status"], iid))
        if request.form.get("auto_post") and amt > 0:
            cash = AUTO_CASH
            err = _post_journal("IR", f"تحصيل مستخلص {i['payment_no']}", rdate,
                                [(cash, amt, 0), ("1201", 0, amt)],
                                pid=i["project_id"], source_type="INTERIM_RECV", source_id=iid)
            if err:
                flash(err, "err")
        db.audit(g.user["username"], "تحصيل مستخلص", f"#{iid}")
        flash("تم تسجيل التحصيل", "ok")
    return redirect(url_for("interim"))


@app.route("/interim/<int:iid>/delete", methods=["POST"])
@require_write
def interim_delete(iid):
    _purge_source("INTERIM", iid)
    _purge_source("INTERIM_REL", iid)
    _purge_source("INTERIM_RECV", iid)
    db.execute("DELETE FROM interim_payments WHERE id=?", (iid,))
    flash("تم حذف المستخلص", "ok")
    return redirect(url_for("interim"))


@app.route("/interim/<int:iid>/edit", methods=["POST"])
@require_write
def interim_edit(iid):
    """تعديل مستخلص مع إعادة حساب الصافي تلقائيًا (أعمال - محجوز)."""
    i = db.query_one("SELECT * FROM interim_payments WHERE id=?", (iid,))
    if not i:
        abort(404)
    work_value = _num(request.form.get("work_value", i["work_value"]))
    ret_pct = _num(request.form.get("retention_percent", i["retention_percent"]))
    ret_amt = _num(request.form.get("retention_amount", 0)) or (work_value * ret_pct / 100)
    net = _num(request.form.get("net_payment", 0)) or (work_value - ret_amt)
    pn = _sanitize(request.form.get("payment_no", i["payment_no"])) or i["payment_no"]
    pdate = _sanitize(request.form.get("payment_date", i["payment_date"]))
    db.execute("UPDATE interim_payments SET payment_no=?, payment_date=?, description=?, work_value=?, "
               "retention_percent=?, retention_amount=?, previous_payments=?, net_payment=?, "
               "status=?, notes=? WHERE id=?",
               (pn, pdate,
                _sanitize(request.form.get("description", i["description"])),
                work_value, ret_pct, ret_amt,
                _num(request.form.get("previous_payments", i["previous_payments"])),
                net,
                _sanitize(request.form.get("status", i["status"])),
                _sanitize(request.form.get("notes", i["notes"])),
                iid))
    _purge_source("INTERIM", iid)
    _purge_source("INTERIM_REL", iid)
    if work_value > 0:
        err = _post_journal("IN", f"مستخلص {pn}", pdate,
                            [("1201", net, 0), ("2104", ret_amt, 0), ("4101", 0, work_value)],
                            pid=i["project_id"], source_type="INTERIM", source_id=iid)
        if err:
            flash(err, "err")
    db.audit(g.user["username"], "تعديل مستخلص", f"#{iid}")
    flash("تم تعديل المستخلص", "ok")
    return redirect(url_for("interim"))


# ==================================================================
# التكاليف
# ==================================================================
@app.route("/costs")
def costs():
    rows = db.query("SELECT * FROM project_costs ORDER BY id DESC")
    projm = {p["id"]: p["name"] for p in db.query("SELECT id,name FROM projects")}
    sup = {s["id"]: s["name"] for s in db.query("SELECT id,name FROM suppliers")}
    sub = {s["id"]: s["name"] for s in db.query("SELECT id,name FROM subcontractors")}
    mat = {m["id"]: m["name"] for m in db.query("SELECT id,name FROM materials")}
    for r in rows:
        r["project_name"] = projm.get(r["project_id"], "-")
        r["supplier_name"] = sup.get(r["supplier_id"], "")
        r["sub_name"] = sub.get(r["sub_id"], "")
        r["material_name"] = mat.get(r["material_id"], "")
    total = sum(_num(r["amount"]) for r in rows)
    return render_template("costs.html", rows=rows, total=total,
                           projects=db.query("SELECT * FROM projects ORDER BY id DESC"),
                           suppliers=db.query("SELECT id,name FROM suppliers ORDER BY name"),
                           subs=db.query("SELECT id,name FROM subcontractors ORDER BY name"),
                           materials=db.query("SELECT id,name FROM materials ORDER BY name"))


@app.route("/costs/new", methods=["POST"])
@require_write
def costs_new():
    pid = request.form.get("project_id")
    pid = int(pid) if pid else None
    amount = _num(request.form.get("amount", 0))
    cost_type = _sanitize(request.form.get("cost_type", "مواد"))
    cdate = _sanitize(request.form.get("cost_date", ""))
    cid = db.execute("INSERT INTO project_costs (project_id, cost_date, cost_type, description, amount, "
                     "supplier_id, worker_id, equipment_id, sub_id, material_id, quantity, notes) "
                     "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                     (pid, cdate, cost_type,
                      _sanitize(request.form.get("description", "")), amount,
                      request.form.get("supplier_id") or None,
                      request.form.get("worker_id") or None,
                      request.form.get("equipment_id") or None,
                      request.form.get("sub_id") or None,
                      request.form.get("material_id") or None,
                      _num(request.form.get("quantity", 0)),
                      _sanitize(request.form.get("notes", ""))))
    db.audit(g.user["username"], "إضافة تكلفة", f"مشروع #{pid}")
    if request.form.get("auto_post"):
        err = _post_journal("CO", f"تكلفة مشروع: {cost_type}", cdate,
                            [(_cost_account(cost_type), amount, 0), ("2101", 0, amount)],
                            pid=pid, source_type="COST", source_id=cid)
        if err:
            flash(err, "err")
    flash("تم تسجيل التكلفة", "ok")
    return redirect(url_for("costs"))


@app.route("/costs/<int:cid>/delete", methods=["POST"])
@require_write
def costs_delete(cid):
    _purge_source("COST", cid)
    db.execute("DELETE FROM project_costs WHERE id=?", (cid,))
    flash("تم حذف التكلفة", "ok")
    return redirect(url_for("costs"))


@app.route("/costs/<int:cid>/edit", methods=["POST"])
@require_write
def costs_edit(cid):
    c = db.query_one("SELECT * FROM project_costs WHERE id=?", (cid,))
    if not c:
        abort(404)
    pid = request.form.get("project_id")
    pid = int(pid) if pid else c["project_id"]
    amount = _num(request.form.get("amount", c["amount"]))
    cost_type = _sanitize(request.form.get("cost_type", c["cost_type"]))
    cdate = _sanitize(request.form.get("cost_date", c["cost_date"]))
    db.execute("UPDATE project_costs SET project_id=?, cost_date=?, cost_type=?, description=?, amount=?, "
               "supplier_id=?, worker_id=?, equipment_id=?, sub_id=?, material_id=?, quantity=?, notes=? WHERE id=?",
               (pid, cdate, cost_type,
                _sanitize(request.form.get("description", c["description"])), amount,
                request.form.get("supplier_id") or None,
                request.form.get("worker_id") or None,
                request.form.get("equipment_id") or None,
                request.form.get("sub_id") or None,
                request.form.get("material_id") or None,
                _num(request.form.get("quantity", c["quantity"])),
                _sanitize(request.form.get("notes", c["notes"])),
                cid))
    _purge_source("COST", cid)
    err = _post_journal("CO", f"تكلفة مشروع: {cost_type}", cdate,
                        [(_cost_account(cost_type), amount, 0), ("2101", 0, amount)],
                        pid=pid, source_type="COST", source_id=cid)
    if err:
        flash(err, "err")
    db.audit(g.user["username"], "تعديل تكلفة", f"#{cid}")
    flash("تم تعديل التكلفة", "ok")
    return redirect(url_for("costs"))


# ==================================================================
# دفعات استلام من العميل
# ==================================================================
@app.route("/projects/<int:pid>/payment", methods=["POST"])
@require_write
def project_payment(pid):
    amount = _num(request.form.get("amount", 0))
    ref = _sanitize(request.form.get("reference", ""))
    method = _sanitize(request.form.get("method", "نقداً"))
    pdate = _sanitize(request.form.get("payment_date", ""))
    rpid = db.execute("INSERT INTO client_payments (project_id, payment_date, amount, method, reference, notes) "
                      "VALUES (?,?,?,?,?,?)",
                      (pid, pdate, amount, method, ref,
                       _sanitize(request.form.get("notes", ""))))
    db.audit(g.user["username"], "دفعة من عميل", f"مشروع #{pid} — {amount:,.2f}")
    if request.form.get("auto_post"):
        cash = AUTO_CASH if method == "نقداً" else AUTO_BANK
        desc = f"دفعة من عميل {ref}".strip()
        err = _post_journal("CP", desc, pdate, [(cash, amount, 0), ("1201", 0, amount)],
                            pid=pid, source_type="CLIENT_PAYMENT", source_id=rpid)
        if err:
            flash(err, "err")
    flash("تم تسجيل الدفعة بنجاح", "ok")
    return redirect(url_for("project_view", pid=pid) + "#payments")


@app.route("/payments/<int:rpid>/delete", methods=["POST"])
@require_write
def payment_delete(rpid):
    row = db.query_one("SELECT project_id FROM client_payments WHERE id=?", (rpid,))
    if row:
        _purge_source("CLIENT_PAYMENT", rpid)
        db.execute("DELETE FROM client_payments WHERE id=?", (rpid,))
        flash("تم حذف الدفعة", "ok")
        return redirect(url_for("project_view", pid=row["project_id"]) + "#payments")
    return redirect(url_for("projects"))


@app.route("/payments/<int:rpid>/edit", methods=["POST"])
@require_write
def payment_edit(rpid):
    r = db.query_one("SELECT * FROM client_payments WHERE id=?", (rpid,))
    if not r:
        abort(404)
    amount = _num(request.form.get("amount", r["amount"]))
    method = _sanitize(request.form.get("method", r["method"]))
    pdate = _sanitize(request.form.get("payment_date", r["payment_date"]))
    ref = _sanitize(request.form.get("reference", r["reference"]))
    db.execute("UPDATE client_payments SET payment_date=?, amount=?, method=?, reference=?, notes=? WHERE id=?",
               (pdate, amount, method, ref,
                _sanitize(request.form.get("notes", r["notes"])), rpid))
    _purge_source("CLIENT_PAYMENT", rpid)
    cash = AUTO_CASH if method == "نقداً" else AUTO_BANK
    err = _post_journal("CP", f"دفعة من عميل {ref}".strip(), pdate,
                        [(cash, amount, 0), ("1201", 0, amount)],
                        pid=r["project_id"], source_type="CLIENT_PAYMENT", source_id=rpid)
    if err:
        flash(err, "err")
    db.audit(g.user["username"], "تعديل دفعة عميل", f"#{rpid}")
    flash("تم تعديل الدفعة", "ok")
    return redirect(url_for("project_view", pid=r["project_id"]) + "#payments")


# ==================================================================
# الحالة المالية للمشروع (كشف حساب / إجماليات / المحجوزات)
# ==================================================================
def _project_financials(pid):
    """يعيد كل أرقام الحالة المالية للمشروع في شكل قاموس واحد."""
    p = db.query_one("SELECT * FROM projects WHERE id=?", (pid,))
    if not p:
        return None
    contract = db.query_one("SELECT * FROM contracts WHERE project_id=?", (pid,))
    cv = (_num(contract["contract_value"]) if contract else 0)

    interims = db.query("SELECT * FROM interim_payments WHERE project_id=? ORDER BY payment_date, id", (pid,))
    receipts = db.query("SELECT * FROM client_payments WHERE project_id=? ORDER BY payment_date, id", (pid,))
    cost_rows = db.query("SELECT * FROM project_costs WHERE project_id=?", (pid,))
    pay_rows = db.query("SELECT * FROM supplier_payments WHERE project_id=? ORDER BY payment_date, id", (pid,))

    work_total = sum(_num(i["work_value"]) for i in interims)
    ret_total = sum(_num(i["retention_amount"]) for i in interims)
    ret_released = sum(_num(i["retention_amount"]) for i in interims if i["retention_release"])
    net_total = sum(_num(i["net_payment"]) for i in interims)
    recv_interim = sum(_num(i["actual_received"]) for i in interims)
    recv_direct = sum(_num(r["amount"]) for r in receipts)

    cost_total = sum(_num(c["amount"]) for c in cost_rows)
    pay_total = sum(_num(x["amount"]) for x in pay_rows)

    ret_balance = ret_total - ret_released
    recv_total = recv_interim + recv_direct
    client_balance = net_total - recv_total
    unpaid_suppliers = cost_total - pay_total
    expected_profit = cv - cost_total
    position = client_balance - unpaid_suppliers  # صافي مركز المشروع الحالي

    return {
        "contract_value": cv,
        "work_total": work_total,
        "ret_total": ret_total,
        "ret_released": ret_released,
        "ret_balance": ret_balance,
        "net_total": net_total,
        "recv_interim": recv_interim,
        "recv_direct": recv_direct,
        "recv_total": recv_total,
        "client_balance": client_balance,
        "cost_total": cost_total,
        "pay_total": pay_total,
        "unpaid_suppliers": unpaid_suppliers,
        "expected_profit": expected_profit,
        "position": position,
        "interims": interims,
        "receipts": receipts,
        "pay_rows": pay_rows,
        "cost_rows": cost_rows,
    }


@app.route("/projects/<int:pid>/financial")
def project_financial(pid):
    fin = _project_financials(pid)
    if not fin:
        abort(404)
    p = db.query_one("SELECT * FROM projects WHERE id=?", (pid,))
    clients = {c["id"]: c["name"] for c in db.query("SELECT id,name FROM clients")}
    p["client_name"] = clients.get(p["client_id"], "-")
    projm = {x["id"]: x["name"] for x in db.query("SELECT id,name FROM projects")}
    sup = {s["id"]: s["name"] for s in db.query("SELECT id,name FROM suppliers")}
    sub = {s["id"]: s["name"] for s in db.query("SELECT id,name FROM subcontractors")}
    for r in fin["pay_rows"]:
        r["party_name"] = sup.get(r["supplier_id"]) or sub.get(r["sub_id"]) or "-"
    for r in fin["interims"]:
        r["released"] = bool(r["retention_release"])
    for r in fin["receipts"]:
        r["project_name"] = projm.get(r["project_id"], "")
    return render_template(
        "project_financial.html", p=p, fin=fin,
        suppliers=db.query("SELECT id,name FROM suppliers ORDER BY name"),
        subs=db.query("SELECT id,name FROM subcontractors ORDER BY name"),
    )


@app.route("/projects/<int:pid>/pay", methods=["POST"])
@require_write
def project_pay(pid):
    amount = _num(request.form.get("amount", 0))
    method = _sanitize(request.form.get("method", "نقداً"))
    pdate = _sanitize(request.form.get("payment_date", ""))
    supplier_id = request.form.get("supplier_id") or None
    sub_id = request.form.get("sub_id") or None
    spid = db.execute(
        "INSERT INTO supplier_payments (project_id, supplier_id, sub_id, payment_date, amount, method, reference, notes) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (pid, supplier_id, sub_id, pdate, amount, method,
         _sanitize(request.form.get("reference", "")),
         _sanitize(request.form.get("notes", ""))))
    db.audit(g.user["username"], "دفعة لمورد/مقاول باطن", f"مشروع #{pid} — {amount:,.2f}")
    if request.form.get("auto_post"):
        payee = "2101" if supplier_id else "2102"
        cash = AUTO_CASH if method == "نقداً" else AUTO_BANK
        party = "مورد" if supplier_id else "مقاول باطن"
        err = _post_journal("SP", f"دفعة لـ{party}", pdate,
                            [(payee, amount, 0), (cash, 0, amount)],
                            pid=pid, source_type="SUPPLIER_PAYMENT", source_id=spid)
        if err:
            flash(err, "err")
    flash("تم تسجيل الدفعة للمورد/مقاول الباطن", "ok")
    return redirect(url_for("project_financial", pid=pid) + "#suppliers")


@app.route("/supplier-payments/<int:spid>/delete", methods=["POST"])
@require_write
def supplier_payment_delete(spid):
    row = db.query_one("SELECT project_id FROM supplier_payments WHERE id=?", (spid,))
    if row:
        _purge_source("SUPPLIER_PAYMENT", spid)
        db.execute("DELETE FROM supplier_payments WHERE id=?", (spid,))
        flash("تم حذف الدفعة", "ok")
        return redirect(url_for("project_financial", pid=row["project_id"]) + "#suppliers")
    return redirect(url_for("projects"))


@app.route("/supplier-payments/<int:spid>/edit", methods=["POST"])
@require_write
def supplier_payment_edit(spid):
    row = db.query_one("SELECT * FROM supplier_payments WHERE id=?", (spid,))
    if not row:
        abort(404)
    amount = _num(request.form.get("amount", row["amount"]))
    method = _sanitize(request.form.get("method", row["method"]))
    pdate = _sanitize(request.form.get("payment_date", row["payment_date"]))
    supplier_id = request.form.get("supplier_id") or None
    sub_id = request.form.get("sub_id") or None
    db.execute("UPDATE supplier_payments SET supplier_id=?, sub_id=?, payment_date=?, amount=?, method=?, "
               "reference=?, notes=? WHERE id=?",
               (supplier_id, sub_id, pdate, amount, method,
                _sanitize(request.form.get("reference", row["reference"])),
                _sanitize(request.form.get("notes", row["notes"])),
                spid))
    _purge_source("SUPPLIER_PAYMENT", spid)
    payee = "2101" if supplier_id else "2102"
    cash = AUTO_CASH if method == "نقداً" else AUTO_BANK
    party = "مورد" if supplier_id else "مقاول باطن"
    err = _post_journal("SP", f"دفعة لـ{party}", pdate,
                        [(payee, amount, 0), (cash, 0, amount)],
                        pid=row["project_id"], source_type="SUPPLIER_PAYMENT", source_id=spid)
    if err:
        flash(err, "err")
    db.audit(g.user["username"], "تعديل دفعة مورد", f"#{spid}")
    flash("تم تعديل الدفعة", "ok")
    return redirect(url_for("project_financial", pid=row["project_id"]) + "#suppliers")


# ==================================================================
# فواتير الموردين
# ==================================================================
@app.route("/supplier-invoices")
@require_write
def supplier_invoices():
    suppliers = db.query("SELECT id, name FROM suppliers ORDER BY name")
    rows = db.query("SELECT si.*, s.name AS supplier_name "
                    "FROM supplier_invoices si LEFT JOIN suppliers s ON s.id=si.supplier_id "
                    "ORDER BY si.invoice_date DESC, si.id DESC")
    return render_template("supplier_invoices.html", invoices=rows, suppliers=suppliers,
                           today=date.today().isoformat())


@app.route("/supplier-invoices/new", methods=["POST"])
@require_write
def supplier_invoice_new():
    siid = db.execute("INSERT INTO supplier_invoices (supplier_id, invoice_no, invoice_date, due_date, amount, notes) "
                      "VALUES (?,?,?,?,?,?)",
                      (request.form.get("supplier_id") or None,
                       _sanitize(request.form.get("invoice_no", "")),
                       _sanitize(request.form.get("invoice_date", "")),
                       _sanitize(request.form.get("due_date", "")),
                       _num(request.form.get("amount", 0)),
                       _sanitize(request.form.get("notes", ""))))
    db.audit(g.user["username"], "إضافة فاتورة مورد", f"#{siid}")
    flash("تمت إضافة الفاتورة", "ok")
    return redirect(url_for("supplier_invoices"))


@app.route("/supplier-invoices/<int:siid>/edit", methods=["POST"])
@require_write
def supplier_invoice_edit(siid):
    r = db.query_one("SELECT * FROM supplier_invoices WHERE id=?", (siid,))
    if not r:
        abort(404)
    db.execute("UPDATE supplier_invoices SET supplier_id=?, invoice_no=?, invoice_date=?, due_date=?, amount=?, notes=? WHERE id=?",
               (request.form.get("supplier_id") or None,
                _sanitize(request.form.get("invoice_no", r["invoice_no"])),
                _sanitize(request.form.get("invoice_date", r["invoice_date"])),
                _sanitize(request.form.get("due_date", r.get("due_date") or "")),
                _num(request.form.get("amount", r["amount"])),
                _sanitize(request.form.get("notes", r["notes"])),
                siid))
    db.audit(g.user["username"], "تعديل فاتورة مورد", f"#{siid}")
    flash("تم تعديل الفاتورة", "ok")
    return redirect(url_for("supplier_invoices"))


@app.route("/supplier-invoices/<int:siid>/pay", methods=["POST"])
@require_write
def supplier_invoice_pay(siid):
    r = db.query_one("SELECT * FROM supplier_invoices WHERE id=?", (siid,))
    if r:
        amt = _num(request.form.get("amount", r["amount"]))
        pdate = _sanitize(request.form.get("payment_date", ""))
        method = _sanitize(request.form.get("method", "نقداً"))
        db.execute("UPDATE supplier_invoices SET paid=1, payment_date=?, amount=? WHERE id=?",
                   (pdate, amt, siid))
        if request.form.get("auto_post") and amt > 0:
            cash = AUTO_CASH if method == "نقداً" else AUTO_BANK
            err = _post_journal("SI", f"سداد فاتورة مورد {r['invoice_no'] or siid}", pdate,
                                [("2101", amt, 0), (cash, 0, amt)],
                                source_type="INV_PAY", source_id=siid)
            if err:
                flash(err, "err")
        db.audit(g.user["username"], "سداد فاتورة مورد", f"#{siid}")
        flash("تم تسجيل السداد", "ok")
    return redirect(url_for("supplier_invoices"))


@app.route("/supplier-invoices/<int:siid>/delete", methods=["POST"])
@require_write
def supplier_invoice_delete(siid):
    _purge_source("INV_PAY", siid)
    db.execute("DELETE FROM supplier_invoices WHERE id=?", (siid,))
    flash("تم حذف الفاتورة", "ok")
    return redirect(url_for("supplier_invoices"))


# ==================================================================
# كشف حساب المورد (فواتير + سددات + رصيد)
# ==================================================================
def _supplier_statement(sid):
    s = db.query_one("SELECT * FROM suppliers WHERE id=?", (sid,))
    if not s:
        return None
    inv = db.query("SELECT * FROM supplier_invoices WHERE supplier_id=? ORDER BY invoice_date, id", (sid,))
    pays = db.query("SELECT * FROM supplier_payments WHERE supplier_id=? AND sub_id IS NULL"
                    " ORDER BY payment_date, id", (sid,))
    projm = {p["id"]: p["name"] for p in db.query("SELECT id,name FROM projects")}
    events = []
    for i in inv:
        events.append(((i["invoice_date"] or "0001-01-01"), 0, i["id"], "فاتورة", i))
    for p in pays:
        events.append(((p["payment_date"] or "9999-12-31"), 1, p["id"], "سداد", p))
    events.sort(key=lambda e: (e[0], e[1], e[2]))
    balance = 0.0
    rows = []
    for date, _k, _seq, kind, row in events:
        if kind == "فاتورة":
            amt = _num(row["amount"])
            balance += amt
            desc = f"فاتورة رقم {row['invoice_no'] or ('#' + str(row['id']))}"
            rows.append({"date": date, "desc": desc, "debit": amt, "credit": 0.0, "balance": balance})
        else:
            amt = _num(row["amount"])
            balance -= amt
            proj = projm.get(row["project_id"], "")
            desc = "سداد فاتورة/أعمال"
            if proj:
                desc += f" — {proj}"
            rows.append({"date": date, "desc": desc, "debit": 0.0, "credit": amt, "balance": balance})
    totals = {
        "invoice": sum(_num(i["amount"]) for i in inv),
        "paid": sum(_num(p["amount"]) for p in pays),
        "balance": balance,
    }
    return {"supplier": s, "rows": rows, "totals": totals}


@app.route("/suppliers/<int:sid>/statement")
def supplier_statement(sid):
    data = _supplier_statement(sid)
    if not data:
        abort(404)
    return render_template("supplier_statement.html", s=data["supplier"],
                           rows=data["rows"], totals=data["totals"])


@app.route("/export/supplier-statement/<int:sid>")
@require_write
def export_supplier_statement(sid):
    data = _supplier_statement(sid)
    if not data:
        abort(404)
    s = data["supplier"]
    headers = ["التاريخ", "البيان", "فاتورة (مدين)", "سداد (دائن)", "الرصيد"]
    hdata = [[r["date"], r["desc"], r["debit"], r["credit"], r["balance"]] for r in data["rows"]]
    trow = ["الإجمالي", "", data["totals"]["invoice"], data["totals"]["paid"], data["totals"]["balance"]]
    if request.args.get("fmt") == "pdf":
        buf = px.build_pdf_report(f"كشف حساب المورد — {s['name']}",
                                  [f"الشركة: {_export_company()['name']}",
                                   f"الرقم الضريبي للمورد: {s['tax_no'] or '-'}", _exp_sub()],
                                  headers, hdata, num_cols=(2, 3, 4),
                                  totals_row=trow, landscape=True, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, f"كشف_حساب_مورد_{s['name'].strip()}.pdf")
    wb, ws, _ = xl.build_report("كشف حساب مورد", f"كشف حساب المورد — {s['name']}",
                                [f"الشركة: {_export_company()['name']}",
                                 f"الرقم الضريبي للمورد: {s['tax_no'] or '-'}"],
                                headers, hdata, totals=trow, num_cols=(2, 3, 4))
    return send_file(xl.to_bytes(wb), as_attachment=True,
                     download_name=f"كشف_حساب_مورد_{s['name'].strip()}.xlsx")


# ==================================================================
# مسير رواتب العمالة
# ==================================================================
@app.route("/payroll")
@require_write
def payroll():
    workers = db.query("SELECT id, name, daily_rate, monthly_salary FROM workers ORDER BY name")
    default_period = datetime.now().strftime("%Y-%m")
    rows = db.query("SELECT py.*, w.name AS worker_name, w.daily_rate, w.monthly_salary "
                    "FROM payroll py LEFT JOIN workers w ON w.id=py.worker_id "
                    "ORDER BY py.period DESC, py.id DESC")
    return render_template("payroll.html", rows=rows, workers=workers,
                           default_period=default_period)


@app.route("/payroll/generate", methods=["POST"])
@require_write
def payroll_generate():
    """توليد صفوف مسير لشهر جديد لكل عامل نشط."""
    period = _sanitize(request.form.get("period", datetime.now().strftime("%Y-%m")))
    reg = re.match(r"^\d{4}-\d{2}$", period)
    if not reg:
        flash("صيغة الفترة غير صحيحة (YYYY-MM)", "err")
        return redirect(url_for("payroll"))
    existing = {r["worker_id"] for r in db.query("SELECT worker_id FROM payroll WHERE period=?", (period,))}
    added = 0
    for w in db.query("SELECT id, daily_rate, monthly_salary FROM workers WHERE status<>'منتهي' OR status=''"):
        if w["id"] in existing:
            continue
        rate = w["daily_rate"] or w["monthly_salary"] or 0
        db.execute("INSERT INTO payroll (worker_id, period, days_worked, gross, net, status) "
                   "VALUES (?,?,?,?,?, 'مسجل')",
                   (w["id"], period, 26, rate, rate))
        added += 1
    db.audit(g.user["username"], "توليد مسير رواتب", f"{period} — {added} عامل")
    flash(f"تم توليد المسير لـ {added} عامل ({period})", "ok")
    return redirect(url_for("payroll"))


@app.route("/payroll/<int:pid2>/edit", methods=["POST"])
@require_write
def payroll_edit(pid2):
    r = db.query_one("SELECT * FROM payroll WHERE id=?", (pid2,))
    if not r:
        abort(404)
    days = _num(request.form.get("days_worked", r["days_worked"]))
    w = db.query_one("SELECT daily_rate, monthly_salary FROM workers WHERE id=?", (r["worker_id"],))
    rate = (w["daily_rate"] if w else None) or (w["monthly_salary"] if w else None) or 0
    gross = rate * days
    deductions = _num(request.form.get("deductions", r["deductions"]))
    db.execute("UPDATE payroll SET days_worked=?, gross=?, deductions=?, net=? WHERE id=?",
               (days, gross, deductions, gross - deductions, pid2))
    db.audit(g.user["username"], "تعديل بند مسير", f"#{pid2}")
    flash("تم تعديل البند", "ok")
    return redirect(url_for("payroll"))


@app.route("/payroll/<int:pid2>/pay", methods=["POST"])
@require_write
def payroll_pay(pid2):
    r = db.query_one("SELECT * FROM payroll WHERE id=?", (pid2,))
    if r and r["status"] != "مسدد":
        pdate = _sanitize(request.form.get("payment_date", ""))
        db.execute("UPDATE payroll SET status='مسدد', payment_date=? WHERE id=?", (pdate, pid2))
        if request.form.get("auto_post") and r["net"] > 0:
            err = _post_journal("PRY", f"صرف راتب {r['worker_id']} — فترة {r['period']}", pdate,
                                [("5102", r["net"], 0), ("1101", 0, r["net"])],
                                source_type="PAYROLL", source_id=pid2)
            if err:
                flash(err, "err")
        db.audit(g.user["username"], "صرف راتب", f"#{pid2}")
        flash("تم صرف الراتب", "ok")
    return redirect(url_for("payroll"))


@app.route("/payroll/<int:pid2>/delete", methods=["POST"])
@require_write
def payroll_delete(pid2):
    _purge_source("PAYROLL", pid2)
    db.execute("DELETE FROM payroll WHERE id=?", (pid2,))
    flash("تم حذف البند", "ok")
    return redirect(url_for("payroll"))


# ==================================================================
# إهلاك المعدات تلقائيًا شهريًا
# ==================================================================
@app.route("/depreciation")
@require_write
def depreciation():
    equipment = db.query("SELECT id, name, purchase_cost, depreciation_rate FROM equipment ORDER BY name")
    periods = db.query("SELECT DISTINCT period FROM depreciation ORDER BY period DESC")
    rows = db.query("SELECT d.*, e.name AS equipment_name, e.purchase_cost "
                    "FROM depreciation d LEFT JOIN equipment e ON e.id=d.equipment_id "
                    "ORDER BY d.period DESC, d.id DESC")
    return render_template("depreciation.html", rows=rows, equipment=equipment,
                           periods=[p["period"] for p in periods],
                           default_period=datetime.now().strftime("%Y-%m"))


@app.route("/depreciation/run", methods=["POST"])
@require_write
def depreciation_run():
    period = _sanitize(request.form.get("period", datetime.now().strftime("%Y-%m")))
    if not re.match(r"^\d{4}-\d{2}$", period):
        flash("صيغة الفترة غير صحيحة (YYYY-MM)", "err")
        return redirect(url_for("depreciation"))
    existing = {r["equipment_id"] for r in db.query("SELECT equipment_id FROM depreciation WHERE period=?", (period,))}
    total = 0
    added = 0
    for e in db.query("SELECT id, purchase_cost, depreciation_rate FROM equipment WHERE depreciation_rate>0"):
        if e["id"] in existing:
            continue
        dep = round((e["purchase_cost"] or 0) * (e["depreciation_rate"] or 0) / 1200, 2)
        if dep <= 0:
            continue
        db.execute("INSERT INTO depreciation (equipment_id, period, amount) VALUES (?,?,?)",
                   (e["id"], period, dep))
        total += dep
        added += 1
    if added:
        src = int(period.replace("-", "")) * 100 + 1
        err = _post_journal("DEP", f"إهلاك المعدات — {period}", f"{period}-01",
                            [("5210", total, 0), ("1404", 0, total)],
                            source_type="DEP", source_id=src)
        for r in db.query("SELECT id FROM depreciation WHERE period=? AND posted=0", (period,)):
            db.execute("UPDATE depreciation SET posted=1 WHERE id=?", (r["id"],))
        if err:
            flash(err, "err")
    db.audit(g.user["username"], "تشغيل الإهلاك", f"{period} — {added} معدة")
    flash(f"تم احتساب إهلاك {added} معدة (إجمالي {total:,.2f})", "ok")
    return redirect(url_for("depreciation"))


@app.route("/depreciation/<period>/delete", methods=["POST"])
@require_write
def depreciation_delete(period):
    _purge_source("DEP", int(period.replace("-", "")) * 100 + 1)
    db.execute("DELETE FROM depreciation WHERE period=?", (period,))
    flash(f"تم حذف إهلاك فترة {period}", "ok")
    return redirect(url_for("depreciation"))


# ==================================================================
# الميزانية التقديرية للمشروع
# ==================================================================
@app.route("/projects/<int:pid>/budget/add", methods=["POST"])
@require_write
def budget_add(pid):
    qty = _num(request.form.get("quantity", 0))
    price = _num(request.form.get("unit_price", 0))
    db.execute("INSERT INTO budget_items (project_id, item_no, description, unit, quantity, unit_price, "
               "total, sort_order) VALUES (?,?,?,?,?,?,?,?)",
               (pid, _sanitize(request.form.get("item_no", "")),
                _sanitize(request.form.get("description", "")),
                _sanitize(request.form.get("unit", "")),
                qty, price, qty * price,
                int(request.form.get("sort_order", 0) or 0)))
    db.audit(g.user["username"], "إضافة بند ميزانية", f"مشروع #{pid}")
    flash("تمت إضافة البند", "ok")
    return redirect(url_for("project_view", pid=pid) + "#budget")


@app.route("/projects/budget/<int:bid>/edit", methods=["POST"])
@require_write
def budget_edit(bid):
    b = db.query_one("SELECT * FROM budget_items WHERE id=?", (bid,))
    if not b:
        abort(404)
    qty = _num(request.form.get("quantity", b["quantity"]))
    price = _num(request.form.get("unit_price", b["unit_price"]))
    db.execute("UPDATE budget_items SET item_no=?, description=?, unit=?, quantity=?, unit_price=?, "
               "total=?, sort_order=? WHERE id=?",
               (_sanitize(request.form.get("item_no", b["item_no"])),
                _sanitize(request.form.get("description", b["description"])),
                _sanitize(request.form.get("unit", b["unit"])),
                qty, price, qty * price,
                int(request.form.get("sort_order", b["sort_order"]) or 0),
                bid))
    db.audit(g.user["username"], "تعديل بند ميزانية", f"#{bid}")
    flash("تم تعديل البند", "ok")
    return redirect(url_for("project_view", pid=b["project_id"]) + "#budget")


@app.route("/projects/budget/<int:bid>/delete", methods=["POST"])
@require_write
def budget_delete(bid):
    b = db.query_one("SELECT project_id FROM budget_items WHERE id=?", (bid,))
    if b:
        db.execute("DELETE FROM budget_items WHERE id=?", (bid,))
        flash("تم حذف البند", "ok")
        return redirect(url_for("project_view", pid=b["project_id"]) + "#budget")
    return redirect(url_for("projects"))


# ==================================================================
# الفاتورة الضريبية (أهم مستند رسمي PDF)
# ==================================================================
@app.route("/payments/<int:rpid>/tax-invoice")
@require_write
def payment_tax_invoice(rpid):
    r = db.query_one("SELECT * FROM client_payments WHERE id=?", (rpid,))
    if not r:
        abort(404)
    comp = _export_company()
    p = db.query_one("SELECT * FROM projects WHERE id=?", (r["project_id"],))
    clients = {c["id"]: c["name"] for c in db.query("SELECT id,name FROM clients")}
    client_name = clients.get((p or {}).get("client_id"), "-")
    vat_rate = _num(db.get_setting("vat_rate", "0"))
    total = r["amount"] or 0
    vat_amt = total * vat_rate / 100
    items = [["قيمة الدفعة على أعمال مشروع", round(total, 2)]]
    inv_no = f"TI-{r['id']:06d}"
    buf = px.tax_invoice_pdf(comp["name"], inv_no, r["payment_date"] or "",
                             client_name, r["reference"] or "-", r["method"] or "نقداً",
                             items, vat_rate, round(vat_amt, 2), round(total, 2),
                             round(total + vat_amt, 2), r["notes"] or "")
    db.execute(
        "INSERT INTO tax_invoices (invoice_no, payment_id, invoice_date, client_name, description, "
        "total_net, vat_rate, vat_amount, total_with_vat) VALUES (?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(invoice_no) DO UPDATE SET invoice_date=excluded.invoice_date, "
        "client_name=excluded.client_name, total_net=excluded.total_net, vat_rate=excluded.vat_rate, "
        "vat_amount=excluded.vat_amount, total_with_vat=excluded.total_with_vat",
        (inv_no, r["id"], r["payment_date"] or "", client_name,
         f"دفعة عميل على مشروع {(p or {}).get('name', '')}",
         round(total, 2), vat_rate, round(vat_amt, 2), round(total + vat_amt, 2)))
    return _send_pdf(buf, f"فاتورة_ضريبية_{inv_no}.pdf")


# ==================================================================
# سند قبض / سند صرف (مستندات يومية PDF فاخرة)
# ==================================================================
def _payment_amount_words(amount):
    return px.tafqeet(amount, db.get_setting("currency", "جنيه"))


@app.route("/payments/<int:rpid>/voucher")
@require_write
def payment_voucher(rpid):
    """سند قبض — دفعة استلام من عميل."""
    r = db.query_one("SELECT * FROM client_payments WHERE id=?", (rpid,))
    if not r:
        abort(404)
    comp = _export_company()
    p = db.query_one("SELECT * FROM projects WHERE id=?", (r["project_id"],))
    clients = {c["id"]: c["name"] for c in db.query("SELECT id,name FROM clients")}
    client_name = clients.get((p or {}).get("client_id"), "-")
    vno = f"QBD-{r['id']:06d}"
    buf = px.voucher_pdf("قبض", vno, r["payment_date"] or "", "العميل",
                         f"{client_name} — مشروع: {(p or {}).get('name', '')}",
                         "سند استلام نقدية من العميل", f"دفعة على أعمال مشروع {(p or {}).get('name', '')}",
                         r["amount"] or 0, r["method"] or "نقداً", r["reference"] or "",
                         r["notes"] or "", db.get_setting("currency", "جنيه"))
    return _send_pdf(buf, f"سند_قبض_{vno}.pdf")


@app.route("/supplier-payments/<int:spid>/voucher")
@require_write
def supplier_payment_voucher(spid):
    """سند صرف — دفعة لمورد أو مقاول باطن."""
    r = db.query_one("SELECT * FROM supplier_payments WHERE id=?", (spid,))
    if not r:
        abort(404)
    comp = _export_company()
    p = db.query_one("SELECT * FROM projects WHERE id=?", (r["project_id"],))
    sup = {s["id"]: s["name"] for s in db.query("SELECT id,name FROM suppliers")}
    sub = {s["id"]: s["name"] for s in db.query("SELECT id,name FROM subcontractors")}
    payee = sup.get(r["supplier_id"]) or sub.get(r["sub_id"]) or "-"
    vno = f"SRF-{r['id']:06d}"
    buf = px.voucher_pdf("صرف", vno, r["payment_date"] or "", "المستفيد",
                         f"{payee} — مشروع: {(p or {}).get('name', '')}",
                         "سند صرف نقدية", "دفعة لحساب مشروع",
                         r["amount"] or 0, r["method"] or "نقداً", r["reference"] or "",
                         r["notes"] or "", db.get_setting("currency", "جنيه"))
    return _send_pdf(buf, f"سند_صرف_{vno}.pdf")


# ==================================================================
# تقرير الأرباح الشهرية (تأريخ عام)
# ==================================================================
def _monthly_data():
    by_month = {}
    for it in db.query("SELECT payment_date, work_value FROM interim_payments"):
        m = (it["payment_date"] or "")[:7]
        if re.match(r"^\d{4}-\d{2}$", m):
            by_month.setdefault(m, {"work": 0.0, "cost": 0.0, "recv": 0.0})
            by_month[m]["work"] += _num(it["work_value"])
    for c in db.query("SELECT cost_date, amount FROM project_costs"):
        m = (c["cost_date"] or "")[:7]
        if re.match(r"^\d{4}-\d{2}$", m):
            by_month.setdefault(m, {"work": 0.0, "cost": 0.0, "recv": 0.0})
            by_month[m]["cost"] += _num(c["amount"])
    for p in db.query("SELECT payment_date, amount FROM client_payments"):
        m = (p["payment_date"] or "")[:7]
        if re.match(r"^\d{4}-\d{2}$", m):
            by_month.setdefault(m, {"work": 0.0, "cost": 0.0, "recv": 0.0})
            by_month[m]["recv"] += _num(p["amount"])
    rows = [{**d, "month": m, "profit": d["work"] - d["cost"]}
            for m, d in sorted(by_month.items())]
    totals = {"work": sum(r["work"] for r in rows),
              "cost": sum(r["cost"] for r in rows),
              "recv": sum(r["recv"] for r in rows),
              "profit": sum(r["profit"] for r in rows)}
    return rows, totals


@app.route("/monthly")
@require_write
def monthly():
    rows, totals = _monthly_data()
    return render_template("monthly.html", rows=rows, totals=totals)


@app.route("/export/monthly")
@require_write
def export_monthly():
    rows, totals = _monthly_data()
    data = [[r["month"], r["work"], r["cost"], r["recv"], r["profit"]] for r in rows]
    headers = ["الشهر", "الأعمال المنفذة", "التكاليف", "المحصل", "صافي الربح"]
    if request.args.get("fmt") == "pdf":
        trow = ["الإجمالي", totals["work"], totals["cost"], totals["recv"], totals["profit"]]
        buf = px.build_pdf_report("تقرير الأرباح الشهرية",
                                  [f"الشركة: {_export_company()['name']}", _exp_sub()],
                                  headers, data, num_cols=(1, 2, 3, 4), totals_row=trow,
                                  landscape=True, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "تقرير_الأرباح_الشهرية.pdf")
    wb, ws, _ = xl.build_report("الأرباح الشهرية", "تقرير الأرباح الشهرية",
                                [f"الشركة: {_export_company()['name']}"],
                                headers, data, num_cols=(1, 2, 3, 4),
                                totals=["", totals["work"], totals["cost"],
                                        totals["recv"], totals["profit"]])
    return send_file(xl.to_bytes(wb), as_attachment=True,
                     download_name="تقرير_الأرباح_الشهرية.xlsx")


# ==================================================================
# العهد والأمانات
# ==================================================================
@app.route("/custody")
@require_write
def custody():
    projects = db.query("SELECT id,name FROM projects ORDER BY name")
    cust = db.query("SELECT c.*, p.name AS project_name, "
                    "(SELECT COALESCE(SUM(amount),0) FROM custody_ops WHERE custody_id=c.id AND op_type='صرف') AS spent, "
                    "(SELECT COALESCE(SUM(amount),0) FROM custody_ops WHERE custody_id=c.id AND op_type='سداد') AS refunded "
                    "FROM custody c LEFT JOIN projects p ON p.id=c.project_id ORDER BY c.id DESC")
    for c in cust:
        c["remaining"] = _num(c["amount"]) - _num(c["spent"]) + _num(c["refunded"])
    return render_template("custody.html", rows=cust, projects=projects)


@app.route("/custody/add", methods=["POST"])
@require_write
def custody_add():
    cid = db.execute("INSERT INTO custody (custodian, project_id, amount, notes) VALUES (?,?,?,?)",
                     (_sanitize(request.form.get("custodian", "")),
                      request.form.get("project_id") or None,
                      _num(request.form.get("amount", 0)),
                      _sanitize(request.form.get("notes", ""))))
    db.audit(g.user["username"], "إنشاء عهدة", f"#{cid}")
    flash("تم إنشاء العهدة", "ok")
    return redirect(url_for("custody"))


@app.route("/custody/<int:cid>/op", methods=["POST"])
@require_write
def custody_op(cid):
    c = db.query_one("SELECT custodian FROM custody WHERE id=?", (cid,))
    if not c:
        abort(404)
    op_type = _sanitize(request.form.get("op_type", "صرف"))
    amt = _num(request.form.get("amount", 0))
    if amt > 0:
        db.execute("INSERT INTO custody_ops (custody_id, op_type, amount, op_date, notes) VALUES (?,?,?,?,?)",
                   (cid, op_type, amt, _sanitize(request.form.get("op_date", "")),
                    _sanitize(request.form.get("notes", ""))))
        db.audit(g.user["username"], "عملية عهدة", f"#{cid} {op_type} {amt:,.2f}")
        flash("تم تسجيل العملية", "ok")
    else:
        flash("أدخل مبلغًا صحيحًا", "err")
    return redirect(url_for("custody"))


@app.route("/custody/<int:cid>/delete", methods=["POST"])
@require_write
def custody_delete(cid):
    db.execute("DELETE FROM custody_ops WHERE custody_id=?", (cid,))
    db.execute("DELETE FROM custody WHERE id=?", (cid,))
    flash("تم حذف العهدة", "ok")
    return redirect(url_for("custody"))


@app.route("/export/custody")
@require_write
def export_custody():
    rows, _ = [], []
    for c in db.query("SELECT c.*, p.name AS project_name, "
                      "(SELECT COALESCE(SUM(amount),0) FROM custody_ops WHERE custody_id=c.id AND op_type='صرف') AS spent, "
                      "(SELECT COALESCE(SUM(amount),0) FROM custody_ops WHERE custody_id=c.id AND op_type='سداد') AS refunded "
                      "FROM custody c LEFT JOIN projects p ON p.id=c.project_id ORDER BY c.id DESC"):
        rows.append([c["custodian"], c["project_name"] or "-", c["amount"],
                     c["spent"] or 0, c["refunded"] or 0,
                     _num(c["amount"]) - _num(c["spent"]) + _num(c["refunded"])])
    headers = ["المسؤول", "المشروع", "المبلغ المخوّل", "المصروف", "المسدد", "الرصيد المتبقي"]
    if request.args.get("fmt") == "pdf":
        trow = ["الإجمالي", "", sum(r[2] for r in rows), sum(r[3] for r in rows),
                sum(r[4] for r in rows), sum(r[5] for r in rows)]
        buf = px.build_pdf_report("كشف العهد والأمانات",
                                  [f"الشركة: {_export_company()['name']}", _exp_sub()],
                                  headers, rows, num_cols=(2, 3, 4, 5), totals_row=trow,
                                  landscape=True, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "كشف_العهدات.pdf")
    wb, ws, _ = xl.build_report("العهد", "كشف العهد والأمانات",
                                [f"الشركة: {_export_company()['name']}"],
                                headers, rows, num_cols=(2, 3, 4, 5),
                                totals=["", "", sum(r[2] for r in rows), sum(r[3] for r in rows),
                                        sum(r[4] for r in rows), sum(r[5] for r in rows)])
    return send_file(xl.to_bytes(wb), as_attachment=True, download_name="كشف_العهدات.xlsx")


@app.route("/interim/<int:iid>/release", methods=["POST"])
@require_write
def interim_release(iid):
    i = db.query_one("SELECT * FROM interim_payments WHERE id=?", (iid,))
    if i:
        releasing = not i["retention_release"]
        db.execute("UPDATE interim_payments SET retention_release = "
                   "CASE WHEN retention_release THEN 0 ELSE 1 END WHERE id=?", (iid,))
        # مزامنة دفتر القيود مع حالة المحجوز (تحرير الضمان ↔ إعادة حجزه)
        _purge_source("INTERIM_REL", iid)
        if releasing and _num(i["retention_amount"]) > 0:
            err = _post_journal("REL", f"تحرير ضمان مستخلص {i['payment_no']}",
                                datetime.now().strftime("%Y-%m-%d"),
                                [("1201", _num(i["retention_amount"]), 0),
                                 ("2104", 0, _num(i["retention_amount"]))],
                                pid=i["project_id"], source_type="INTERIM_REL", source_id=iid)
            if err:
                flash(err, "err")
        db.audit(g.user["username"], "تحرير/إعادة حجز ضمان", f"مستخلص #{iid}")
        flash("تم تحديث حالة المحجوز", "ok")
        return redirect(url_for("project_financial", pid=i["project_id"]) + "#retention")
    return redirect(url_for("projects"))


@app.route("/interim/<int:iid>/print")
@require_write
def interim_print(iid):
    """طباعة رسمية لمستخلص (Excel فخم بتوقيعات)."""
    i = db.query_one("SELECT * FROM interim_payments WHERE id=?", (iid,))
    if not i:
        abort(404)
    p = db.query_one("SELECT * FROM projects WHERE id=?", (i["project_id"],))
    c = db.query_one("SELECT * FROM contracts WHERE project_id=?", (i["project_id"],))
    client = None
    if p:
        client = db.query_one("SELECT * FROM clients WHERE id=?", (p["client_id"],))
    company = _export_company()
    subs = [f"الشركة: {company['name']}",
            f"المشروع: {p['name'] if p else '-'} — العميل: {client['name'] if client else '-'}",
            f"رقم المستخلص: {i['payment_no']} — تاريخه: {i['payment_date'] or '-'}"]
    headers = ["البيان", "المبلغ"]
    rows = [
        ["قيمة الأعمال المنفذة لهذا المستخلص", round(i["work_value"], 2)],
        ["نسبة المحجوز %", round(i["retention_percent"], 2)],
        ["قيمة المحجوز (ضمان)", round(i["retention_amount"], 2)],
        ["المستحق عن مستخلصات سابقة", round(i["previous_payments"], 2)],
        ["الصافي المستحق دفعه", round(i["net_payment"], 2)],
    ]
    if i["actual_received"]:
        rows.append(["محصل فعليًا", round(i["actual_received"], 2)])
    if request.args.get("fmt") == "pdf":
        buf = px.build_pdf_report(f"مستخلص رقم {i['payment_no']}", subs, headers, rows,
                                  num_cols=(1,), signatures=True,
                                  company=company["name"])
        return _send_pdf(buf, f"مستخلص_{i['payment_no']}.pdf")
    wb, ws, nr = xl.build_report("مستخلص", f"مستخلص رقم {i['payment_no']}", subs, headers, rows,
                                 num_cols=(1,))
    xl.add_signatures(ws, nr, len(headers), acc_user=g.user["full_name"])
    return send_file(xl.to_bytes(wb), as_attachment=True,
                     download_name=f"مستخلص_{i['payment_no']}.xlsx")


@app.route("/export/project/<int:pid>")
@require_write
def export_project_financial(pid):
    fin = _project_financials(pid)
    if not fin:
        abort(404)
    p = db.query_one("SELECT * FROM projects WHERE id=?", (pid,))
    clients = {c["id"]: c["name"] for c in db.query("SELECT id,name FROM clients")}
    cname = clients.get(p["client_id"], "-")
    headers = ["البيان", "المبلغ"]
    rows = [
        ["قيمة العقد", round(fin["contract_value"], 2)],
        ["إجمالي الأعمال المنفذة (مستخلصات)", round(fin["work_total"], 2)],
        ["إجمالي المحجوز (ضمانات)", round(fin["ret_total"], 2)],
        ["المحجوز المحرر", round(fin["ret_released"], 2)],
        ["رصيد المحجوز الحالي", round(fin["ret_balance"], 2)],
        ["صافي المستحق من العميل", round(fin["net_total"], 2)],
        ["محصل من المستخلصات", round(fin["recv_interim"], 2)],
        ["دفعات مباشرة من العميل", round(fin["recv_direct"], 2)],
        ["إجمالي المحصل من العميل", round(fin["recv_total"], 2)],
        ["رصيد المتبقي على العميل", round(fin["client_balance"], 2)],
        ["إجمالي تكاليف المشروع", round(fin["cost_total"], 2)],
        ["مدفوعات الموردين ومقاولي الباطن", round(fin["pay_total"], 2)],
        ["المتبقي للموردين ومقاولي الباطن", round(fin["unpaid_suppliers"], 2)],
        ["صافي مركز المشروع الحالي", round(fin["position"], 2)],
        ["الربح المتوقع (العقد - التكاليف)", round(fin["expected_profit"], 2)],
    ]
    if request.args.get("fmt") == "pdf":
        buf = px.build_pdf_report("كشف حساب المشروع",
                                  [f"الشركة: {_export_company()['name']}",
                                   f"المشروع: {p['name']} — العميل: {cname}"],
                                  headers, rows, num_cols=(1,), signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, f"كشف_حساب_مشروع_{pid}.pdf")
    wb, ws, _ = xl.build_report(
        "الحالة المالية", "كشف حساب المشروع",
        [f"الشركة: {_export_company()['name']}",
         f"المشروع: {p['name']} — العميل: {cname}",
         f"التاريخ: {datetime.now().strftime('%Y-%m-%d')}"],
        headers, rows,
        num_cols=(1,))
    return send_file(xl.to_bytes(wb), as_attachment=True,
                     download_name=f"كشف_حساب_مشروع_{pid}.xlsx")


# ==================================================================
# المخازن
# ==================================================================
@app.route("/stock")
def stock():
    movements = db.query("SELECT * FROM stock_movements ORDER BY id DESC")
    materials = db.query("SELECT * FROM materials ORDER BY id DESC")
    projm = {p["id"]: p["name"] for p in db.query("SELECT id,name FROM projects")}
    sup = {s["id"]: s["name"] for s in db.query("SELECT id,name FROM suppliers")}

    # حساب الأرصدة الحالية
    current = {}
    for m in materials:
        inn = db.query_one("SELECT COALESCE(SUM(quantity),0) s FROM stock_movements "
                           "WHERE material_id=? AND movement_type='إدخال'", (m["id"],))["s"]
        out = db.query_one("SELECT COALESCE(SUM(quantity),0) s FROM stock_movements "
                           "WHERE material_id=? AND movement_type='صرف'", (m["id"],))["s"]
        current[m["id"]] = (inn or 0) - (out or 0)

    for mv in movements:
        mv["project_name"] = projm.get(mv["project_id"], "")
        mv["material_name"] = ""
        mv["supplier_name"] = sup.get(mv["supplier_id"], "")
        for m in materials:
            if m["id"] == mv["material_id"]:
                mv["material_name"] = m["name"]

    stock_rows = []
    for m in materials:
        bal = current.get(m["id"], 0)
        low = bal < (m["min_stock"] or 0)
        stock_rows.append({**m, "balance": bal, "low": low})

    return render_template("stock.html", movements=movements, stock_rows=stock_rows,
                           materials=materials, projects=db.query("SELECT * FROM projects ORDER BY id DESC"),
                           suppliers=db.query("SELECT id,name FROM suppliers ORDER BY name"))


@app.route("/stock/move", methods=["POST"])
@require_write
def stock_move():
    qty = _num(request.form.get("quantity", 0))
    up = _num(request.form.get("unit_price", 0))
    mtype = _sanitize(request.form.get("movement_type", "إدخال"))
    total = qty * up
    db.execute("INSERT INTO stock_movements (material_id, project_id, movement_date, movement_type, "
               "quantity, unit_price, total, supplier_id, reference, notes) VALUES (?,?,?,?,?,?,?,?,?,?)",
               (request.form.get("material_id") or None,
                request.form.get("project_id") or None,
                _sanitize(request.form.get("movement_date", "")), mtype,
                qty if mtype == "إدخال" else qty, up, total,
                request.form.get("supplier_id") or None,
                _sanitize(request.form.get("reference", "")),
                _sanitize(request.form.get("notes", ""))))
    db.audit(g.user["username"], f"حركة مخزن: {mtype}", f"كمية {qty}")
    flash("تم تسجيل الحركة", "ok")
    return redirect(url_for("stock"))


@app.route("/stock/<int:mid>/delete", methods=["POST"])
@require_write
def stock_movement_delete(mid):
    db.execute("DELETE FROM stock_movements WHERE id=?", (mid,))
    flash("تم حذف الحركة", "ok")
    return redirect(url_for("stock"))


@app.route("/stock/<int:mid>/edit", methods=["POST"])
@require_write
def stock_movement_edit(mid):
    m = db.query_one("SELECT * FROM stock_movements WHERE id=?", (mid,))
    if not m:
        abort(404)
    qty = _num(request.form.get("quantity", m["quantity"]))
    up = _num(request.form.get("unit_price", m["unit_price"]))
    db.execute("UPDATE stock_movements SET material_id=?, project_id=?, movement_date=?, movement_type=?, "
               "quantity=?, unit_price=?, total=?, supplier_id=?, reference=?, notes=? WHERE id=?",
               (request.form.get("material_id") or m["material_id"],
                request.form.get("project_id") or None,
                _sanitize(request.form.get("movement_date", m["movement_date"])),
                _sanitize(request.form.get("movement_type", m["movement_type"])),
                qty, up, qty * up,
                request.form.get("supplier_id") or None,
                _sanitize(request.form.get("reference", m["reference"])),
                _sanitize(request.form.get("notes", m["notes"])),
                mid))
    db.audit(g.user["username"], "تعديل حركة مخزن", f"#{mid}")
    flash("تم تعديل الحركة", "ok")
    return redirect(url_for("stock"))


# ==================================================================
# دليل الحسابات
# ==================================================================
@app.route("/accounts")
def accounts():
    rows = db.query("SELECT * FROM accounts ORDER BY acc_no")
    return render_template("accounts.html", accounts=rows,
                           types=["أصول", "خصوم", "حقوق ملكية", "إيرادات", "مصروفات", "أخرى"])


@app.route("/accounts/new", methods=["POST"])
@require_write
def accounts_new():
    acc_no = _sanitize(request.form.get("acc_no", ""))
    name = _sanitize(request.form.get("name", ""))
    acc_type = _sanitize(request.form.get("type", ""))
    if not acc_no or not name:
        flash("رقم الحساب والاسم مطلوبان", "err")
        return redirect(url_for("accounts"))
    try:
        db.execute("INSERT INTO accounts (acc_no, name, type, opening_balance) VALUES (?,?,?,?)",
                   (acc_no, name, acc_type, _num(request.form.get("opening_balance", 0))))
        flash("تمت إضافة الحساب", "ok")
    except Exception:
        flash("رقم الحساب موجود مسبقًا", "err")
    return redirect(url_for("accounts"))


@app.route("/accounts/<int:aid>/edit", methods=["POST"])
@require_write
def accounts_edit(aid):
    db.execute("UPDATE accounts SET acc_no=?, name=?, type=?, opening_balance=? WHERE id=?",
               (_sanitize(request.form.get("acc_no", "")),
                _sanitize(request.form.get("name", "")),
                _sanitize(request.form.get("type", "")),
                _num(request.form.get("opening_balance", 0)), aid))
    db.audit(g.user["username"], "تعديل حساب", f"#{aid}")
    flash("تم تحديث الحساب", "ok")
    return redirect(url_for("accounts"))


@app.route("/accounts/<int:aid>/delete", methods=["POST"])
@require_write
def accounts_delete(aid):
    used = db.query_one("SELECT COUNT(*) c FROM journal_lines WHERE account_id=?", (aid,))["c"]
    if used:
        flash("لا يمكن حذف حساب له حركات", "err")
    else:
        db.execute("DELETE FROM accounts WHERE id=?", (aid,))
        flash("تم حذف الحساب", "ok")
    return redirect(url_for("accounts"))


@app.route("/accounts/tree")
def accounts_tree():
    rows = db.query("SELECT * FROM accounts ORDER BY acc_no")
    return render_template("accounts_tree.html", accounts=rows,
                           types=["أصول", "خصوم", "حقوق ملكية", "إيرادات", "مصروفات", "أخرى"])


@app.route("/accounts/reset", methods=["POST"])
@require_write
def accounts_reset():
    """حذف نهائي لشجرة الحسابات بالكامل مع كل القيود والدفاتر (لا يمكن التراجع)."""
    n_acc = db.query_one("SELECT COUNT(*) c FROM accounts")["c"]
    n_ent = db.query_one("SELECT COUNT(*) c FROM journal_entries")["c"]
    if n_acc == 0:
        flash("لا توجد حسابات لحذفها", "err")
        return redirect(url_for("accounts_tree"))
    db.execute("DELETE FROM journal_lines", ())
    db.execute("DELETE FROM journal_entries", ())
    db.execute("DELETE FROM accounts", ())
    db.audit(g.user["username"], "حذف شجرة الحسابات نهائيًا",
             f"حُذف {n_acc} حساب و{n_ent} قيد مع كل الدفاتر")
    flash(f"تم حذف شجرة الحسابات نهائيًا ({n_acc} حساب، {n_ent} قيد) — يمكنك إعادة بناء الدليل من دليل الحسابات القديم.", "ok")
    return redirect(url_for("accounts_tree"))


# ==================================================================
# القيود اليومية
# ==================================================================
@app.route("/journal")
def journal():
    entries = db.query("SELECT * FROM journal_entries ORDER BY entry_date DESC, id DESC")
    projm = {p["id"]: p["name"] for p in db.query("SELECT id,name FROM projects")}
    acc_cache = {a["id"]: a for a in db.query("SELECT * FROM accounts")}
    for e in entries:
        if e["project_id"]:
            e["project_name"] = projm.get(e["project_id"])
        lines = db.query("SELECT * FROM journal_lines WHERE entry_id=?", (e["id"],))
        e["lines"] = lines
        e["total_d"] = sum(_num(l["debit"]) for l in lines)
        e["total_c"] = sum(_num(l["credit"]) for l in lines)
        e["acc_names"] = ", ".join(acc_cache.get(l["account_id"], {}).get("name", "?") for l in lines)
    return render_template("journal.html", entries=entries,
                           accounts=db.query("SELECT * FROM accounts ORDER BY acc_no"),
                           entry_types=ENTRY_TYPES,
                           projects=db.query("SELECT * FROM projects ORDER BY id DESC"))


@app.route("/journal/new", methods=["GET", "POST"])
@require_write
def journal_new():
    if request.method == "POST":
        desc = _sanitize(request.form.get("description", ""))
        edate = _sanitize(request.form.get("entry_date", ""))
        etype = _sanitize(request.form.get("entry_type", "عادي"))
        pid = request.form.get("project_id")
        pid = int(pid) if pid else None
        accs = request.form.getlist("account_id[]")
        debits = request.form.getlist("debit[]")
        credits = request.form.getlist("credit[]")
        lines = list(zip(accs, debits, credits))
        lines = [(a, _num(d), _num(c)) for a, d, c in lines if a and (_num(d) > 0 or _num(c) > 0)]
        if not desc or not edate or not lines:
            flash("أكمل البيانات: الوصف، التاريخ، وسطر واحد على الأقل", "err")
            return redirect(url_for("journal_new"))
        td = sum(l[1] for l in lines)
        tc = sum(l[2] for l in lines)
        if abs(td - tc) > 0.01:
            flash(f"القيد غير متوازن: مدين {td:,.2f} ≠ دائن {tc:,.2f}", "err")
            return redirect(url_for("journal_new"))
        mvno = db.next_number("Q", "journal_entries", "movement_no")
        eid = db.execute("INSERT INTO journal_entries (movement_no, entry_date, description, project_id, "
                         "status, entry_type, created_by) VALUES (?,?,?,?,?,?,?)",
                         (mvno, edate, desc, pid, "posted", etype, g.user["id"]))
        for a, d, c in lines:
            db.execute("INSERT INTO journal_lines (entry_id, account_id, debit, credit) VALUES (?,?,?,?)",
                       (eid, a, d, c))
        db.audit(g.user["username"], "قيد جديد", f"{mvno} {desc}")
        flash(f"تم ترحيل القيد {mvno}", "ok")
        return redirect(url_for("journal"))
    return render_template("journal_form.html",
                           accounts=db.query("SELECT * FROM accounts ORDER BY acc_no"),
                           projects=db.query("SELECT * FROM projects ORDER BY id DESC"),
                           entry_types=ENTRY_TYPES)


@app.route("/journal/<int:eid>/delete", methods=["POST"])
@require_write
def journal_delete(eid):
    """حذف جزئي: يمسح القيد (بحسب رقم الحركة) مع كل بنوده حتى لا تبقى بنود يتيمة."""
    e = db.query_one("SELECT * FROM journal_entries WHERE id=?", (eid,))
    if e:
        mv = e["movement_no"]
        ids = [r["id"] for r in db.query(
            "SELECT id FROM journal_entries WHERE movement_no=?", (mv,))]
        if ids:
            marks = ",".join("?" for _ in ids)
            db.execute(f"DELETE FROM journal_lines WHERE entry_id IN ({marks})", tuple(ids))
            db.execute(f"DELETE FROM journal_entries WHERE id IN ({marks})", tuple(ids))
        db.audit(g.user["username"], "حذف قيد", mv)
        flash(f"تم حذف القيد {mv} وكامل بنوده", "ok")
    return redirect(url_for("journal"))


@app.route("/journal/<int:eid>/edit", methods=["GET", "POST"])
@require_write
def journal_edit(eid):
    """تعديل قيد كامل (حسب رقم الحركة): التاريخ والبيان والنوع والمشروع والأسطر مع فحص التوازن."""
    e = db.query_one("SELECT * FROM journal_entries WHERE id=?", (eid,))
    if not e:
        abort(404)
    mv = e["movement_no"]
    e["lines"] = db.query("SELECT * FROM journal_lines WHERE entry_id=?", (eid,))
    if request.method == "POST":
        desc = _sanitize(request.form.get("description", ""))
        edate = _sanitize(request.form.get("entry_date", ""))
        etype = _sanitize(request.form.get("entry_type", "عادي"))
        pid = request.form.get("project_id")
        pid = int(pid) if pid else None
        accs = request.form.getlist("account_id[]")
        debits = request.form.getlist("debit[]")
        credits = request.form.getlist("credit[]")
        lines = list(zip(accs, debits, credits))
        lines = [(a, _num(d), _num(c)) for a, d, c in lines if a and (_num(d) > 0 or _num(c) > 0)]
        if not edate or not lines:
            flash("أكمل البيانات: التاريخ وسطر واحد على الأقل", "err")
            return redirect(url_for("journal_edit", eid=eid))
        td = sum(l[1] for l in lines)
        tc = sum(l[2] for l in lines)
        if abs(td - tc) > 0.01:
            flash(f"القيد غير متوازن: مدين {td:,.2f} ≠ دائن {tc:,.2f}", "err")
            return redirect(url_for("journal_edit", eid=eid))
        all_ids = [r["id"] for r in db.query(
            "SELECT id FROM journal_entries WHERE movement_no=?", (mv,))]
        if all_ids:
            marks = ",".join("?" for _ in all_ids)
            db.execute(f"DELETE FROM journal_lines WHERE entry_id IN ({marks})", tuple(all_ids))
            db.execute(f"DELETE FROM journal_entries WHERE id IN ({marks})", tuple(all_ids))
        new_eid = db.execute(
            "INSERT INTO journal_entries (movement_no, entry_date, description, project_id, "
            "status, entry_type, created_by) VALUES (?,?,?,?,?,?,?)",
            (mv, edate, desc, pid, "posted", etype, g.user["id"]))
        for a, d, c in lines:
            db.execute("INSERT INTO journal_lines (entry_id, account_id, debit, credit) VALUES (?,?,?,?)",
                       (new_eid, a, d, c))
        db.audit(g.user["username"], "تعديل قيد", mv)
        flash(f"تم تعديل القيد {mv}", "ok")
        return redirect(url_for("journal"))
    return render_template("journal_form.html",
                           accounts=db.query("SELECT * FROM accounts ORDER BY acc_no"),
                           projects=db.query("SELECT * FROM projects ORDER BY id DESC"),
                           entry_types=ENTRY_TYPES,
                           entry=e, is_edit=True)


@app.route("/journal/clear", methods=["POST"])
@require_admin
def journal_clear():
    """مسح نهائي لكامل القيود وبنودها (يحتفظ بدليل الحسابات والإعدادات)."""
    confirm = request.form.get("confirm", "")
    if confirm != "DELETE":
        flash("للمسح النهائي يجب كتابة DELETE في خانة التأكيد", "err")
        return redirect(url_for("journal"))
    db.execute("DELETE FROM journal_lines")
    db.execute("DELETE FROM journal_entries")
    db.execute("DELETE FROM sqlite_sequence WHERE name IN ('journal_lines','journal_entries')")
    db.audit(g.user["username"], "مسح كل القيود", "تم حذف كل القيود وبنودها نهائيًا")
    flash("تم مسح كل القيود نهائيًا", "ok")
    return redirect(url_for("journal"))


# ==================================================================
# الأستاذ العام + ميزان المراجعة
# ==================================================================
@app.route("/ledger")
def ledger():
    accounts = db.query("SELECT * FROM accounts ORDER BY acc_no")
    rows = []
    for a in accounts:
        lines = db.query("SELECT * FROM journal_lines WHERE account_id=? ORDER BY entry_id", (a["id"],))
        total_d = sum(_num(l["debit"]) for l in lines)
        total_c = sum(_num(l["credit"]) for l in lines)
        balance = a["opening_balance"] + total_d - total_c
        rows.append({**a, "lines": len(lines), "total_d": total_d, "total_c": total_c, "balance": balance})
    return render_template("ledger.html", accounts=rows)


@app.route("/trial-balance")
def trial_balance():
    accounts = db.query("SELECT * FROM accounts ORDER BY acc_no")
    rows = []
    t_d = t_c = 0
    for a in accounts:
        lines = db.query("SELECT * FROM journal_lines WHERE account_id=?", (a["id"],)) or []
        total_d = sum(_num(l["debit"]) for l in lines)
        total_c = sum(_num(l["credit"]) for l in lines)
        ob = a["opening_balance"] or 0
        bal = ob + total_d - total_c
        rows.append({**a, "total_d": total_d, "total_c": total_c, "balance": bal})
        t_d += total_d
        t_c += total_c
    return render_template("trial_balance.html", rows=rows, t_d=t_d, t_c=t_c)


# ==================================================================
# القوائم المالية
# ==================================================================
@app.route("/financial")
def financial():
    accounts = db.query("SELECT * FROM accounts ORDER BY acc_no")
    balances = {}
    for a in accounts:
        lines = db.query("SELECT * FROM journal_lines WHERE account_id=?", (a["id"],))
        bal = (a["opening_balance"] or 0) + sum(_num(l["debit"]) for l in lines) - sum(_num(l["credit"]) for l in lines)
        balances[a["acc_no"]] = {"name": a["name"], "type": a["type"], "balance": bal}

    # قائمة الدخل
    income_rows = [(k, v["name"], v["balance"]) for k, v in balances.items() if v["type"] == "إيرادات"]
    expense_rows = [(k, v["name"], v["balance"]) for k, v in balances.items() if v["type"] == "مصروفات"]
    total_income = sum(v for _, _, v in income_rows)
    total_expense = sum(v for _, _, v in expense_rows)
    net_income = total_income - total_expense

    # الميزانية العمومية
    asset_rows = [(k, v["name"], v["balance"]) for k, v in balances.items() if v["type"] == "أصول"]
    liability_rows = [(k, v["name"], v["balance"]) for k, v in balances.items() if v["type"] == "خصوم"]
    equity_rows = [(k, v["name"], v["balance"]) for k, v in balances.items() if v["type"] == "حقوق ملكية"]
    total_assets = sum(v for _, _, v in asset_rows)
    total_liabs = sum(v for _, _, v in liability_rows)
    total_equity = sum(v for _, _, v in equity_rows)

    return render_template("financial.html", income_rows=income_rows, expense_rows=expense_rows,
                           total_income=total_income, total_expense=total_expense, net_income=net_income,
                           asset_rows=asset_rows, liability_rows=liability_rows, equity_rows=equity_rows,
                           total_assets=total_assets, total_liabs=total_liabs, total_equity=total_equity)


# ==================================================================
# المستخدمون
# ==================================================================
@app.route("/users")
@require_admin
def users():
    return render_template("users.html", users=db.query("SELECT * FROM users ORDER BY id"))


@app.route("/users/new", methods=["POST"])
@require_admin
def users_new():
    username = _sanitize(request.form.get("username", ""))
    full_name = _sanitize(request.form.get("full_name", ""))
    role = _sanitize(request.form.get("role", "viewer"))
    password = request.form.get("password", "")
    if not username or not full_name or len(password) < 6:
        flash("أدخل اسم مستخدم واسم كامل وكلمة مرور 6 خانات على الأقل", "err")
        return redirect(url_for("users"))
    try:
        db.execute("INSERT INTO users (username, password_hash, full_name, role) VALUES (?,?,?,?)",
                   (username, generate_password_hash(password), full_name, role))
        flash("تم إنشاء المستخدم", "ok")
    except Exception:
        flash("اسم المستخدم موجود مسبقًا", "err")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/role", methods=["POST"])
@require_admin
def users_role(uid):
    role = _sanitize(request.form.get("role", "viewer"))
    db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    db.audit(g.user["username"], "تغيير صلاحية", f"مستخدم #{uid}")
    flash("تم تحديث الصلاحية", "ok")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/password", methods=["POST"])
@require_admin
def users_password(uid):
    pwd = request.form.get("password", "")
    if len(pwd) < 6:
        flash("كلمة المرور 6 خانات على الأقل", "err")
        return redirect(url_for("users"))
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(pwd), uid))
    flash("تم تغيير كلمة المرور", "ok")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/delete", methods=["POST"])
@require_admin
def users_delete(uid):
    if uid == g.user["id"]:
        flash("لا يمكنك حذف نفسك", "err")
        return redirect(url_for("users"))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    flash("تم حذف المستخدم", "ok")
    return redirect(url_for("users"))


# ==================================================================
# سجل العمليات
# ==================================================================
@app.route("/audit")
@require_admin
def audit():
    logs = db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500")
    return render_template("audit.html", logs=logs)


# ==================================================================
# الإعدادات + النسخ الاحتياطي
# ==================================================================
@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        if not can_write():
            flash("ليست لديك صلاحية تعديل الإعدادات", "err")
            return redirect(url_for("settings"))
        if "company_name" in request.form:
            db.set_setting("company_name", _sanitize(request.form.get("company_name", "")))
            db.set_setting("company_address", _sanitize(request.form.get("company_address", "")))
            db.set_setting("company_tax_no", _sanitize(request.form.get("company_tax_no", "")))
            db.set_setting("company_commercial_no", _sanitize(request.form.get("company_commercial_no", "")))
            db.set_setting("financial_year", _sanitize(request.form.get("financial_year", "")))
            db.set_setting("currency", _sanitize(request.form.get("currency", "")))
            db.set_setting("contract_default_retention", _sanitize(request.form.get("contract_default_retention", "5")))
            db.set_setting("vat_rate", _sanitize(request.form.get("vat_rate", "0")))
            db.audit(g.user["username"], "تحديث بيانات الشركة")
        if "sig_title[]" in request.form:
            titles = request.form.getlist("sig_title[]")
            names = request.form.getlist("sig_name[]")
            sigs = [{"title": _sanitize(t), "name": _sanitize(n)} for t, n in zip(titles, names)]
            db.set_setting("signatures", json.dumps(sigs, ensure_ascii=False))
            db.audit(g.user["username"], "تحديث توقيعات التقارير")
        flash("تم حفظ الإعدادات", "ok")
        return redirect(url_for("settings"))
    sigs = json.loads(db.get_setting("signatures", "[]") or "[]")
    return render_template("settings.html", sigs=sigs)


@app.route("/settings/reset-all", methods=["POST"])
@require_admin
def reset_all_data():
    """مسح شامل لكل البيانات التجارية بلا رجعة (يحافظ على المستخدمين ودليل الحسابات والإعدادات)."""
    confirm = request.form.get("confirm", "")
    if confirm != "DELETE":
        flash("يجب كتابة كلمة DELETE للتأكيد على المسح الشامل", "err")
        return redirect(url_for("settings"))
    tables = [
        "journal_lines", "journal_entries", "stock_movements",
        "project_costs", "client_payments", "interim_payments",
        "boq_items", "contracts", "projects",
        "clients", "suppliers", "subcontractors", "workers", "equipment", "materials",
        "supplier_payments", "supplier_invoices", "payroll", "depreciation",
        "budget_items", "custody_ops", "custody",
        "tax_invoices",
        "audit_log",
    ]
    for t in tables:
        db.execute(f"DELETE FROM {t}")
    db.execute("DELETE FROM sqlite_sequence WHERE name IN (%s)" %
               ",".join("'" + t.replace("'", "''") + "'" for t in tables))
    db.audit(g.user["username"], "مسح شامل", "تم حذف كل البيانات التجارية نهائيًا")
    flash("تم مسح كل البيانات تمامًا — لا توجد أي بيانات تجريبية الآن", "ok")
    return redirect(url_for("settings"))


@app.route("/backup")
@require_admin
def backup_list():
    return render_template("backup.html", backups=db.list_backups())


@app.route("/backup/create", methods=["POST"])
@require_admin
def backup_create():
    name = db.create_backup("manual")
    db.audit(g.user["username"], "نسخة احتياطية", name)
    flash("تم إنشاء النسخة الاحتياطية", "ok")
    return redirect(url_for("backup_list"))


@app.route("/backup/download", methods=["POST"])
@require_admin
def backup_download():
    name = request.form.get("name", "")
    import io
    src = db.BACKUP_DIR / name
    if not db.SAFE_BACKUP_NAME.match(name) or not src.exists():
        flash("ملف غير صالح", "err")
        return redirect(url_for("backup_list"))
    return send_file(src, as_attachment=True, download_name=name)


@app.route("/backup/restore", methods=["POST"])
@require_admin
def backup_restore():
    name = request.form.get("name", "")
    try:
        pre = db.restore_backup(name)
        msg = "تمت الاستعادة بنجاح"
        if pre:
            msg += f" (تم حفظ نسخة أمان قبل الاستعادة: {pre})"
        flash(msg, "ok")
    except Exception as exc:
        flash(f"فشلت الاستعادة: {exc}", "err")
    return redirect(url_for("backup_list"))


@app.route("/backup/delete", methods=["POST"])
@require_admin
def backup_delete():
    name = request.form.get("name", "")
    if db.SAFE_BACKUP_NAME.match(name):
        src = db.BACKUP_DIR / name
        if src.exists():
            src.unlink()
            flash("تم حذف النسخة", "ok")
    return redirect(url_for("backup_list"))


# ==================================================================
# التصدير إلى Excel
# ==================================================================
def _export_company():
    return {
        "name": db.get_setting("company_name", "شركة المقاولات"),
        "address": db.get_setting("company_address", ""),
        "tax_no": db.get_setting("company_tax_no", ""),
    }


@app.route("/export/projects")
@require_write
def export_projects():
    rows = db.query("SELECT * FROM projects ORDER BY id DESC")
    clients = {c["id"]: c["name"] for c in db.query("SELECT id,name FROM clients")}
    data = []
    for p in rows:
        c = db.query_one("SELECT contract_value FROM contracts WHERE project_id=?", (p["id"],))
        tc = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM project_costs WHERE project_id=?", (p["id"],))["s"]
        tr = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM client_payments WHERE project_id=?", (p["id"],))["s"]
        cv = c["contract_value"] if c else 0
        data.append([p["name"], clients.get(p["client_id"], "-"), p["project_type"], p["status"],
                     p["start_date"], p["end_date"], cv, tc, tr, cv - tc])
    headers = ["المشروع", "العميل", "النوع", "الحالة", "البداية", "النهاية",
               "قيمة العقد", "التكلفة", "المحصل", "الربح"]
    if request.args.get("fmt") == "pdf":
        totals = ["الإجمالي", "", "", "", "", "",
                  sum(d[6] for d in data), sum(d[7] for d in data),
                  sum(d[8] for d in data), sum(d[9] for d in data)]
        buf = px.build_pdf_report("تقرير المشاريع",
                                  [f"الشركة: {_export_company()['name']}"],
                                  headers, data, num_cols=(6, 7, 8, 9),
                                  totals_row=totals, landscape=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "تقرير_المشاريع.pdf")
    wb, ws, _ = xl.build_report("المشاريع", "تقرير المشاريع",
                                [f"الشركة: {_export_company()['name']}",
                                 f"التاريخ: {datetime.now().strftime('%Y-%m-%d')}"],
                                headers, data, totals=["", "", "", "", "", "",
                                                       sum(d[6] for d in data), sum(d[7] for d in data),
                                                       sum(d[8] for d in data), sum(d[9] for d in data)],
                                num_cols=(6, 7, 8, 9))
    return send_file(xl.to_bytes(wb), as_attachment=True,
                     download_name="تقرير_المشاريع.xlsx")


@app.route("/export/costs")
@require_write
def export_costs():
    rows = db.query("SELECT * FROM project_costs ORDER BY id DESC")
    projm = {p["id"]: p["name"] for p in db.query("SELECT id,name FROM projects")}
    data = [[projm.get(r["project_id"], "-"), r["cost_date"], r["cost_type"],
             r["description"], r["quantity"], r["amount"]] for r in rows]
    headers = ["المشروع", "التاريخ", "النوع", "البيان", "الكمية", "المبلغ"]
    if request.args.get("fmt") == "pdf":
        buf = px.build_pdf_report("تقرير تكاليف المشاريع",
                                  [f"الشركة: {_export_company()['name']}"],
                                  headers, data, num_cols=(4, 5),
                                  totals_row=["الإجمالي", "", "", "", "", sum(d[5] for d in data)],
                                  landscape=True, company=_export_company()["name"])
        return _send_pdf(buf, "تقرير_التكاليف.pdf")
    wb, ws, _ = xl.build_report("التكاليف", "تقرير تكاليف المشاريع",
                                [f"الشركة: {_export_company()['name']}"],
                                headers, data, totals=["", "", "", "", "", sum(d[5] for d in data)],
                                num_cols=(4, 5))
    return send_file(xl.to_bytes(wb), as_attachment=True, download_name="تقرير_التكاليف.xlsx")


# ==================================================================
# كشف المتأخرات (عملاء مستحق علينا / موردون مستحق لهم)
# ==================================================================
def _aging_rows():
    today = date.today()

    def ddiff(d):
        try:
            return (today - datetime.strptime((d or "")[:10], "%Y-%m-%d").date()).days
        except Exception:
            return 9999

    def bucket(d):
        return 0 if d <= 30 else 1 if d <= 60 else 2 if d <= 90 else 3

    rows = []
    # 1) المبالغ المستحقة لنا على العملاء (مستخلصات غير محصلة)
    for p in db.query("SELECT * FROM projects"):
        pid = p["id"]
        interims = db.query("SELECT * FROM interim_payments WHERE project_id=? "
                            "ORDER BY payment_date, id", (pid,))
        recv = sum(_num(r["amount"]) for r in db.query(
            "SELECT amount FROM client_payments WHERE project_id=?", (pid,)))
        used = 0.0
        buckets = [0.0, 0.0, 0.0, 0.0]
        for it in interims:
            net = _num(it["net_payment"])
            applied = min(net, max(recv - used, 0.0))
            unpaid = net - applied
            used += applied
            if unpaid > 0.01:
                buckets[bucket(ddiff(it["payment_date"]))] += unpaid
        if sum(buckets) > 0.01:
            rows.append(["عميل", p["name"], "مستخلصات غير محصلة",
                         round(sum(buckets), 2), [round(b, 2) for b in buckets]])
    # 2) المبالغ المستحقة للموردين (فواتير غير مسددة)
    for si in db.query("SELECT si.*, s.name AS supplier_name FROM supplier_invoices si "
                       "LEFT JOIN suppliers s ON s.id=si.supplier_id"):
        if si.get("paid"):
            continue
        remaining = _num(si["amount"])
        if remaining <= 0.01:
            continue
        buckets = [0.0, 0.0, 0.0, 0.0]
        d = ddiff(si["due_date"] or si["invoice_date"] or "")
        buckets[bucket(d)] = round(remaining, 2)
        rows.append(["مورد", si["supplier_name"] or "-", f"فاتورة {si['invoice_no'] or ('#' + str(si['id']))}",
                     round(remaining, 2), [round(b, 2) for b in buckets]])
    # فرز: الأقدم أولًا
    rows.sort(key=lambda r: -sum(r[4][i] * (10 ** i) for i in range(4)))
    totals = {"clients": 0.0, "suppliers": 0.0, "buckets": [0.0, 0.0, 0.0, 0.0]}
    for r in rows:
        if r[0] == "عميل":
            totals["clients"] += r[3]
        else:
            totals["suppliers"] += r[3]
        for i in range(4):
            totals["buckets"][i] += r[4][i]
    return rows, totals


@app.route("/aging")
@require_write
def aging():
    rows, totals = _aging_rows()
    return render_template("aging.html", rows=rows, totals=totals)


@app.route("/export/aging")
@require_write
def export_aging():
    rows, totals = _aging_rows()
    headers = ["الجهة", "الطرف", "البيان", "الإجمالي", "حتى 30 يومًا", "31–60 يوم", "61–90 يوم", "أكثر من 90 يوم"]
    data = [[r[0], r[1], r[2], r[3], *r[4]] for r in rows]
    trow = ["الإجمالي", "", "", round(totals["clients"] + totals["suppliers"], 2),
            *[round(b, 2) for b in totals["buckets"]]]
    if request.args.get("fmt") == "pdf":
        buf = px.build_pdf_report("كشف المتأخرات",
                                  [f"الشركة: {_export_company()['name']}",
                                   f"مستحق لنا على العملاء: {totals['clients']:,.2f} — مستحق للموردين: {totals['suppliers']:,.2f}",
                                   _exp_sub()],
                                  headers, data, num_cols=(3, 4, 5, 6, 7),
                                  totals_row=trow, landscape=True, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "كشف_المتأخرات.pdf")
    wb, ws, _ = xl.build_report("كشف المتأخرات", "كشف المتأخرات",
                                [f"الشركة: {_export_company()['name']}"],
                                headers, data, totals=trow, num_cols=(3, 4, 5, 6, 7))
    return send_file(xl.to_bytes(wb), as_attachment=True, download_name="كشف_المتأخرات.xlsx")


# ==================================================================
# تقرير ضريبة القيمة المضافة (من الفواتير الضريبية المصدرة)
# ==================================================================
@app.route("/vat")
@require_write
def vat_report():
    rows = db.query("SELECT * FROM tax_invoices ORDER BY invoice_date, id")
    totals = {
        "net": sum(_num(r["total_net"]) for r in rows),
        "vat": sum(_num(r["vat_amount"]) for r in rows),
        "total": sum(_num(r["total_with_vat"]) for r in rows),
    }
    return render_template("vat.html", rows=rows, totals=totals)


@app.route("/export/vat")
@require_write
def export_vat():
    rows = db.query("SELECT * FROM tax_invoices ORDER BY invoice_date, id")
    headers = ["رقم الفاتورة", "التاريخ", "العميل", "البيان", "الصافي", "الضريبة", "الإجمالي"]
    data = [[r["invoice_no"], r["invoice_date"] or "-", r["client_name"] or "-",
             r["description"] or "", r["total_net"], r["vat_amount"], r["total_with_vat"]] for r in rows]
    trow = ["الإجمالي", "", "", "",
            sum(_num(r["total_net"]) for r in rows),
            sum(_num(r["vat_amount"]) for r in rows),
            sum(_num(r["total_with_vat"]) for r in rows)]
    if request.args.get("fmt") == "pdf":
        buf = px.build_pdf_report("تقرير ضريبة القيمة المضافة",
                                  [f"الشركة: {_export_company()['name']}",
                                   f"الرقم الضريبي: {_export_company()['tax_no'] or '-'}", _exp_sub()],
                                  headers, data, num_cols=(4, 5, 6),
                                  totals_row=trow, landscape=True, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "تقرير_ضريبة_القيمة_المضافة.pdf")
    wb, ws, _ = xl.build_report("تقريض القيمة المضافة", "تقرير ضريبة القيمة المضافة",
                                [f"الشركة: {_export_company()['name']}"],
                                headers, data, totals=trow, num_cols=(4, 5, 6))
    return send_file(xl.to_bytes(wb), as_attachment=True,
                     download_name="تقرير_ضريبة_القيمة_المضافة.xlsx")


# ==================================================================
# تصدير التقارير المحاسبية (إكسل منسّق) + الاستيراد من القوالب
# ==================================================================
def _exp_sigs():
    try:
        return json.loads(db.get_setting("signatures", "[]") or "[]")
    except Exception:
        return []


def _exp_user():
    u = getattr(g, "user", None) or {}
    return u.get("full_name") or u.get("username") or ""


def _exp_sub():
    return f"التاريخ: {datetime.now().strftime('%Y-%m-%d')}"


def _send_pdf(buf, name):
    return send_file(buf, as_attachment=True, download_name=name,
                     mimetype="application/pdf")


def _journal_export_entries():
    """يرجع القيود مع بنودها وبيانات الحساب والمنطقة (اسم المشروع) جاهزة للتصدير."""
    entries = db.query("SELECT * FROM journal_entries ORDER BY entry_date, id")
    accs = {a["id"]: a for a in db.query("SELECT * FROM accounts")}
    projm = {p["id"]: p["name"] for p in db.query("SELECT id,name FROM projects")}
    out = []
    for e in entries:
        lines = db.query("SELECT * FROM journal_lines WHERE entry_id=?", (e["id"],))
        for ln in lines:
            a = accs.get(ln["account_id"]) or {}
            ln["acc_no"] = a.get("acc_no", "")
            ln["name"] = a.get("name", "")
        e = dict(e)
        e["lines"] = lines
        e["region"] = projm.get(e.get("project_id"), "") or ""
        ed = e.get("entry_date") or ""
        if not ed:
            ed = (e.get("created_at") or "")[:10] or "2026-01-01"
        e["entry_date"] = ed
        out.append(e)
    return out


@app.route("/export/accounts")
@require_write
def export_accounts_xlsx():
    accounts = db.query("SELECT * FROM accounts ORDER BY acc_no")
    if request.args.get("fmt") == "pdf":
        rows = [[a["acc_no"], a["name"], a["type"], a["opening_balance"]] for a in accounts]
        headers = ["رقم الحساب", "اسم الحساب", "النوع", "رصيد افتتاحي"]
        buf = px.build_pdf_report("دليل الحسابات",
                                  [f"الشركة: {_export_company()['name']}"],
                                  headers, rows, num_cols=(3,), landscape=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "دليل_الحسابات.pdf")
    buf = xl.export_accounts(accounts, _export_company()["name"],
                             acc_user=_exp_user(), signatures=_exp_sigs())
    return send_file(buf, as_attachment=True, download_name="دليل_الحسابات.xlsx")


@app.route("/export/journal")
@require_write
def export_journal_xlsx():
    entries = _journal_export_entries()
    if request.args.get("fmt") == "pdf":
        rows = []
        for e in entries:
            for ln in e["lines"]:
                rows.append([e["entry_date"], e["movement_no"], e["description"] or "",
                             e["region"], ln["acc_no"], ln["name"], ln["debit"], ln["credit"]])
        headers = ["التاريخ", "رقم القيد", "البيان", "المشروع", "رقم الحساب",
                   "اسم الحساب", "مدين", "دائن"]
        totals = ["", "", "", "", "", "", sum(r[6] for r in rows), sum(r[7] for r in rows)]
        buf = px.build_pdf_report("دفتر اليومية العام",
                                  [f"الشركة: {_export_company()['name']}", _exp_sub()],
                                  headers, rows, num_cols=(4, 6, 7), totals_row=totals,
                                  landscape=True, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "دفتر_اليومية.pdf")
    buf = xl.export_journal(entries, _export_company()["name"],
                            subtitle_extra=_exp_sub(),
                            acc_user=_exp_user(), signatures=_exp_sigs())
    return send_file(buf, as_attachment=True, download_name="دفتر_اليومية.xlsx")


@app.route("/export/ledger")
@require_write
def export_ledger_xlsx():
    aid = request.args.get("account_id", type=int)
    account = db.query_one("SELECT * FROM accounts WHERE id=?", (aid,))
    if not account:
        account = db.query_one("SELECT * FROM accounts ORDER BY acc_no")
        if not account:
            flash("لا توجد حسابات للتصدير", "err")
            return redirect(url_for("ledger"))
    projm = {p["id"]: p["name"] for p in db.query("SELECT id,name FROM projects")}
    lines = db.query("SELECT * FROM journal_lines WHERE account_id=? ORDER BY entry_id",
                     (account["id"],))
    eids = [ln["entry_id"] for ln in lines]
    eby = {}
    if eids:
        marks = ",".join("?" for _ in eids)
        for e in db.query(f"SELECT * FROM journal_entries WHERE id IN ({marks})", tuple(eids)):
            if isinstance(e["entry_date"], str) and e["entry_date"]:
                e["entry_date"] = e["entry_date"][:10]
            eby[e["id"]] = e
    rows = []
    bal = account["opening_balance"] or 0
    for ln in lines:
        e = eby.get(ln["entry_id"]) or {}
        bal += (_num(ln["debit"]) - _num(ln["credit"]))
        edate = e.get("entry_date") or (e.get("created_at") or "")[:10] or "2026-01-01"
        rows.append({"date": edate,
                     "movement_no": e.get("movement_no", ""),
                     "description": e.get("description", ""),
                     "region": projm.get(e.get("project_id"), "") or "",
                     "debit": _num(ln["debit"]), "credit": _num(ln["credit"]),
                     "balance": bal})
    totals = {"debit": sum(_num(l["debit"]) for l in lines),
              "credit": sum(_num(l["credit"]) for l in lines),
              "balance": bal}
    if request.args.get("fmt") == "pdf":
        pdf_rows = [[r["date"], r["movement_no"], r["description"], r["region"],
                     r["debit"], r["credit"], r["balance"]] for r in rows]
        headers = ["التاريخ", "رقم القيد", "البيان", "المشروع", "مدين", "دائن", "الرصيد"]
        pdf_totals = ["", "", "", "", totals["debit"], totals["credit"], totals["balance"]]
        buf = px.build_pdf_report(f"كشف حساب — {account['name']} ({account['acc_no']})",
                                  [f"الشركة: {_export_company()['name']}", _exp_sub()],
                                  headers, pdf_rows, num_cols=(4, 5, 6), totals_row=pdf_totals,
                                  landscape=True, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, f"الأستاذ_العام_{account['acc_no']}.pdf")
    buf = xl.export_ledger(account, account["opening_balance"] or 0, rows, totals,
                           _export_company()["name"], subtitle_extra=_exp_sub(),
                           acc_user=_exp_user(), signatures=_exp_sigs())
    return send_file(buf, as_attachment=True,
                     download_name=f"الأستاذ_العام_{account['acc_no']}.xlsx")


@app.route("/export/trial-balance")
@require_write
def export_trial_xlsx():
    accounts = db.query("SELECT * FROM accounts ORDER BY acc_no")
    rows = []
    totals = {"o_debit": 0, "o_credit": 0, "p_debit": 0, "p_credit": 0, "f_debit": 0, "f_credit": 0}
    for a in accounts:
        ob = a["opening_balance"] or 0
        ld = db.query("SELECT COALESCE(SUM(debit),0) s FROM journal_lines WHERE account_id=?", (a["id"],))[0]["s"]
        lc = db.query("SELECT COALESCE(SUM(credit),0) s FROM journal_lines WHERE account_id=?", (a["id"],))[0]["s"]
        bal = ob + (ld or 0) - (lc or 0)
        o_d = ob if ob > 0 else 0.0
        o_c = -ob if ob < 0 else 0.0
        f_d = bal if bal > 0 else 0.0
        f_c = -bal if bal < 0 else 0.0
        rows.append([a["acc_no"], a["name"], o_d, o_c, ld or 0, lc or 0, f_d, f_c])
        totals["o_debit"] += o_d
        totals["o_credit"] += o_c
        totals["p_debit"] += ld or 0
        totals["p_credit"] += lc or 0
        totals["f_debit"] += f_d
        totals["f_credit"] += f_c
    if request.args.get("fmt") == "pdf":
        headers = ["رقم", "اسم الحساب", "رصيد افتتاحي مدين", "رصيد افتتاحي دائن",
                   "حركة مدين", "حركة دائن", "رصيد مدين", "رصيد دائن"]
        pdf_totals = ["", "الإجمالي", totals["o_debit"], totals["o_credit"],
                      totals["p_debit"], totals["p_credit"], totals["f_debit"], totals["f_credit"]]
        buf = px.build_pdf_report("ميزان المراجعة",
                                  [f"الشركة: {_export_company()['name']}", _exp_sub()],
                                  headers, rows, num_cols=(2, 3, 4, 5, 6, 7),
                                  totals_row=pdf_totals, landscape=True, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "ميزان_المراجعة.pdf")
    buf = xl.export_trial(rows, totals, _export_company()["name"],
                          subtitle_extra=_exp_sub(),
                          acc_user=_exp_user(), signatures=_exp_sigs())
    return send_file(buf, as_attachment=True, download_name="ميزان_المراجعة.xlsx")


def _financial_data():
    accounts = db.query("SELECT * FROM accounts ORDER BY acc_no")
    items = []
    for a in accounts:
        ld = db.query("SELECT COALESCE(SUM(debit),0) s FROM journal_lines WHERE account_id=?", (a["id"],))[0]["s"]
        lc = db.query("SELECT COALESCE(SUM(credit),0) s FROM journal_lines WHERE account_id=?", (a["id"],))[0]["s"]
        items.append({**a, "bal": (a["opening_balance"] or 0) + (ld or 0) - (lc or 0)})
    revenues = [{"acc_no": b["acc_no"], "name": b["name"], "amount": round(b["bal"], 2)} for b in items if b["type"] == "إيرادات"]
    expenses = [{"acc_no": b["acc_no"], "name": b["name"], "amount": round(b["bal"], 2)} for b in items if b["type"] == "مصروفات"]
    assets = [{"acc_no": b["acc_no"], "name": b["name"], "amount": round(b["bal"], 2)} for b in items if b["type"] == "أصول"]
    liabs = [{"acc_no": b["acc_no"], "name": b["name"], "amount": round(b["bal"], 2)} for b in items if b["type"] == "خصوم"]
    equity = [{"acc_no": b["acc_no"], "name": b["name"], "amount": round(b["bal"], 2)} for b in items if b["type"] == "حقوق ملكية"]
    tl_rev = round(sum(x["amount"] for x in revenues), 2)
    tl_exp = round(sum(x["amount"] for x in expenses), 2)
    net = round(tl_rev - tl_exp, 2)
    ta = round(sum(x["amount"] for x in assets), 2)
    tle = round(sum(x["amount"] for x in liabs) + sum(x["amount"] for x in equity), 2)
    diff = round(ta - (tle + net), 2)
    return {
        "revenues": revenues, "revenues_total": tl_rev,
        "expenses": expenses, "expenses_total": tl_exp,
        "net": net,
        "assets": assets, "assets_total": ta,
        "liabilities_equity": liabs + equity, "liab_equity_total": tle,
        "net_cumulative": net, "balanced": abs(diff) < 0.01, "difference": diff,
    }


@app.route("/export/income")
@require_write
def export_income_xlsx():
    data = _financial_data()
    if request.args.get("fmt") == "pdf":
        rows = [["الإيرادات", "", ""]]
        for x in data["revenues"]:
            rows.append([x["acc_no"], x["name"], x["amount"]])
        rows.append(["المصروفات", "", ""])
        for x in data["expenses"]:
            rows.append([x["acc_no"], x["name"], x["amount"]])
        headers = ["رقم الحساب", "البيان", "المبلغ"]
        buf = px.build_pdf_report("قائمة الدخل",
                                  [f"الشركة: {_export_company()['name']}", _exp_sub()],
                                  headers, rows, num_cols=(2,),
                                  totals_row=["صافي الدخل", "", data["net"]],
                                  landscape=False, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "قائمة_الدخل.pdf")
    buf = xl.export_income(data, _export_company()["name"],
                           subtitle_extra=_exp_sub(),
                           acc_user=_exp_user(), signatures=_exp_sigs())
    return send_file(buf, as_attachment=True, download_name="قائمة_الدخل.xlsx")


@app.route("/export/balance")
@require_write
def export_balance_xlsx():
    data = _financial_data()
    if request.args.get("fmt") == "pdf":
        rows = [["الأصول", "", ""]]
        for x in data["assets"]:
            rows.append([x["acc_no"], x["name"], x["amount"]])
        rows.append(["الخصوم وحقوق الملكية", "", ""])
        for x in data["liabilities_equity"]:
            rows.append([x["acc_no"], x["name"], x["amount"]])
        headers = ["رقم الحساب", "البيان", "المبلغ"]
        buf = px.build_pdf_report("المركز المالي",
                                  [f"الشركة: {_export_company()['name']}", _exp_sub()],
                                  headers, rows, num_cols=(2,),
                                  totals_row=["مجموع الأصول", "", data["assets_total"]],
                                  signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "المركز_المالي.pdf")
    buf = xl.export_balance(data, _export_company()["name"],
                            subtitle_extra=_exp_sub(),
                            acc_user=_exp_user(), signatures=_exp_sigs())
    return send_file(buf, as_attachment=True, download_name="المركز_المالي.xlsx")


@app.route("/export/cashflow/xlsx")
@require_write
def export_cashflow_xlsx():
    cash_accts = db.query("SELECT * FROM accounts WHERE acc_no IN (?,?) ORDER BY acc_no", ("1101", "1102"))
    rows, t = [], {"opening": 0, "inflow": 0, "outflow": 0, "closing": 0}
    if not cash_accts:
        cash_accts = db.query("SELECT * FROM accounts WHERE name LIKE ? OR name LIKE ? ORDER BY acc_no",
                              ("%صندوق%", "%بنك%"))
    for a in cash_accts:
        ld = db.query("SELECT COALESCE(SUM(debit),0) s FROM journal_lines WHERE account_id=?", (a["id"],))[0]["s"]
        lc = db.query("SELECT COALESCE(SUM(credit),0) s FROM journal_lines WHERE account_id=?", (a["id"],))[0]["s"]
        opening = a["opening_balance"] or 0
        inflow, outflow = (ld or 0), (lc or 0)
        closing = opening + inflow - outflow
        rows.append({"acc_no": a["acc_no"], "name": a["name"], "opening": opening,
                     "inflow": inflow, "outflow": outflow, "closing": closing})
        t["opening"] += opening
        t["inflow"] += inflow
        t["outflow"] += outflow
        t["closing"] += closing
    if request.args.get("fmt") == "pdf":
        pdf_rows = [[r["acc_no"], r["name"], r["opening"], r["inflow"], r["outflow"], r["closing"]]
                    for r in rows]
        headers = ["رقم", "الحساب", "الرصيد الافتتاحي", "وارد", "منصرف", "الرصيد الختامي"]
        buf = px.build_pdf_report("التدفقات النقدية (مبسّط)",
                                  [f"الشركة: {_export_company()['name']}", _exp_sub()],
                                  headers, pdf_rows, num_cols=(2, 3, 4, 5),
                                  totals_row=["", "الإجمالي", t["opening"], t["inflow"],
                                              t["outflow"], t["closing"]],
                                  landscape=True, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, "التدفقات_النقدية.pdf")
    buf = xl.export_cashflow({"rows": rows, "totals": t}, _export_company()["name"],
                             subtitle_extra=_exp_sub(),
                             acc_user=_exp_user(), signatures=_exp_sigs())
    return send_file(buf, as_attachment=True, download_name="التدفقات_النقدية.xlsx")


def _deliver(title, sheet, headers, rows, file_base, num_cols=(), date_cols=(),
             totals=None, landscape=True, extra_subs=None):
    """تسليم تصدير موحّد: fmt=pdf يُرجع PDF منسّق، وإلا إكسل منسّق — بنفس ورقة البيانات."""
    subs = [f"الشركة: {_export_company()['name']}"]
    if extra_subs:
        subs += list(extra_subs)
    subs.append(_exp_sub())
    if request.args.get("fmt") == "pdf":
        buf = px.build_pdf_report(title, subs, headers, rows, num_cols=num_cols,
                                  totals_row=totals, landscape=landscape, signatures=True,
                                  company=_export_company()["name"])
        return _send_pdf(buf, file_base + ".pdf")
    buf = xl.export_table(sheet, title, headers, rows, subtitles=subs, totals=totals,
                          num_cols=num_cols, date_cols=date_cols, landscape=landscape,
                          acc_user=_exp_user(), signatures=_exp_sigs())
    return send_file(buf, as_attachment=True, download_name=file_base + ".xlsx")


@app.route("/export/stock")
@require_write
def export_stock():
    movements = db.query(
        "SELECT sm.*, m.name AS material_name, p.name AS project_name, s.name AS supplier_name "
        "FROM stock_movements sm "
        "LEFT JOIN materials m ON m.id=sm.material_id "
        "LEFT JOIN projects p ON p.id=sm.project_id "
        "LEFT JOIN suppliers s ON s.id=sm.supplier_id "
        "ORDER BY sm.movement_date DESC, sm.id DESC")
    rows = [[mv["movement_date"], mv["material_name"], mv["movement_type"],
             mv["quantity"], mv["unit_price"], mv["total"],
             mv["project_name"], mv["supplier_name"], mv["reference"] or ""] for mv in movements]
    headers = ["التاريخ", "المادة", "النوع", "الكمية", "سعر الوحدة",
               "الإجمالي", "المشروع", "المورد", "المرجع"]
    return _deliver("سجل حركة المخازن", "سجل حركة المخازن", headers, rows,
                    "سجل_حركة_المخازن", num_cols=(3, 4, 5), landscape=True)


@app.route("/export/payroll")
@require_write
def export_payroll():
    rows = db.query("SELECT py.*, w.name AS worker_name FROM payroll py "
                    "LEFT JOIN workers w ON w.id=py.worker_id "
                    "ORDER BY py.period DESC, py.id DESC")
    out = [[r["period"], r["worker_name"], r["days_worked"], r["gross"],
            r["deductions"], r["net"], "مسدد" if r["status"] == "مسدد" else r["status"] or "مسجل"]
           for r in rows]
    headers = ["الفترة", "العامل", "أيام العمل", "الإجمالي", "الخصومات", "الصافي", "الحالة"]
    totals = ["", "الإجمالي", "", round(sum(r[3] for r in out), 2),
              round(sum(r[4] for r in out), 2), round(sum(r[5] for r in out), 2), ""] if out else None
    return _deliver("مسير رواتب العمالة", "مسير رواتب العمالة", headers, out,
                    "مسير_الرواتب", num_cols=(2, 3, 4, 5), totals=totals, landscape=True)


@app.route("/export/depreciation")
@require_write
def export_depreciation():
    rows = db.query("SELECT d.*, e.name AS equipment_name, e.purchase_cost "
                    "FROM depreciation d LEFT JOIN equipment e ON e.id=d.equipment_id "
                    "ORDER BY d.period DESC, d.id DESC")
    out = [[r["period"], r["equipment_name"], r["purchase_cost"], r["amount"]] for r in rows]
    headers = ["الفترة", "المعدة", "تكلفة الشراء", "قيمة الإهلاك"]
    totals = ["", "الإجمالي", round(sum(r[2] for r in out), 2),
              round(sum(r[3] for r in out), 2)] if out else None
    return _deliver("سجل إهلاك المعدات", "سجل إهلاك المعدات", headers, out,
                    "سجل_الإهلاك", num_cols=(2, 3), totals=totals, landscape=False)


@app.route("/export/registry/<table>")
@require_write
def registry_export(table):
    if table not in REGISTRY:
        abort(404)
    title, cols, colkeys, fields, icon = REGISTRY[table]
    items = db.query(f"SELECT * FROM {table} ORDER BY id DESC")
    rows = [[it[k] for k in colkeys] for it in items]
    return _deliver(f"قائمة {title}", f"قائمة {title}", cols, rows,
                    f"قائمة_{title}".replace(" ", "_"), landscape=False)


@app.route("/export/supplier-invoices")
@require_write
def export_supplier_invoices():
    rows = db.query("SELECT si.*, su.name AS supplier_name FROM supplier_invoices si "
                    "LEFT JOIN suppliers su ON su.id=si.supplier_id "
                    "ORDER BY si.invoice_date DESC, si.id DESC")
    out = [[r["supplier_name"], r["invoice_no"] or "", r["invoice_date"] or "",
            r["due_date"] or "", r["amount"], "مسددة" if r["paid"] else "غير مسددة",
            r["payment_date"] or ""] for r in rows]
    headers = ["المورد", "رقم الفاتورة", "التاريخ", "تاريخ الاستحقاق",
               "المبلغ", "الحالة", "تاريخ السداد"]
    totals = ["", "", "", "", round(sum(r[4] for r in out), 2), "", ""] if out else None
    return _deliver("فواتير الموردين", "فواتير الموردين", headers, out,
                    "فواتير_الموردين", num_cols=(4,), totals=totals, landscape=True)


@app.route("/export/audit")
@require_write
def export_audit():
    rows = db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500")
    out = [[r["id"], r["user"], r["action"], r["details"], r["at"]] for r in rows]
    headers = ["#", "المستخدم", "العملية", "التفاصيل", "الوقت"]
    return _deliver("سجل العمليات (المُراجعة)", "سجل العمليات", headers, out,
                    "سجل_العمليات", date_cols=(4,), landscape=True)


@app.route("/export/contracts")
@require_write
def export_contracts():
    rows = db.query("SELECT c.*, p.name AS project_name, cl.name AS client_name "
                    "FROM contracts c "
                    "LEFT JOIN projects p ON p.id=c.project_id "
                    "LEFT JOIN clients cl ON cl.id=p.client_id "
                    "ORDER BY c.contract_date DESC, c.id DESC")
    out = [[r["contract_no"] or "", r["project_name"], r["client_name"] or "",
            r["contract_date"] or "", r["contract_value"], r["advance_amount"],
            r["retention_amount"], r["retention_release_date"] or "", r["duration_days"]]
           for r in rows]
    headers = ["رقم العقد", "المشروع", "العميل", "التاريخ", "قيمة العقد",
               "العربون المقدم", "الضمان", "تاريخ إفراج الضمان", "المدة (يوم)"]
    totals = ["", "", "", "", round(sum(r[4] for r in out), 2),
              round(sum(r[5] for r in out), 2), round(sum(r[6] for r in out), 2), "", ""] if out else None
    return _deliver("العقود", "عقود المشاريع", headers, out,
                    "العقود", num_cols=(4, 5, 6), totals=totals, landscape=True)


@app.route("/export/interim")
@require_write
def export_interim():
    rows = db.query("SELECT ip.*, p.name AS project_name FROM interim_payments ip "
                    "LEFT JOIN projects p ON p.id=ip.project_id "
                    "ORDER BY ip.payment_date DESC, ip.id DESC")
    out = [[r["payment_no"], r["project_name"], r["payment_date"], r["work_value"],
            r["retention_amount"], r["previous_payments"], r["net_payment"],
            r["actual_received"], r["status"] or "مقدم"] for r in rows]
    headers = ["الرقم", "المشروع", "التاريخ", "قيمة الأعمال", "الضمان",
               "المستخلصات السابقة", "الصافي", "المحصل", "الحالة"]
    totals = ["", "", "", round(sum(r[3] for r in out), 2),
              round(sum(r[4] for r in out), 2), round(sum(r[5] for r in out), 2),
              round(sum(r[6] for r in out), 2), round(sum(r[7] for r in out), 2), ""] if out else None
    return _deliver("كشوف المستخلصات", "كشوف المستخلصات", headers, out,
                    "المستخلصات", num_cols=(3, 4, 5, 6, 7), totals=totals, landscape=True)


@app.route("/export/accounts/template")
@require_write
def accounts_template_download():
    return send_file(xl.blank_template_accounts(), as_attachment=True,
                     download_name="قالب_دليل_الحسابات.xlsx")


@app.route("/export/journal/template")
@require_write
def journal_template_download():
    return send_file(xl.blank_template_journal(), as_attachment=True,
                     download_name="قالب_دفتر_اليومية.xlsx")


def _find_account_ref(acc_no, name):
    if acc_no:
        a = db.query_one("SELECT id FROM accounts WHERE acc_no=?", (acc_no,))
        if a:
            return a["id"]
    if name:
        a = db.query_one("SELECT id FROM accounts WHERE TRIM(name)=TRIM(?)", (name,))
        if a:
            return a["id"]
    return None


@app.route("/import/accounts", methods=["POST"])
@require_write
def import_accounts():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("اختر ملف إكسيل أولاً", "err")
        return redirect(url_for("accounts"))
    rows, errors = xl.read_accounts_template(f.stream)
    added = 0
    for r in rows:
        if db.query_one("SELECT id FROM accounts WHERE acc_no=?", (r["acc_no"],)):
            errors.append(f"الحساب {r['acc_no']} موجود مسبقًا — تم تخطيه")
            continue
        db.execute("INSERT INTO accounts (acc_no, name, type, opening_balance) VALUES (?,?,?,?)",
                   (r["acc_no"], r["name"], r["type"] or "", r["opening"] or 0))
        added += 1
    db.audit(g.user["username"], "استيراد دليل حسابات", f"تمت إضافة {added} حساب")
    msg = f"تم استيراد {added} حساب بنجاح"
    if errors:
        msg += " — " + "؛ ".join(errors[:10])
    flash(msg, "ok" if added else "err")
    return redirect(url_for("accounts"))


@app.route("/import/journal", methods=["POST"])
@require_write
def import_journal():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("اختر ملف إكسيل أولاً", "err")
        return redirect(url_for("journal"))
    groups, errors = xl.read_journal_template(f.stream)
    added = 0
    for grp in groups:
        mv = grp["movement"] or ""
        if db.query_one("SELECT id FROM journal_entries WHERE movement_no=?", (mv,)):
            errors.append(f"حركة {mv} موجودة مسبقًا — تم تخطيها")
            continue
        final_lines = []
        skip = False
        for ln in grp["lines"]:
            aid = _find_account_ref(ln["acc_no"], ln["name"])
            if aid is None:
                errors.append(f"صف {ln['row']} (حركة {mv}): الحساب غير موجود — تم تخطي الحركة")
                skip = True
                break
            final_lines.append((aid, _num(ln["debit"]), _num(ln["credit"])))
        if skip or not final_lines:
            continue
        td = sum(d for _, d, _ in final_lines)
        tc = sum(c for _, _, c in final_lines)
        if abs(td - tc) > 0.01:
            errors.append(f"حركة {mv}: القيد غير متوازن (مدين {td:,.2f} ≠ دائن {tc:,.2f}) — تم تخطيها")
            continue
        edate = (grp["date"].strftime("%Y-%m-%d") if grp["date"] else "")
        desc = grp["desc"] or "استيراد من إكسيل"
        eid = db.execute(
            "INSERT INTO journal_entries (movement_no, entry_date, description, status, entry_type, created_by) "
            "VALUES (?,?,?,?,?,?)",
            (mv, edate, desc, "posted", "عادي", g.user["id"]))
        for aid, d, c in final_lines:
            db.execute("INSERT INTO journal_lines (entry_id, account_id, debit, credit) VALUES (?,?,?,?)",
                       (eid, aid, d, c))
        added += 1
    db.audit(g.user["username"], "استيراد دفتر يومية", f"تمت إضافة {added} قيد")
    msg = f"تم استيراد {added} قيد بنجاح"
    if errors:
        msg += " — " + "؛ ".join(errors[:10])
    flash(msg, "ok" if added else "err")
    return redirect(url_for("journal"))


@app.after_request
def _no_cache(response):
    if request.path.startswith("/export/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ==================================================================
# التدفقات النقدية (الحسابات البنكية والصندوق)
# ==================================================================
@app.route("/cashflow")
def cashflow():
    entries = db.query("SELECT * FROM journal_entries WHERE status='posted' ORDER BY entry_date, id")
    # نحسب صافي النقد من القيود على حسابات البنوك والصندوق (1101, 1102)
    cash_accounts = ("1101", "1102")
    acc_ids = [a["id"] for a in db.query(
        "SELECT id FROM accounts WHERE acc_no IN (?,?)", cash_accounts)]
    cash_flows = []
    for e in entries:
        lines = db.query("SELECT * FROM journal_lines WHERE entry_id=?", (e["id"],))
        flow = 0
        for ln in lines:
            if ln["account_id"] in acc_ids:
                flow += ln["debit"] - ln["credit"]
        if flow != 0:
            cash_flows.append({**e, "project_name": None, "flow": flow})
    projm = {p["id"]: p["name"] for p in db.query("SELECT id,name FROM projects")}
    for cf in cash_flows:
        if cf["project_id"]:
            cf["project_name"] = projm.get(cf["project_id"], "")
    inflow = sum(max(0, c["flow"]) for c in cash_flows)
    outflow = sum(max(0, -c["flow"]) for c in cash_flows)
    return render_template("cashflow.html", cash_flows=cash_flows, inflow=inflow, outflow=outflow)


# ------------------------------------------------------------------
# التقارير
# ------------------------------------------------------------------
@app.route("/reports")
def reports():
    projects = db.query("SELECT * FROM projects ORDER BY id DESC")
    report_rows = []
    total_cv = total_tc = total_rec = total_profit = 0
    for p in projects:
        c = db.query_one("SELECT contract_value FROM contracts WHERE project_id=?", (p["id"],))
        tc = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM project_costs WHERE project_id=?", (p["id"],))["s"]
        tr = db.query_one("SELECT COALESCE(SUM(amount),0) s FROM client_payments WHERE project_id=?", (p["id"],))["s"]
        cv = c["contract_value"] if c else 0
        profit = cv - tc
        total_cv += cv
        total_tc += tc
        total_rec += tr
        total_profit += profit
        report_rows.append({**p, "contract_value": cv, "cost": tc, "received": tr,
                            "profit": profit,
                            "profit_pct": (profit / cv * 100) if cv else 0})
    # تكلفة حسب النوع
    cost_by_type = {}
    for r in db.query("SELECT cost_type, COALESCE(SUM(amount),0) s FROM project_costs GROUP BY cost_type"):
        cost_by_type[r["cost_type"]] = r["s"]
    return render_template("reports.html", report_rows=report_rows,
                           total_cv=total_cv, total_tc=total_tc, total_rec=total_rec,
                           total_profit=total_profit, cost_by_type=cost_by_type)


# ==================================================================
# نقطة التشغيل
# ==================================================================
if __name__ == "__main__":
    try:
        if not os.path.exists(db.DB_PATH) or db.query_one("SELECT COUNT(*) c FROM users")["c"] == 0:
            db.init_db()
    except Exception:
        db.init_db()


    def _auto_backup_loop():
        while True:
            try:
                db.auto_daily_backup()
            except Exception:
                pass
            time.sleep(24 * 3600)


    threading.Thread(target=_auto_backup_loop, daemon=True).start()
    PORT = int(os.environ.get("PORT", "5010"))
    print("=" * 55)
    print("  نظام محاسبة المقاولات المتكامل")
    print("  يعمل الآن على:  http://127.0.0.1:%d" % PORT)
    print("  لإيقاف النظام استخدم:  إيقاف النظام.bat")
    print("=" * 55)
    if getattr(sys, "frozen", False):
        import webbrowser

        def _open_browser_when_ready():
            import socket as _sk
            for _ in range(60):
                try:
                    _s = _sk.create_connection(("127.0.0.1", PORT), timeout=1)
                    _s.close()
                    break
                except OSError:
                    time.sleep(0.5)
            webbrowser.open("http://127.0.0.1:%d" % PORT)

        threading.Thread(target=_open_browser_when_ready, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, debug=False)
