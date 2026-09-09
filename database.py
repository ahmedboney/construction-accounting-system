# -*- coding: utf-8 -*-
"""قاعدة البيانات SQLite — نظام محاسبة المقاولات المتكامل"""
import os
import re
import shutil
import sqlite3
import secrets
import sys
import json
from datetime import date, datetime
from pathlib import Path
from werkzeug.security import generate_password_hash

# البيانات تُحفظ بجوار الكود (أو بجوار الـ EXE في النسخة المجمّعة)
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).parent
elif os.environ.get("MOQAWALAT_DB"):
    BASE_DIR = Path(os.environ["MOQAWALAT_DB"])
else:
    BASE_DIR = Path(__file__).parent
INSTANCE_DIR = BASE_DIR / "instance"
DB_PATH = INSTANCE_DIR / "accounting.db"
SECRET_PATH = INSTANCE_DIR / "secret.key"
BACKUP_DIR = INSTANCE_DIR / "backups"

ACCOUNT_TYPES = ["أصول", "خصوم", "حقوق ملكية", "إيرادات", "مصروفات", "أخرى"]

# دليل حسابات ابتدائي مصمم خصيصًا لشركات المقاولات
STARTER_ACCOUNTS = [
    # الأصول المتداولة
    ("1101", "الصندوق", "أصول"),
    ("1102", "البنوك", "أصول"),
    ("1201", "العملاء (المالكون)", "أصول"),
    ("1202", "مستخلصات محصلة مقدماً", "أصول"),
    ("1203", "مدفوعات مقدمة للموردين", "أصول"),
    ("1301", "مخزن المواد", "أصول"),
    ("1302", "مخزون أعمال تحت التنفيذ (WIP)", "أصول"),
    # الأصول الثابتة
    ("1401", "الأصول الثابتة", "أصول"),
    ("1402", "مجمع الإهلاك", "أصول"),
    ("1403", "معدات التشغيل", "أصول"),
    ("1404", "مجمع إهلاك المعدات", "أصول"),
    # الخصوم
    ("2101", "الموردون", "خصوم"),
    ("2102", "مقاولو الباطن", "خصوم"),
    ("2103", "أجور ورواتب مستحقة", "خصوم"),
    ("2104", "ضمانات العملاء (محجوز)", "خصوم"),
    ("2105", "ضمانات مقاولي الباطن", "أصول"),
    ("2106", "ضرائب القيمة المضافة", "خصوم"),
    ("2107", "تأمينات اجتماعية", "خصوم"),
    ("2108", "مصروفات مستحقة", "خصوم"),
    ("2201", "قروض طويلة الأجل", "خصوم"),
    # حقوق الملكية
    ("3101", "رأس المال", "حقوق ملكية"),
    ("3102", "المسحوبات الشخصية", "حقوق ملكية"),
    ("3103", "الأرباح المحتجزة", "حقوق ملكية"),
    ("3104", "أرباح وخسائر العام", "حقوق ملكية"),
    # الإيرادات
    ("4101", "إيرادات التعاقدات", "إيرادات"),
    ("4102", "إيرادات خالصة المشاريع المكتملة", "إيرادات"),
    ("4103", "إيرادات أخرى", "إيرادات"),
    # المصروفات — تكاليف مباشرة وغير مباشرة
    ("5101", "تكاليف المواد المباشرة", "مصروفات"),
    ("5102", "تكاليف العمالة المباشرة", "مصروفات"),
    ("5103", "تكاليف المعدات", "مصروفات"),
    ("5104", "تكاليف مقاولي الباطن", "مصروفات"),
    ("5105", "مصروفات مباشرة أخرى للمشروع", "مصروفات"),
    ("5201", "رواتب وأجور إدارية", "مصروفات"),
    ("5202", "إيجارات", "مصروفات"),
    ("5203", "كهرباء ومياه", "مصروفات"),
    ("5204", "هاتف وإنترنت", "مصروفات"),
    ("5205", "صيانة", "مصروفات"),
    ("5206", "وقود ومواصلات", "مصروفات"),
    ("5207", "قرطاسية ومطبوعات", "مصروفات"),
    ("5208", "إعلانات ودعاية", "مصروفات"),
    ("5209", "مصروفات بنكية", "مصروفات"),
    ("5210", "إهلاك", "مصروفات"),
    ("5211", "ضرائب ورسوم", "مصروفات"),
    ("5212", "تأمينات المشروع", "مصروفات"),
    ("5213", "مصروفات متنوعة", "مصروفات"),
    ("9901", "حساب وسيط - سداد", "أخرى"),
    ("9902", "فروقات تسوية", "أخرى"),
]


def connect():
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def query(sql, args=()):
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]


def query_one(sql, args=()):
    rows = query(sql, args)
    return rows[0] if rows else None


def execute(sql, args=()):
    with connect() as conn:
        cur = conn.execute(sql, args)
        conn.commit()
        return cur.lastrowid


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'accountant',
    security_question TEXT DEFAULT '',
    security_answer_hash TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> السجلات الرئيسية للمقاولات <<<<<

CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    company TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    email TEXT DEFAULT '',
    address TEXT DEFAULT '',
    tax_no TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS suppliers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    company TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    email TEXT DEFAULT '',
    address TEXT DEFAULT '',
    tax_no TEXT DEFAULT '',
    payment_terms TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS subcontractors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT DEFAULT '',
    email TEXT DEFAULT '',
    address TEXT DEFAULT '',
    trade TEXT DEFAULT '',
    tax_no TEXT DEFAULT '',
    payment_terms TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS workers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    job TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    daily_rate REAL DEFAULT 0,
    monthly_salary REAL DEFAULT 0,
    ssn TEXT DEFAULT '',
    status TEXT DEFAULT 'نشط',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS equipment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    license_no TEXT DEFAULT '',
    category TEXT DEFAULT '',
    purchase_cost REAL DEFAULT 0,
    depreciation_rate REAL DEFAULT 0,
    status TEXT DEFAULT 'متاح',
    site TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS materials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    unit TEXT DEFAULT '',
    category TEXT DEFAULT '',
    cost_price REAL DEFAULT 0,
    min_stock REAL DEFAULT 0,
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> المشاريع والعقود <<<<<

CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    client_id INTEGER REFERENCES clients(id),
    project_type TEXT DEFAULT 'مباني',
    location TEXT DEFAULT '',
    engineer TEXT DEFAULT '',
    supervisor TEXT DEFAULT '',
    start_date TEXT DEFAULT '',
    end_date TEXT DEFAULT '',
    status TEXT DEFAULT 'جاري',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    contract_no TEXT DEFAULT '',
    contract_date TEXT DEFAULT '',
    contract_value REAL DEFAULT 0,
    advance_percent REAL DEFAULT 0,
    advance_amount REAL DEFAULT 0,
    retention_percent REAL DEFAULT 5,
    retention_amount REAL DEFAULT 0,
    retention_release_date TEXT DEFAULT '',
    duration_days INTEGER DEFAULT 0,
    terms TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS boq_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    item_no TEXT DEFAULT '',
    description TEXT NOT NULL,
    unit TEXT DEFAULT '',
    quantity REAL DEFAULT 0,
    unit_price REAL DEFAULT 0,
    total REAL DEFAULT 0,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS interim_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    payment_no TEXT DEFAULT '',
    payment_date TEXT DEFAULT '',
    description TEXT DEFAULT '',
    work_value REAL DEFAULT 0,
    retention_percent REAL DEFAULT 0,
    retention_amount REAL DEFAULT 0,
    retention_release INTEGER DEFAULT 0,
    previous_payments REAL DEFAULT 0,
    net_payment REAL DEFAULT 0,
    status TEXT DEFAULT 'مقدم',
    actual_received REAL DEFAULT 0,
    receive_date TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS client_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    payment_date TEXT DEFAULT '',
    amount REAL DEFAULT 0,
    method TEXT DEFAULT 'نقداً',
    reference TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> تكاليف المشروع <<<<<

CREATE TABLE IF NOT EXISTS project_costs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    cost_date TEXT DEFAULT '',
    cost_type TEXT DEFAULT 'مواد',
    description TEXT DEFAULT '',
    amount REAL DEFAULT 0,
    supplier_id INTEGER REFERENCES suppliers(id),
    worker_id INTEGER REFERENCES workers(id),
    equipment_id INTEGER REFERENCES equipment(id),
    sub_id INTEGER REFERENCES subcontractors(id),
    material_id INTEGER REFERENCES materials(id),
    quantity REAL DEFAULT 0,
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> المخازن <<<<<

CREATE TABLE IF NOT EXISTS stock_movements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    material_id INTEGER REFERENCES materials(id),
    project_id INTEGER REFERENCES projects(id),
    movement_date TEXT DEFAULT '',
    movement_type TEXT DEFAULT 'إدخال',
    quantity REAL DEFAULT 0,
    unit_price REAL DEFAULT 0,
    total REAL DEFAULT 0,
    supplier_id INTEGER REFERENCES suppliers(id),
    reference TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- حساب المشروع
CREATE TABLE IF NOT EXISTS supplier_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    supplier_id INTEGER REFERENCES suppliers(id),
    sub_id INTEGER REFERENCES subcontractors(id),
    payment_date TEXT DEFAULT '',
    amount REAL DEFAULT 0,
    method TEXT DEFAULT 'نقداً',
    reference TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> فواتير الموردين <<<<<
CREATE TABLE IF NOT EXISTS supplier_invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    supplier_id INTEGER NOT NULL REFERENCES suppliers(id) ON DELETE CASCADE,
    invoice_no TEXT DEFAULT '',
    invoice_date TEXT DEFAULT '',
    due_date TEXT DEFAULT '',
    amount REAL DEFAULT 0,
    paid INTEGER DEFAULT 0,
    payment_date TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> مسير رواتب العمالة <<<<<
CREATE TABLE IF NOT EXISTS payroll (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id INTEGER NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    period TEXT DEFAULT '',
    days_worked REAL DEFAULT 0,
    gross REAL DEFAULT 0,
    deductions REAL DEFAULT 0,
    net REAL DEFAULT 0,
    status TEXT DEFAULT 'مسجل',
    payment_date TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> إهلاك المعدات <<<<<
CREATE TABLE IF NOT EXISTS depreciation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    equipment_id INTEGER NOT NULL REFERENCES equipment(id) ON DELETE CASCADE,
    period TEXT DEFAULT '',
    amount REAL DEFAULT 0,
    posted INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> الميزانية التقديرية للمشروع <<<<<
CREATE TABLE IF NOT EXISTS budget_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    item_no TEXT DEFAULT '',
    description TEXT NOT NULL,
    unit TEXT DEFAULT '',
    quantity REAL DEFAULT 0,
    unit_price REAL DEFAULT 0,
    total REAL DEFAULT 0,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> العهد والأمانات (مبالغ مخوّلة للمشرفين) <<<<<
CREATE TABLE IF NOT EXISTS custody (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    custodian TEXT NOT NULL,
    project_id INTEGER REFERENCES projects(id),
    amount REAL DEFAULT 0,
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);
CREATE TABLE IF NOT EXISTS custody_ops (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    custody_id INTEGER NOT NULL REFERENCES custody(id) ON DELETE CASCADE,
    op_type TEXT DEFAULT 'صرف',
    amount REAL DEFAULT 0,
    op_date TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

-- >>>>> المحاسبة العامة <<<<<

CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    acc_no TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    type TEXT DEFAULT '',
    opening_balance REAL NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS journal_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    movement_no TEXT UNIQUE NOT NULL,
    entry_date TEXT NOT NULL,
    description TEXT DEFAULT '',
    project_id INTEGER REFERENCES projects(id),
    status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','posted')),
    entry_type TEXT DEFAULT 'عادي',
    created_by INTEGER REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now','localtime')),
    source_type TEXT DEFAULT '',
    source_id INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS journal_lines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES journal_entries(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    debit REAL NOT NULL DEFAULT 0,
    credit REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    action TEXT,
    details TEXT,
    at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE TABLE IF NOT EXISTS tax_invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_no TEXT UNIQUE NOT NULL,
    payment_id INTEGER DEFAULT 0,
    invoice_date TEXT DEFAULT '',
    client_name TEXT DEFAULT '',
    description TEXT DEFAULT '',
    total_net REAL DEFAULT 0,
    vat_rate REAL DEFAULT 0,
    vat_amount REAL DEFAULT 0,
    total_with_vat REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime'))
);

CREATE INDEX IF NOT EXISTS idx_boq_project ON boq_items(project_id);
CREATE INDEX IF NOT EXISTS idx_pay_project ON interim_payments(project_id);
CREATE INDEX IF NOT EXISTS idx_cost_project ON project_costs(project_id);
CREATE INDEX IF NOT EXISTS idx_stock_material ON stock_movements(material_id);
CREATE INDEX IF NOT EXISTS idx_lines_entry ON journal_lines(entry_id);
CREATE INDEX IF NOT EXISTS idx_lines_account ON journal_lines(account_id);
CREATE INDEX IF NOT EXISTS idx_entries_date ON journal_entries(entry_date);
CREATE INDEX IF NOT EXISTS idx_entries_status ON journal_entries(status);
CREATE INDEX IF NOT EXISTS idx_budget_project ON budget_items(project_id);
CREATE INDEX IF NOT EXISTS idx_payroll_worker ON payroll(worker_id);
CREATE INDEX IF NOT EXISTS idx_payroll_period ON payroll(period);
CREATE INDEX IF NOT EXISTS idx_inv_supplier ON supplier_invoices(supplier_id);
CREATE INDEX IF NOT EXISTS idx_dep_equipment ON depreciation(equipment_id);
CREATE INDEX IF NOT EXISTS idx_src_entries ON journal_entries(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_custody_project ON custody(project_id);
CREATE INDEX IF NOT EXISTS idx_custody_ops ON custody_ops(custody_id);
"""


def load_secret():
    SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SECRET_PATH.exists():
        return SECRET_PATH.read_bytes()
    key = secrets.token_hex(32).encode()
    SECRET_PATH.write_bytes(key)
    return key


def datetime_now():
    from datetime import datetime
    return datetime.now()


def init_db():
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect()
    conn.executescript(SCHEMA)

    default_users = [
        ("admin", "admin123", "مدير النظام", "admin"),
        ("accountant", "acc123", "محاسب", "accountant"),
        ("viewer", "viewer123", "مستخدم مشاهدة", "viewer"),
    ]
    for username, pwd, full_name, role in default_users:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, full_name, role) VALUES (?,?,?,?)",
            (username, generate_password_hash(pwd), full_name, role),
        )

    for acc_no, name, acc_type in STARTER_ACCOUNTS:
        conn.execute(
            "INSERT OR IGNORE INTO accounts (acc_no, name, type) VALUES (?,?,?)",
            (acc_no, name, acc_type),
        )

    year = datetime_now().year
    defaults = {
        "company_name": "شركة المقاولات",
        "company_address": "",
        "company_tax_no": "",
        "company_commercial_no": "",
        "financial_year": str(year),
        "currency": "جنيه مصري",
        "signatures": json.dumps([
            {"title": "مهندس المشروع", "name": ""},
            {"title": "المدير المالي", "name": ""},
            {"title": "رئيس الحسابات", "name": ""},
        ], ensure_ascii=False),
        "contract_default_retention": "5",
        "vat_rate": "0",
    }
    for k, v in defaults.items():
        conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?,?)", (k, v))

    conn.commit()
    conn.close()


def migrate():
    """ترقية قاعدة البيانات بأمان: ينشئ أي جداول/حقول جديدة عند كل تشغيل (لا يمس البيانات)."""
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        # أولًا: ترقية الجداول الموجودة (قبل إنشاء الفهارس).
        has_table = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='journal_entries'").fetchone()[0]
        if has_table:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(journal_entries)")}
            for colname, coltype in (("source_type", "TEXT"), ("source_id", "INTEGER")):
                if colname not in cols:
                    conn.execute(f"ALTER TABLE journal_entries ADD COLUMN {colname} {coltype} DEFAULT ''")
        has_inv = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='supplier_invoices'").fetchone()[0]
        if has_inv:
            icols = {r[1] for r in conn.execute("PRAGMA table_info(supplier_invoices)")}
            if "due_date" not in icols:
                conn.execute("ALTER TABLE supplier_invoices ADD COLUMN due_date TEXT DEFAULT ''")
        has_users = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'").fetchone()[0]
        if has_users:
            ucols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
            for colname, coltype in (("security_question", "TEXT"), ("security_answer_hash", "TEXT")):
                if colname not in ucols:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {colname} {coltype} DEFAULT ''")
        conn.commit()
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def get_setting(key, default=""):
    row = query_one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


def set_setting(key, value):
    execute(
        "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


def cleanup_duplicates(keep_latest=True):
    """إصلاح القيود المكررة الناتجة عن النسخ القديمة (نفس المصدر + نفس السطر مرتين).

    - يحذف أي قيد تلقائي له نفس (source_type, source_id) أكثر من نسخة واحدة،
      ويبقي الأحدث (أو الأقدم) ويتجاهل إعداده.
    - يمسح بنود أيتام (بنود بلا قيد أم).
    - يرجع dict فيه عدد العمليات المنفذة.
    """
    conn = connect()
    removed = {"duplicate_entries": 0, "duplicate_lines": 0, "orphan_lines": 0}
    try:
        # 1) القيود المكررة بنفس المصدر
        dup_groups = db_groups(conn, "SELECT source_type, source_id FROM journal_entries "
                                    "WHERE source_type<>'' AND source_id>0 "
                                    "GROUP BY source_type, source_id HAVING COUNT(*)>1")
        for source_type, source_id in dup_groups:
            ids = [r["id"] for r in conn.execute(
                "SELECT id FROM journal_entries WHERE source_type=? AND source_id=? ORDER BY id",
                (source_type, source_id)).fetchall()]
            keep = ids[-1] if keep_latest else ids[0]
            drop = [x for x in ids if x != keep]
            if drop:
                marks = ",".join("?" for _ in drop)
                cur = conn.execute(f"DELETE FROM journal_lines WHERE entry_id IN ({marks})", tuple(drop))
                removed["duplicate_lines"] += cur.rowcount
                cur = conn.execute(f"DELETE FROM journal_entries WHERE id IN ({marks})", tuple(drop))
                removed["duplicate_entries"] += cur.rowcount
        # 2) بنود أيتام (لا يوجد قيد أم)
        orphans = conn.execute(
            "SELECT COUNT(*) c FROM journal_lines WHERE entry_id NOT IN (SELECT id FROM journal_entries)"
        ).fetchone()[0]
        if orphans:
            conn.execute("DELETE FROM journal_lines WHERE entry_id NOT IN (SELECT id FROM journal_entries)")
            removed["orphan_lines"] = orphans
        conn.commit()
    finally:
        conn.close()
    return removed


# ------------------------------------------------------------------
# دالة مساعدة للاستعلامات الجماعية (تحتاج connect صريح)
# ------------------------------------------------------------------
def db_groups(conn, sql):
    return [tuple(r) for r in conn.execute(sql).fetchall()]


def audit(user, action, details=""):
    execute("INSERT INTO audit_log (user, action, details) VALUES (?,?,?)", (user, action, details))


# ------------------------------------------------------------------
# النسخ الاحتياطي
# ------------------------------------------------------------------

_last_auto_check = None


def create_backup(prefix="manual"):
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime_now().strftime("%Y-%m-%d_%H%M%S")
    dest = BACKUP_DIR / f"{prefix}-{ts}.db"
    conn = connect()
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    shutil.copy2(DB_PATH, dest)
    return dest.name


def auto_monthly_backup():
    global _last_auto_check
    today = date.today()
    if _last_auto_check == today:
        return
    _last_auto_check = today
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    marker = today.strftime("%Y-%m")
    has_this_month = any(p.name.startswith(f"auto-{marker}") for p in BACKUP_DIR.glob("auto-*.db"))
    if not has_this_month:
        create_backup(prefix=f"auto-{today.isoformat()}")
    all_backups = sorted(BACKUP_DIR.glob("*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in all_backups[24:]:
        try:
            old.unlink()
        except OSError:
            pass


def auto_daily_backup():
    """نسخة احتياطية يومية مع الاحتفاظ بآخر 14 نسخة."""
    today = date.today()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    daily = today.strftime("%Y-%m-%d")
    has_today = any(p.name.startswith(f"daily-{daily}") for p in BACKUP_DIR.glob("daily-*.db"))
    if not has_today:
        create_backup(prefix="daily-" + today.isoformat())
    dailies = sorted(BACKUP_DIR.glob("daily-*.db"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in dailies[14:]:
        try:
            old.unlink()
        except OSError:
            pass


SAFE_BACKUP_NAME = re.compile(r"^(auto|manual|pre-restore)-[A-Za-z0-9_\-.]+\.db$")


def restore_backup(name):
    if not SAFE_BACKUP_NAME.match(name):
        raise ValueError("اسم النسخة غير صالح")
    src = BACKUP_DIR / name
    if not src.exists():
        raise FileNotFoundError("النسخة غير موجودة")
    try:
        safe_name = create_backup(prefix="pre-restore")
    except Exception:
        safe_name = None
    conn = connect()
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    shutil.copy2(src, DB_PATH)
    return safe_name


def list_backups():
    if not BACKUP_DIR.exists():
        return []
    out = []
    for p in sorted(BACKUP_DIR.glob("*.db"), reverse=True):
        if SAFE_BACKUP_NAME.match(p.name):
            out.append({
                "name": p.name,
                "size": p.stat().st_size,
                "modified": datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
            })
    return out


# ------------------------------------------------------------------
# دالة مساعدة للأرقام المتتابعة
# ------------------------------------------------------------------

def next_number(prefix, table, col="id"):
    """يولّد رقماً متسلسلاً مثل INV-0001 بناءً على أكبر رقم موجود"""
    pos = len(prefix) + 2  # تخطي الفاصلة (-) بعد البادئة
    rows = query(f"SELECT MAX(CAST(SUBSTR({col}, {pos}) AS INTEGER)) AS m "
                 f"FROM {table} WHERE {col} LIKE ?", (f"{prefix}%",))
    m = rows[0]["m"] if rows else None
    n = (m or 0) + 1
    return f"{prefix}-{n:04d}"


if __name__ == "__main__":
    init_db()
    print("تم إنشاء قاعدة بيانات المقاولات بنجاح ✅")
