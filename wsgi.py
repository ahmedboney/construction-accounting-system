# -*- coding: utf-8 -*-
"""نقطة دخول منصات الاستضافة (PythonAnywhere / Render).
على PythonAnywhere يضمّن المكتبات من مجلد vendor (يعمل دون تثبيت) ويطبّق
وضع القفل: مستخدم واحد فقط + منع الإعدادات وتغيير كلمات المرور.
"""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

# على PythonAnywhere (دليل /var/www موجود) نعتمد على المكتبات المرفقة محليًا
PA = os.path.exists("/var/www")
if PA and os.path.isdir(os.path.join(BASE, "vendor")):
    sys.path.insert(0, os.path.join(BASE, "vendor"))

if PA:
    import database as db
    from werkzeug.security import generate_password_hash
    db.init_db()
    # حساب واحد فقط — مستخدم عادي (محاسب) بدلًا من admin
    db.execute("UPDATE users SET role='accountant', full_name='محاسب' WHERE username='accountant'", ())
    if not db.query_one("SELECT id FROM users WHERE username='accountant'"):
        db.execute(
            "INSERT INTO users (username, password_hash, full_name, role) VALUES (?,?,?,?)",
            ("accountant", generate_password_hash("accountant@2026"), "محاسب", "accountant"))
    else:
        db.execute(
            "UPDATE users SET password_hash=? WHERE username='accountant'",
            (generate_password_hash("accountant@2026"),))
    # إزالة أي حسابات أخرى (مدير أو غيره) — يبقى المحاسب وحده
    db.execute("DELETE FROM users WHERE username <> 'accountant'", ())
    db.set_setting("security_lockdown", "1")
    db.set_setting("lockdown_username", "accountant")
    db.set_setting("force_https", "1")

from app import app as application

if __name__ == "__main__":
    application.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5010")), debug=False)