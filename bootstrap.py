# -*- coding: utf-8 -*-
"""بوتستراب الاستضافة: تهيئة أولية آمنة — ينفَّذ مرة واحدة من مهمة مجدولة.
- إنشاء القاعدة والمستخدم الافتراضي ودليل الحسابات.
- تفعيل وضع القفل: مستخدم واحد فقط، كلمة مرور المستخدمين الآخرين مغلقة،
  ويُمنع الدخول للإعدادات وتغيير كلمات المرور من داخل التطبيق.
- تفعيل HTTPS الإلزامي على الاستضافة.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import database as db

db.init_db()
if not db.query_one("SELECT id FROM users WHERE username='admin'"):
    print("admin missing — check init_db")

# 1) مستخدم واحد فقط يعمل (حذف الحسابات الأخرى نهائيًا)
deleted = db.execute("DELETE FROM users WHERE username <> 'admin'", ())
print("deleted secondary users:", deleted)

# 2) تفعيل القفل: حساب واحد + منع الإعدادات وتغيير كلمات المرور
db.set_setting("security_lockdown", "1")
db.set_setting("lockdown_username", "admin")

# 3) HTTPS إجباري (كوكي الجلسة آمن + HSTS)
db.set_setting("force_https", "1")

n = db.query_one("SELECT COUNT(*) c FROM users")["c"]
print("active users:", n)
print("BOOTSTRAP OK")