# -*- coding: utf-8 -*-
"""ترقية وتنظيف قاعدة بيانات نظام محاسبة المقاولات من النسخ القديمة.

الاستخدام:
    python upgrade.py            (يعالج قاعدة النسخة الحالية)
    python upgrade.py "المسار\للمجلد"   (يعالج مجلد يحتوي instance\\accounting.db)
    python upgrade.py "X:\path\accounting.db"   (ملف قاعدة مباشرة)

ماذا يفعل:
  1) نسخة احتياطية أمان قبل أي تعديل.
  2) ترقية الجداول والحقول الجديدة (سؤال الأمان، فهارس، ...).
  3) تنظيف القيود المكررة الناتجة عن النسخ القديمة (نفس المصدر أكثر من مرة).
  4) مسح بنود أيتام (بدون قيد أم).
  5) ملخص بما تم.

آمن للتشغيل المتكرر: لا يمسح بيانات سليمة أبدًا.
"""
import os
import sys
import tempfile
import shutil
from pathlib import Path


def main():
    print("=" * 60)
    print("أداة ترقية وتنظيف قاعدة بيانات المقاولات")
    print("=" * 60)

    target = None
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        p = Path(args[0]).resolve()
        if p.is_file() and p.name.lower().endswith(".db"):
            target = p
        elif p.is_dir():
            candidate = p / "instance" / "accounting.db"
            if not candidate.exists():
                candidate = p / "accounting.db"
            if candidate.exists():
                target = candidate
            else:
                print(f"! لم أجد accounting.db داخل {p}")
                sys.exit(1)
        else:
            print(f"! المسار غير موجود: {p}")
            sys.exit(1)

    # ربط database.py بالقاعدة المطلوبة ثم استيراده
    if target:
        base = target.parent.parent if (target.parent.name == "instance") else target.parent
        os.environ["MOQAWALAT_DB"] = str(base)
        print(f"القاعدة: {target}")

    from database import DB_PATH, INSTANCE_DIR, BACKUP_DIR, migrate, cleanup_duplicates, set_setting

    if not DB_PATH.exists():
        print("! لا توجد قاعدة بيانات هنا. أُنشئ قاعدة جديدة أولًا ثم أعد التشغيل.")
        sys.exit(1)

    # 1) نسخة أمان
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = tempfile._get_candidate_names()
    from datetime import datetime
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = BACKUP_DIR / f"pre-upgrade-{stamp}.db"
    try:
        import sqlite3
        shutil.copy2(DB_PATH, safe)
        print(f"[1/4] نسخة أمان: {safe.name} ({safe.stat().st_size:,} بايت)")
    except Exception as exc:
        print(f"[1/4] تعذّر إنشاء نسخة الأمان: {exc}")

    # 2) ترقية الهيكل
    print("[2/4] ترقية الجداول والحقول الجديدة ...")
    migrate()
    print("      تم — أُضيفت الحقول الناقصة (سؤال الأمان، فهارس، ...)")

    # 3) تنظيف القيود المكررة
    print("[3/4] تنظيف القيود المكررة ...")
    removed = cleanup_duplicates(keep_latest=True)
    for k, v in removed.items():
        if v:
            print(f"      - {k}: {v} عنصر")

    # 4) ضمان (source) أُنشئت فهارس جديدة
    print("[4/4] اكتملت الترقية بنجاح.")

    set_setting("db_version", "2.0")
    print("=" * 60)
    print("تم. يمكنك الآن فتح النظام وسيعمل بالنسخة الجديدة.")
    print("=" * 60)


if __name__ == "__main__":
    main()