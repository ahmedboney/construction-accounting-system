#!/bin/bash
# تثبيت نظام محاسبة المقاولات على PythonAnywhere (يُشغَّل مرة واحدة عبر مهمة مجدولة)
set -e
cd /home/ahmedboney01000/mysite

# اختيار بايثون 3.10 إن وجد (لدعم مجلد افتراضي من نفس الإصدار)
PY=$(command -v python3.10 || command -v python3.11 || command -v python3.9 || echo python3)
echo "Using: $PY"

VENV=/home/ahmedboney01000/.virtualenvs/accounting
if [ ! -x "$VENV/bin/python" ]; then
  echo "Creating virtualenv..."
  $PY -m venv "$VENV"
fi

echo "Installing requirements..."
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install -r /home/ahmedboney01000/mysite/requirements.txt

echo "Running secure bootstrap (one user + lockdown)..."
"$VENV/bin/python" /home/ahmedboney01000/mysite/bootstrap.py

echo "Writing WSGI file..."
cat > /var/www/ahmedboney01000_pythonanywhere_com_wsgi.py <<'PYEOF'
import os, sys
path = '/home/ahmedboney01000/mysite'
if path not in sys.path:
    sys.path.insert(0, path)
os.chdir(path)
import wsgi
application = wsgi.application
PYEOF

echo "Reloading webapp..."
touch /var/www/ahmedboney01000_pythonanywhere_com_wsgi.py
echo "DONE"