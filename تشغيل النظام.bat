@echo off
REM تشغيل النظام بدون نافذة CMD واقفة — افتح ملف "تشغيل النظام.vbs" بدلا من هذا الملف
cd /d "%~dp0"
if exist "نظام محاسبة المقاولات.exe" (
    start "" /min "نظام محاسبة المقاولات.exe"
) else (
    start "" /min pythonw "%~dp0app.py"
)
exit