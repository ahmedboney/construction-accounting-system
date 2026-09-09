@echo off
chcp 65001 >nul
title ترقية نظام محاسبة المقاولات من نسخة قديمة
echo ============================================================
echo   ترقية نظام محاسبة المقاولات من نسخة قديمة إلى الجديدة
echo ============================================================
echo.

REM 1) إيقاف أي نسخة قديمة شغّالة على المنفذ 5010
echo [1/3] إيقاف أي نسخة شغّالة من النظام ...
powershell -NoProfile -WindowStyle Hidden -Command "Get-NetTCPConnection -LocalPort 5010 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"
timeout /t 1 /nobreak >nul

REM 2) نسخة أمان يدوية لمجلد البيانات إذا وُجد
if exist "instance\accounting.db" (
    echo [2/3] حفظ نسخة أمان لبياناتك القديمة...
    powershell -NoProfile -Command "if (Test-Path 'manual-backup-before-upgrade.zip') { Remove-Item 'manual-backup-before-upgrade.zip' -Force }; Compress-Archive -Path 'instance' -DestinationPath 'manual-backup-before-upgrade.zip' -Force" >nul 2>&1
) else (
    echo [2/3] لا توجد قاعدة بيانات قديمة هنا - سيتم إنشاء جديدة.
)

REM 3) تشغيل الترقية (يعمل من EXE أو من الكود المصدري)
echo [3/3] ترقية قاعدة البيانات والحقول الجديدة ...
if exist "نظام محاسبة المقاولات.exe" (
    "نظام محاسبة المقاولات.exe" --upgrade
) else (
    python app.py --upgrade
)
echo.

if exist "instance\upgrade_result.txt" (
    echo نتيجة الترقية:
    type "instance\upgrade_result.txt"
    del "instance\upgrade_result.txt" >nul 2>&1
    echo.
)

echo ============================================================
echo   تمت الترقية بنجاح.
echo   الآن افتح النظام من ملف:  تشغيل النظام.vbs
echo   بياناتك القديمة محفوظة في: manual-backup-before-upgrade.zip
echo ============================================================
echo.
pause