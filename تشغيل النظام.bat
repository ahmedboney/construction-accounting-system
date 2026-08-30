@echo off
chcp 65001 >nul
title نظام محاسبة المقاولات - تشغيل
cd /d "%~dp0"

echo.
echo   ==================================================
echo       نظام محاسبة المقاولات المتكامل
echo   ==================================================
echo.

REM قتل أي عملية قديمة على المنفذ 5010 (اختياري)
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5010 ^| findstr LISTENING') do taskkill /f /pid %%a >nul 2>&1

echo  جاري تشغيل النظام...
start "نظام محاسبة المقاولات" /min pythonw "%~dp0app.py"
timeout /t 3 /nobreak >nul

REM فتح المتصفح تلقائيًا
start "" "http://127.0.0.1:5010"

echo.
echo  النظام يعمل الآن على: http://127.0.0.1:5010
echo  افتح الرابط في أي متصفح.
echo.
echo  للحصول على بيانات الدخول تواصل مع مدير النظام.
echo  لإيقاف النظام استخدم: إيقاف النظام.bat
echo.
pause