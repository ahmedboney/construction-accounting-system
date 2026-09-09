@echo off
REM إيقاف النظام بدون نافذة CMD واقفة — افتح ملف "إيقاف النظام.vbs" بدلا من هذا الملف
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5010 ^| findstr LISTENING') do taskkill /f /pid %%a >nul 2>&1
exit