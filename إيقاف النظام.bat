@echo off
chcp 65001 >nul
title نظام محاسبة المقاولات - إيقاف
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5010 ^| findstr LISTENING') do taskkill /f /pid %%a >nul 2>&1
echo تم إيقاف النظام.
timeout /t 2 >nul
exit
