@echo off
setlocal
title NeuralPhish - Starting Security Server
cd /d "%~dp0"
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:5000"
python app.py
if %errorlevel% neq 0 pause
