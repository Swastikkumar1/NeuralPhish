@echo off
setlocal
title NeuralPhish - Real-time Messenger Guard
cd /d "%~dp0"
python messenger_guard.py
if %errorlevel% neq 0 pause
