@echo off
setlocal
title NeuralPhish - Interactive Terminal Scanner

set APP_DIR=%~dp0
if exist "%APP_DIR%NeuralPhish\cli.py" (
    set TARGET_DIR=%APP_DIR%NeuralPhish
) else (
    set TARGET_DIR=%APP_DIR%
)

cd /d "%TARGET_DIR%"
python cli.py --interactive
pause
