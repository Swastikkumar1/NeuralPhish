@echo off
setlocal
title NeuralPhish - Desktop Shortcut Creator

echo [*] Creating Windows Desktop shortcuts...

powershell -NoProfile -Command ^
  "$ws = New-Object -ComObject WScript.Shell; " ^
  "$desktop = [Environment]::GetFolderPath('Desktop'); " ^
  "$s1 = $ws.CreateShortcut(\"$desktop\NeuralPhish Dashboard.lnk\"); " ^
  "$s1.TargetPath = '%~dp0run.bat'; " ^
  "$s1.WorkingDirectory = '%~dp0'; " ^
  "$s1.Description = 'NeuralPhish URL and Phishing Security Dashboard'; " ^
  "$s1.Save(); " ^
  "$s2 = $ws.CreateShortcut(\"$desktop\NeuralPhish Messenger Guard.lnk\"); " ^
  "$s2.TargetPath = '%~dp0run_messenger_guard.bat'; " ^
  "$s2.WorkingDirectory = '%~dp0'; " ^
  "$s2.Description = 'NeuralPhish Real-time Clipboard and WhatsApp Sentinel'; " ^
  "$s2.Save();"

if %errorlevel% equ 0 (
    echo [+] Shortcuts successfully created on your Desktop:
    echo     - "NeuralPhish Dashboard.lnk"
    echo     - "NeuralPhish Messenger Guard.lnk"
) else (
    echo [!] Could not create shortcuts automatically.
)

echo.
pause
