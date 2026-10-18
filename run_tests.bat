@echo off
setlocal
title NeuralPhish - Automated Test Suite

echo =======================================================
echo   Running NeuralPhish Automated Test Suite (pytest)
echo =======================================================
echo.

pytest tests/ -v --tb=short
if %errorlevel% equ 0 (
    echo.
    echo [+] ALL UNIT AND INTEGRATION TESTS PASSED!
) else (
    echo.
    echo [!] Some tests failed. Please review the output above.
)

echo.
pause
