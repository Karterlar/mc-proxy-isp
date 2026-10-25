@echo off
setlocal
title MC Proxy - Offline preflight
cd /d "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-ChainReadiness.ps1"
set "MC_TEST_EXIT=%ERRORLEVEL%"
echo.
echo Exit code: %MC_TEST_EXIT%. See logs and README.zh-CN.txt in this folder.
pause
exit /b %MC_TEST_EXIT%
