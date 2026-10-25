@echo off
setlocal
title MC Proxy - Offline network repair
cd /d "%~dp0"
if "%~1"=="" (
  "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Repair-Network.ps1" -ShowResult -PreserveChangedRules
) else (
  "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Repair-Network.ps1" -RuntimeRoot "%~f1\." -ShowResult -PreserveChangedRules
)
set "repairExit=%errorlevel%"
echo.
echo Repair exit code: %repairExit%
pause
exit /b %repairExit%
