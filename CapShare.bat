@echo off
rem CapShare launcher for Windows.
rem   CapShare.bat                       desktop app + sharing service (the sender)
rem   CapShare.bat gui --client URL      desktop app only, connected to another computer
rem   CapShare.bat serve                 sharing service only (use a browser as the client)
rem   CapShare.bat lab                   run the 5 challenge scenarios in this window
rem   CapShare.bat accounts              list accounts
rem   CapShare.bat reset --yes           delete all CapShare data
setlocal
set "VENV=%USERPROFILE%\.capshare-venv"
set "PY="
if exist "%VENV%\Scripts\python.exe" set "PY=%VENV%\Scripts\python.exe"
if not defined PY if exist "%VENV%\bin\python.exe" set "PY=%VENV%\bin\python.exe"
if not defined PY (
  echo CapShare is not set up yet.
  echo Right-click setup_windows.ps1 and choose "Run with PowerShell", then try again.
  pause
  exit /b 1
)
cd /d "%~dp0"
if "%~1"=="" (
  "%PY%" -m capshare gui
) else (
  "%PY%" -m capshare %*
)
if errorlevel 1 pause
