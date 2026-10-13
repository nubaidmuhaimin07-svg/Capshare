@echo off
rem Runs every automated check. Each test uses its own temporary database and files,
rem so your real CapShare data (%USERPROFILE%\.capshare) is never touched.
rem On Windows the 2-3 Linux-only tests (real setfacl, symlinks) are reported as "skipped".
setlocal
set "VENV=%USERPROFILE%\.capshare-venv"
set "PY="
if exist "%VENV%\Scripts\python.exe" set "PY=%VENV%\Scripts\python.exe"
if not defined PY if exist "%VENV%\bin\python.exe" set "PY=%VENV%\bin\python.exe"
if not defined PY (
  echo CapShare is not set up yet. Run setup_windows.ps1 first.
  pause
  exit /b 1
)
cd /d "%~dp0"
"%PY%" -m unittest discover -s tests -v
echo.
pause
