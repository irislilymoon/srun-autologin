@echo off
chcp 65001 >nul
title Campus Network - Edit username / password
setlocal
cd /d "%~dp0"

rem ---- locate python (no hardcoded path, works after moving to another PC) ----
set "PY="
if exist "D:\Python3.14.2\python.exe" set "PY=D:\Python3.14.2\python.exe"
if not defined PY (
  for /f "delims=" %%P in ('where python 2^>nul') do (
    if not defined PY echo %%P| findstr /i /c:"WindowsApps" >nul || set "PY=%%P"
  )
)
if not defined PY goto nopy
if not exist "%~dp0srun_login.py" goto noscript

"%PY%" "%~dp0srun_login.py" config
echo.
echo ============================================================
echo   Done. Press any key to close this window.
echo ============================================================
pause >nul
exit /b 0

:nopy
echo.
echo [ERROR] Python not found.
echo.
echo   Install Python 3.8+ and tick "Add python.exe to PATH",
echo   or open this .bat and set PY to your own python.exe path:
echo       set "PY=D:\Python3.14.2\python.exe"
echo.
pause >nul
exit /b 1

:noscript
echo.
echo [ERROR] srun_login.py was not found next to this .bat.
echo   Keep all project files in the same folder.
echo.
pause >nul
exit /b 1
