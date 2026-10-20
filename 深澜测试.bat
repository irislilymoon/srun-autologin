@echo off
chcp 65001 >nul
title SRun - Test Lab
setlocal
cd /d "%~dp0"

rem ---- locate python (auto-detect, works after moving to another PC) ----
set "PY="
if exist "D:\Python3.14.2\python.exe" set "PY=D:\Python3.14.2\python.exe"
if not defined PY (
  for /f "delims=" %%P in ('where python 2^>nul') do (
    if not defined PY echo %%P| findstr /i /c:"WindowsApps" >nul || set "PY=%%P"
  )
)
if not defined PY goto nopy
if not exist "%~dp0src\srun_login.py" goto noscript

"%PY%" "%~dp0src\srun_login.py" lab
exit /b %ERRORLEVEL%

:nopy
echo.
echo [ERROR] Python not found.
echo   Install Python 3.8+ and tick "Add python.exe to PATH".
echo.
pause >nul
exit /b 1

:noscript
echo.
echo [ERROR] src\srun_login.py was not found next to this .bat.
echo.
pause >nul
exit /b 1
