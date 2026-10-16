@echo off
chcp 65001 >nul
title Install - Auto login BEFORE you unlock
setlocal
cd /d "%~dp0"

rem ---- locate PowerShell 7 (pythonw.exe is auto-detected inside the .ps1) ----
set "PS="
if exist "C:\Program Files\PowerShell\7\pwsh.exe" set "PS=C:\Program Files\PowerShell\7\pwsh.exe"
if not defined PS for /f "delims=" %%P in ('where pwsh 2^>nul') do if not defined PS set "PS=%%P"
if not defined PS goto nops
if not exist "%~dp0install_autostart.ps1" goto noscript

echo.
echo ============================================================
echo   Install auto login at BOOT time (runs as SYSTEM)
echo   Requires administrator rights - a UAC prompt will appear.
echo ============================================================
echo.

"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_autostart.ps1" -Force
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="10" goto elevated
if not "%RC%"=="0" goto failed

echo ============================================================
echo   RESULT: INSTALLED
echo   SYSTEM task "SRun.AutoLogin" now runs at boot,
echo   before you unlock the screen.
echo ============================================================
goto done

:elevated
echo ============================================================
echo   A UAC prompt was raised (or is on screen now).
echo   Click YES, then read the result in the new window.
echo   This window can be closed.
echo ============================================================
goto done

:failed
echo ============================================================
echo   RESULT: FAIL - exit code %RC%
echo ============================================================
goto done

:nops
echo.
echo [ERROR] PowerShell 7 (pwsh) not found.
echo   Install it from https://aka.ms/powershell
echo.
goto done

:noscript
echo.
echo [ERROR] install_autostart.ps1 was not found next to this .bat.
goto done

:done
echo.
pause >nul
exit /b 0
