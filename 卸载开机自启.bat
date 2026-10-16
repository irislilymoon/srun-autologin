@echo off
chcp 65001 >nul
title Uninstall - Auto login at boot
setlocal
cd /d "%~dp0"

rem ---- locate PowerShell 7 ----
set "PS="
if exist "C:\Program Files\PowerShell\7\pwsh.exe" set "PS=C:\Program Files\PowerShell\7\pwsh.exe"
if not defined PS for /f "delims=" %%P in ('where pwsh 2^>nul') do if not defined PS set "PS=%%P"
if not defined PS goto nops
if not exist "%~dp0uninstall_autostart.ps1" goto noscript

echo.
echo ============================================================
echo   This will REMOVE the scheduled task "SRun.AutoLogin".
echo   Campus network will no longer log in automatically.
echo   Administrator rights are required (a UAC prompt appears).
echo ============================================================
echo.
echo Press any key to continue, or close this window to cancel...
pause >nul
echo.

"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall_autostart.ps1"
set "RC=%ERRORLEVEL%"
echo.
if "%RC%"=="10" goto elevated
if not "%RC%"=="0" goto failed

echo ============================================================
echo   RESULT: UNINSTALLED
echo ============================================================
goto done

:elevated
echo ============================================================
echo   A UAC prompt was raised. Click YES, then read the
echo   result in the new window. This window can be closed.
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
echo [ERROR] uninstall_autostart.ps1 was not found next to this .bat.
goto done

:done
echo.
pause >nul
exit /b 0
