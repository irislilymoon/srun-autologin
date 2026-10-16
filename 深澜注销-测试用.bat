@echo off
chcp 65001 >nul
title Campus Network - Logout (for testing)
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

echo.
echo ============================================================
echo   This will LOG OUT your campus network session.
echo   Use it only to create an offline state for testing.
echo ============================================================
echo.
echo Press any key to log out, or close this window to cancel...
pause >nul
echo.

"%PY%" "%~dp0srun_login.py" logout
set "RC=%ERRORLEVEL%"

echo.
if not "%RC%"=="0" goto failed
echo ============================================================
echo   RESULT: logged out - now run the LOGIN TEST script.
echo ============================================================
goto done

:failed
echo ============================================================
echo   RESULT: logout failed - exit code %RC%
echo ============================================================
goto done

:nopy
echo.
echo [ERROR] Python not found.
echo   Install Python 3.8+ and tick "Add python.exe to PATH",
echo   or edit this .bat and set PY to your python.exe path.
echo.
goto done

:noscript
echo.
echo [ERROR] srun_login.py was not found next to this .bat.
goto done

:done
echo.
pause >nul
exit /b 0
