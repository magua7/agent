@echo off
chcp 65001 >nul
setlocal EnableExtensions EnableDelayedExpansion
set "SEC_GO_ROOT=%~dp0.."
cd /d "%SEC_GO_ROOT%"
set "PYTHONPATH=%SEC_GO_ROOT%\src"
set "EXIT_CODE=2"

if exist "%SEC_GO_ROOT%\.venv\Scripts\python.exe" (
  "%SEC_GO_ROOT%\.venv\Scripts\python.exe" -m security_agent.interfaces.product_cli %*
  set "EXIT_CODE=!ERRORLEVEL!"
  goto :finish
)

for /f "delims=" %%P in ('where python 2^>nul') do (
  "%%P" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
  if not errorlevel 1 (
    "%%P" -m security_agent.interfaces.product_cli %*
    set "EXIT_CODE=!ERRORLEVEL!"
    goto :finish
  )
)

echo SEC-GO requires Python 3.11 or newer. 1>&2

:finish
if "%~1"=="" pause
exit /b %EXIT_CODE%
