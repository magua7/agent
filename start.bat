@echo off
chcp 65001 >nul
setlocal EnableExtensions DisableDelayedExpansion
cd /d "%~dp0"

if not exist "%~dp0settings.json" if exist "%~dp0settings.example.json" (
  copy /y "%~dp0settings.example.json" "%~dp0settings.json" >nul
  echo Created private settings.json from settings.example.json.
  echo Edit it and set llm.enabled to true to use an external model.
  echo.
)

if "%~1"=="" goto :interactive
call "%~dp0scripts\sec-go.bat" %*
exit /b %ERRORLEVEL%

:interactive
call "%~dp0scripts\sec-go.bat" interactive
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if not "%EXIT_CODE%"=="0" echo SEC-GO exited with code %EXIT_CODE%.
pause
exit /b %EXIT_CODE%
