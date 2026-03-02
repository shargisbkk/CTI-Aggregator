@echo off
setlocal
cd /d %~dp0

docker info >nul 2>&1
if %errorlevel% neq 0 (
  echo.
  echo Docker is not running. Please open Docker Desktop first.
  echo.
  pause
  exit /b 1
)

:menu
cls
echo ==========================================
echo        CTI-Aggregator Control Menu
echo ==========================================
echo.
echo  1) Start Application
echo  2) Stop Application
echo  3) Reset Database (WIPE ALL DATA)
echo  4) Ingest All Feeds
echo.
echo  0) Exit
echo.
set /p choice=Choose an option: 

if "%choice%"=="1" call docker\run.bat & goto menu
if "%choice%"=="2" call docker\stop.bat & goto menu
if "%choice%"=="3" call docker\reset_db.bat & goto menu
if "%choice%"=="4" call docker\ingest_all.bat & goto menu
if "%choice%"=="0" goto end

echo.
echo Invalid choice.
pause
goto menu

:end
echo.
echo Goodbye!
exit /b 0