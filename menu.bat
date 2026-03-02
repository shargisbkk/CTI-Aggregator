@echo off
setlocal
cd /d %~dp0

:check_docker
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

if "%choice%"=="1" goto start
if "%choice%"=="2" goto stop
if "%choice%"=="3" goto reset
if "%choice%"=="4" goto ingest
if "%choice%"=="0" goto end

echo.
echo Invalid choice.
pause
goto menu

:start
call start.bat
goto menu

:stop
call stop.bat
goto menu

:reset
call reset_db.bat
goto menu

:ingest
call ingest_all.bat
goto menu

:end
echo.
echo Goodbye!
exit /b 0