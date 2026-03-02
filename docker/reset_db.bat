@echo off
setlocal
cd /d %~dp0

echo Checking Docker...
docker info >nul 2>&1
if %errorlevel% neq 0 (
  echo Docker is not running. Please open Docker Desktop first.
  pause
  exit /b
)

echo.
echo WARNING: This will DELETE the database volume and wipe ALL data.
echo Press Ctrl+C to cancel, or any key to continue...
pause >nul

echo.
echo Stopping containers and removing volumes...
docker compose -f docker-compose.yml down -v --remove-orphans

echo.
echo Rebuilding and starting containers...
docker compose -f docker-compose.yml up -d --build

pause