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
echo Checking if containers are running...
docker compose -f docker-compose.yml | findstr /i "web" >nul
if %errorlevel% neq 0 (
  echo Containers are not running.
  echo Starting containers first...
  docker compose -f docker-compose.yml up -d
  timeout /t 5 >nul
)

echo.
echo Running ingest_all...
docker compose -f docker-compose.yml exec web python manage.py ingest_all

echo.
echo Done.
pause