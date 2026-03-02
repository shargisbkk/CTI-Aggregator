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

if not exist .env (
  echo Creating .env from .env.example...
  copy .env.example .env >nul
)

echo Starting CTI-Aggregator...
docker compose up --build
pause