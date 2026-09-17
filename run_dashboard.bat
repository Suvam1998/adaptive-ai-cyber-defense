@echo off
REM ============================================================
REM  Adaptive AI Cyber Defense System - Windows launcher
REM  Uses the existing Python installation (no virtualenv).
REM ============================================================
setlocal

echo Checking Python...
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python was not found on PATH. Please install Python 3.10+.
  pause
  exit /b 1
)

echo Installing / updating dependencies (user site)...
python -m pip install --user --quiet -r requirements.txt

echo.
echo Generating synthetic sample data (if missing)...
if not exist "data\sample_events.csv" python data\make_samples.py

echo.
echo Starting the Adaptive AI Cyber Defense System...
echo (Press CTRL+C to stop.)
echo.
python run.py

pause
endlocal
