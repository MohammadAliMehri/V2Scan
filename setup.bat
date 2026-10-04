@echo off
setlocal enabledelayedexpansion
title V2Scan - Windows Setup
color 0B

echo.
echo  ============================================================
echo  V2Scan - Windows Environment Setup
echo  ============================================================
echo  This script installs everything you need to run V2Scan.
echo  ============================================================
echo.

:: ── Check Python ──
echo [1/4] Checking Python...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo  [X] Python not found!
    echo.
    echo  Install Python 3.8+ from https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo  [OK] Python %PY_VER%

:: ── Check pip ──
echo.
echo [2/4] Checking pip...
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] pip not found, installing...
    python -m ensurepip --upgrade
)
echo  [OK] pip is available

:: ── Install Python dependencies ──
echo.
echo [3/4] Installing Python packages...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install -r "%~dp0requirements.txt"
echo  [OK] Python packages installed (rich, httpx[socks,http2], fastapi, uvicorn, qrcode)

:: ── Check / Install sing-box ──
echo.
echo [4/4] Checking sing-box...
where sing-box >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%v in ('sing-box version 2^>^&1') do set SB_VER=%%v
    echo  [OK] sing-box found: !SB_VER!
) else (
    echo  [!] sing-box not found in PATH.
    echo.
    echo  Option A - Install with Scoop (recommended):
    echo    scoop install sing-box
    echo.
    echo  Option B - Download manually:
    echo    https://github.com/SagerNet/sing-box/releases
    echo    Extract sing-box.exe and add it to your PATH.
    echo.
    echo  Option C - Already have it? Pass the path:
    echo    python main.py delay -i configs.txt --singbox C:\path\to\sing-box.exe
    echo.
    echo  The 'fetch' command works without sing-box.
    echo.
)

:: ── Done ──
echo.
echo  ============================================================
echo  Setup complete!
echo  ============================================================
echo.
echo  Quick start:
echo    python main.py fetch               # Fetch free configs from GitHub
echo    python main.py scan --parallel 5    # Fetch + test all
echo    python main.py web --port 8686      # Launch web UI
echo    python main.py delay -i configs.txt # Test existing configs
echo.
echo  Open http://127.0.0.1:8686 for the web dashboard.
echo.
pause
