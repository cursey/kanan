@echo off
@setlocal enableextensions
@cd /d "%~dp0"

echo Checking and installing dependencies...
pip -q install frida toml psutil
if %errorlevel% neq 0 (
    pause
    exit
)
cls
python ./kanan.py -s
if %errorlevel% neq 0 (
    pause
    exit
)