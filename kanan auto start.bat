@echo off
@setlocal enableextensions
@cd /d "%~dp0"

echo Checking and installing dependencies...
pip -q install frida toml psutil
cls
python ./kanan.py -s
