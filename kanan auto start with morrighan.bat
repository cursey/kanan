@echo off
@setlocal enableextensions
@cd /d "%~dp0"

pip -q install frida toml psutil
python ./kanan.py -s -m
