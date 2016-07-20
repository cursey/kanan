@echo off
@setlocal enableextensions
@cd /d "%~dp0"

pip -q install frida
python ./kanan.py
