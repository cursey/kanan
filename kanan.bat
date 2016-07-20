@echo off
@setlocal enableextensions
@cd /d "%~dp0"

pip -q install frida
py -3.5 ./kanan.py
