@echo off
chcp 65001 >nul
cd /d "%~dp0"
title IPInvestigator
python webapp.py
pause
