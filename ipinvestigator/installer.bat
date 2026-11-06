@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -m pip install -r requirements.txt
python -m playwright install chromium
python ipinvestigator.py --update-db
pause
