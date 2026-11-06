@echo off
chcp 65001 >nul
cd /d "%~dp0"
set /p TARGET=Adresse IP a analyser : 
python ipinvestigator.py %TARGET%
pause
