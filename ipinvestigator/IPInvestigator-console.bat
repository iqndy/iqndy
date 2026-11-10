@echo off
chcp 65001 >nul
cd /d "%~dp0"
title IPInvestigator (console)
call "%~dp0_python.bat"
if not defined PY goto nopython
set /p TARGET=Adresse IP a analyser : 
%PY% ipinvestigator.py %TARGET%
pause
exit /b

:nopython
echo.
echo  Python est introuvable sur ce PC.
echo  Installez Python 3.13 depuis https://www.python.org/downloads/
echo  en cochant "Add python.exe to PATH", puis relancez ce fichier.
echo.
pause
exit /b 1
