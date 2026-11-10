@echo off
rem Cherche un Python 3.10+ utilisable et le met dans la variable PY
rem (commande python, lanceur py, puis dossiers d'installation habituels)
set "PY="
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set "PY=python" && goto :eof
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul && set "PY=py -3" && goto :eof
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*" "%LOCALAPPDATA%\Python\pythoncore-3*" "%ProgramFiles%\Python3*" "%ProgramFiles(x86)%\Python3*" "C:\Python3*") do (
  if exist "%%~D\python.exe" set PY="%%~D\python.exe"
)
goto :eof
