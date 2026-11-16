@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Falta el entorno. Sigue INICIO_AUTOMATICO.md para la instalacion inicial.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -c "import tkinter, dns, flask, cheroot, cryptography, argon2"
if errorlevel 1 (
  echo Instala las dependencias de requirements.txt y el componente Tcl/Tk de Python.
  pause
  exit /b 1
)
if exist ".venv\Scripts\pythonw.exe" (
  start "DNSentinel" ".venv\Scripts\pythonw.exe" "%~dp0launcher.py" --recover
) else (
  ".venv\Scripts\python.exe" "%~dp0launcher.py" --recover
)
