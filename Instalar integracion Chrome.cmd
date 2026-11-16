@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Primero prepara el entorno siguiendo INICIO_AUTOMATICO.md.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" install_chrome.py
pause
