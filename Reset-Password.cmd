@echo off
setlocal
cd /d "%~dp0"
if exist "backend\.venv\Scripts\python.exe" (
  "backend\.venv\Scripts\python.exe" recover_admin.py
  goto end
)
py -3 -V >nul 2>&1
if not errorlevel 1 (
  py -3 recover_admin.py
  goto end
)
python -V >nul 2>&1
if not errorlevel 1 (
  python recover_admin.py
  goto end
)
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
  "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" recover_admin.py
  goto end
)
echo Python not found. Install Python or run Start.cmd first.
:end
pause
