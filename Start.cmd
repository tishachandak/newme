@echo off
setlocal
cd /d "%~dp0"
py -3.14 -c "import sys; assert sys.version_info[:2] == (3,14)" >nul 2>&1
if not errorlevel 1 goto py314
python -c "import sys; assert sys.version_info[:2] in {(3,12),(3,13),(3,14)}" >nul 2>&1
if not errorlevel 1 goto python
py -3.13 -c "import sys; assert sys.version_info[:2] == (3,13)" >nul 2>&1
if not errorlevel 1 goto py313
py -3.12 -c "import sys; assert sys.version_info[:2] == (3,12)" >nul 2>&1
if not errorlevel 1 goto py312
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" goto bundled
echo Python was not found. Install Python 3.14 and enable the Python launcher or PATH option.
goto end
:py314
py -3.14 bootstrap.py
goto end
:python
python bootstrap.py
goto end
:py313
py -3.13 bootstrap.py
goto end
:py312
py -3.12 bootstrap.py
goto end
:bundled
"%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" bootstrap.py
:end
pause
