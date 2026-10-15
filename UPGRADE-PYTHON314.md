# Upgrade to Python 3.14.6

The project dependencies and Windows launcher have been updated. All 13
backend integration tests passed on CPython 3.14.6, Windows x64, with the
versions in backend/requirements.txt and backend/constraints.txt.

## Easiest: use the new ZIP

1. Stop your old server with Ctrl+C in its terminal.
2. Extract the new ZIP into a new folder. Do not open files inside the ZIP.
3. Confirm Python 3.14 is installed: `py -3.14 --version` or `python --version`.
4. Double-click Start.cmd. First setup requires internet access.
5. Wait for "Application startup complete", keep the terminal open, and visit
   http://127.0.0.1:8000/ on that computer.
6. To retain your existing records and admin account, with the old server
   stopped, copy its backend/accesslease.db into the new backend folder before
   starting the new version. Keep a backup copy. Do not copy the old .venv.

## Upgrade an existing project folder

Back up the whole project first. Replace the source files with this new version,
including Start.cmd, bootstrap.py and backend/requirements*.txt, and add
backend/constraints.txt. Preserve backend/accesslease.db.

Run Start.cmd. It prefers Python 3.14 and supports a suitable python command
when the py launcher is missing. If the existing .venv uses a different Python
minor version or cannot run, it is renamed to .venv-backup-<timestamp> before
creating a fresh environment. No database tables are dropped by the upgrade.

An old 3.14 environment is reused and its packages are upgraded to the tested
versions. The launcher does not change your system's Python installation.

## VS Code terminal alternative

Open the extracted project root (the folder containing Start.cmd):

```powershell
py -3.14 bootstrap.py
```

If py is unavailable, and `python --version` reports 3.14.6:

```powershell
python bootstrap.py
```

## Tests

After setup, stop the server, then from backend:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m unittest -v test_features test_integration
```

The tests use a temporary database, not your existing campus data.

## What changed

- FastAPI 0.143.2, Pydantic 2.14.1, SQLAlchemy 2.0.52, Uvicorn 0.54.0.
- HTTPX 0.28.1 for tests; resolved transitive versions recorded in constraints.txt.
- Plain Uvicorn is used; optional native speedup packages are not required.
- Unused aiofiles and python-multipart requirements were removed.
- The launcher now selects installed Python instead of requiring 3.12 only.
- A readable setup error remains in the terminal if installation or startup fails.

Existing class-based Pydantic and legacy SQLAlchemy calls may emit deprecation
warnings. Tests pass with this dependency set; these warnings are distinct from
errors that stop installation or startup.

This update enables local Python 3.14 operation. GitHub upload still does not
deploy the Python backend, and localhost URLs work only on the computer running
the server.

Official references: https://www.python.org/downloads/release/python-3146/
and the package release metadata on https://pypi.org/.
