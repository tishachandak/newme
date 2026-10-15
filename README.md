# AccessLease Sentinel

Full local project: FastAPI backend plus a responsive web dashboard. Frontend
features include live overview metrics, finding search and severity filters,
evidence dialogs, direct/inherited/delegated permission paths, policy cards,
scan history, and an optional simulation date when running a scan.

## Where to save it

Keep the entire `accesslease-sentinel` folder together. A suggested permanent
location is `C:\Users\dell\Documents\AccessLease-Sentinel`. Copy or extract the
whole project there; do not move only `main.py`.

```text
accesslease-sentinel/
  Start.cmd
  README.md
  frontend/
    index.html
    styles.css
    app.js
  backend/
    main.py
    database.py
    models.py
    policy_engine.py
    schemas.py
    seed_data.py
    requirements.txt
    requirements-dev.txt
    test_integration.py
    accesslease.db       (created on startup; persistent data)
    .venv/               (created during local setup)
```

Double-click `Start.cmd` to create a local Python environment, install the
dependencies and run the site. First setup needs internet access. It uses the
Python 3.14 first, then an available Python 3.13/3.12 installation. See UPGRADE-PYTHON314.md for upgrading an existing copy.
Keep the terminal window open and visit <http://127.0.0.1:8000/> once startup
completes. If another server already occupies port 8000, stop that server before
starting this copy. You can also use the VS Code commands below.

To move or back up a project with existing data, stop its server first and copy
the project including `backend/accesslease.db`. Recreate `.venv` in the new
location rather than copying the old environment. The download ZIP contains
source only; its demo database is created on first run. The current workspace
folder retains its existing database.

Frontend files are served by the same backend at `/` and `/assets`, so only one
server is required. Do not open `index.html` directly or use VS Code Live Server.
The layout uses local CSS/JavaScript with optional Google Fonts and system-font
fallbacks. No Node.js installation or frontend build command is needed.

The original project modules are included in `backend/`; dependency pins have been upgraded for Python 3.14. The `main.py`
uses their existing database, Pydantic schemas, seeder and policy engine directly.

## Run in Windows VS Code (PowerShell terminal)

Open this `accesslease-sentinel` folder in VS Code. Python 3.14.6 (standard Windows x64 build) has been tested with the upgraded dependency pins. For automatic setup, run Start.cmd. For a clean manual setup:

```powershell
cd backend
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

If `py` is unavailable but Python 3.14 is installed, replace the venv creation
command with `python -m venv .venv`. Running the environment's Python directly
avoids PowerShell activation/execution-policy errors.

On the current PC, `py` was not found. The following installed Python 3.12
runtime was used successfully for integration testing, and can create the venv:

```powershell
& 'C:\Users\dell\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m venv .venv
```

Open <http://127.0.0.1:8000/> for the dashboard or
<http://127.0.0.1:8000/docs> for API testing. Swagger's **Try it out** lets you exercise every endpoint.
Stop the server with Ctrl+C. Run from `backend` so the supplied sibling imports
resolve and the default SQLite database stays in `backend/accesslease.db`.

On the first startup, tables, demo data and an initial policy scan are created.
Subsequent startups preserve the data and existing scans. Seeding uses the
original seeder's user-count guard: if any users exist, it skips seeding entirely.
It does not repair a partly populated database.

## API

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/api/health` | API process health |
| POST | `/api/seed` | Seed demo data if empty; create first scan if needed |
| GET | `/api/dashboard` | Dashboard metrics; alias `/api/dashboard/metrics` |
| POST | `/api/scan` | New full scan; optional JSON `{"simulated_date":"2026-12-31"}` |
| GET | `/api/scans` | Scan history, newest first |
| GET | `/api/findings` | Latest completed scan by default; `scan_id` selects history |
| GET | `/api/findings/{id}` | Finding by numeric ID or `FND-...` identifier |
| GET | `/api/permissions` | Direct grant records, including revoked records |
| GET | `/api/permissions/effective` | Direct, inherited and delegated access paths |
| GET | `/api/users` | Users |
| GET | `/api/resources` | Resources |
| GET | `/api/policies` | Policies |
| GET | `/api/delegations` | Delegation records |
| GET | `/api/role-assignments` | Role assignments |

Findings support `severity`, `classification`, `status`, `user_id`, `department`
(the user's department), `offset`, and `limit`. Direct permissions support
`user_id`, `resource_id`, `status`, `offset`, and `limit`. Effective permissions
support `user_id` and `resource_id`. Lists return arrays; pagination defaults to
100 for findings and direct permissions, with a maximum of 1,000.

All audit/data endpoints now require an authenticated admin session, including
read-only requests. Sign in at the root URL before opening the workspace. API
clients must retain the session cookie returned by `/api/auth/login`.

## Metric definitions and existing engine behavior

- Findings metrics use only the latest completed scan, including a simulated
  scan if that is the latest; previous scans remain available through `scan_id`.
- `total_active_permissions` counts effective access paths, including
  `PENDING_REVIEW`, following the supplied engine. A user/resource pair may
  contribute several paths. Expired access is still counted until deactivated.
- `expired_active_permissions` counts expired active direct, delegated and
  role-derived paths. It uses the latest scan's simulated date, or today's date.
- `overbroad_grants` counts latest-scan POL-007 findings; `ownerless_grants`
  counts current active/pending direct grants with missing or blank owners.
- The existing scan's `total_permissions_scanned` counts direct grants and
  delegations only. It will differ from the dashboard's effective-path count.
- Time-travel scans create findings without changing permission status/expiry.
- The original policy rules are preserved. This adds API integration, not a
  policy-engine correctness audit or additional detection rules.

## Configuration

`DATABASE_URL` is supported by the supplied database module. Default:
`sqlite:///./accesslease.db`. Set `$env:SEED_DEMO_DATA = "false"` before launching
to disable automatic demo seeding. Explicit `POST /api/seed` still works.

CORS allows localhost/127.0.0.1 frontend ports 3000 and 5173. This is a local
demo with admin authentication for all audit reads and mutations; keep the documented loopback binding. Use a
single server process: the write lock coordinates scans/seeding within that
process only.

## Integration tests

From `backend`, with the virtual environment already created:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m unittest -v test_features test_integration
```

The tests use a separate temporary SQLite database. They cover startup,
restart and seed idempotency, scan history, dashboard consistency, all three
access sources, revoked-access exclusion, time travel, filters, validation,
lookup routes, and startup with automatic seeding disabled.

## New admin and accessibility features

Open the **Admin dashboard** and create your local admin username and password
(at least 10 characters). No default password is installed. Subsequently use
that account to sign in. Admin accounts are separate from the campus people
records. Sessions expire after eight hours and are invalidated by sign-out.

- **Accessibility & theme:** System / Light / Dark, high contrast, larger text,
  reduced motion, and a 1–90-day warning window. Preferences are saved in the
  browser and, when signed in, in your admin account. A skip link, visible focus,
  labelled forms, keyboard-operated dialogs and live status messages are included.
- **Admin dashboard → Add data:** Create people, resources and direct grants.
  Inputs are validated; duplicate usernames/emails/resource names are rejected.
  Temporary grants require expiry. Creating a grant triggers a fresh policy scan.
- **Permissions → View path → Confirm revocation:** Enter a reason to revoke a
  direct grant, delegation or entire role assignment. Role revocation removes
  all paths from that assignment. Independent access paths remain visible.
  The operation is audited and immediately rescanned. Repeating a revocation
  does not create duplicate actions.
- **Live updates:** Pages poll every 10 seconds while visible, reconnect after
  errors and show their last update time. Form input, dialogs and unsaved forms
  are preserved. Updates pause while an input is focused. This is polling, not
  a persistent connection or an always-running background notification service.
- **Expiry warnings:** Includes sources expiring today through the configured
  number of days, across direct grants, delegations and role assignments.
  Revoked/inactive sources are excluded. Warnings use actual dates even when
  the latest scan used a simulated date. Warnings are in-app, not email/SMS.
- **People / clickable names:** Inspect recorded changes with actor, time and
  reason, plus historical grant, delegation and role records. Existing demo
  records are not presented as historical logins or actual resource usage.

Revocation changes the Sentinel database. It does **not** revoke credentials
inside SLCM, Active Directory or another external system. All campus data views and APIs require admin sign-in. The login screen fetches
only session status until authentication succeeds. This is
not a production multi-tenant identity service.

### New API routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/auth/status` | Login/setup state |
| POST | `/api/auth/setup` | First local administrator |
| POST | `/api/auth/login` | Sign in using username/password |
| POST | `/api/auth/logout` | Invalidate current session |
| GET / PUT | `/api/preferences` | Admin preferences |
| POST | `/api/users` | Create person (admin) |
| POST | `/api/resources` | Create resource (admin) |
| POST | `/api/permissions` | Create direct grant and scan (admin) |
| POST | `/api/access/{source_type}/{source_id}/revoke` | Revoke source with reason (admin) |
| GET | `/api/users/{user_id}/profile` | Records and recorded activity |
| GET | `/api/warnings?days=7` | Upcoming expiry warnings |
| GET | `/api/admin/dashboard` | Counts and last 50 audit entries (admin) |
| GET | `/api/integrations/slcm/status` | Adapter status (admin) |
| POST | `/api/integrations/slcm/key` | Generate/rotate ingest key (admin) |
| POST | `/api/integrations/slcm/sync` | Approved mapped export, admin or ingest key |

`POST /api/scan` and `/api/seed` now also require admin sign-in. Same-origin
browser writes are enforced. API clients may sign in using a cookie-preserving
session. Integration keys authorize only SLCM ingestion, not other admin routes.

### MUJ SLCM integration boundary

MUJ identifies its official student portal at
https://mujslcm.jaipur.manipal.edu/ via its
[official website](https://jaipur.manipal.edu/pay-fee-online.php).
No public MUJ SLCM API contract was found during this implementation. The app
therefore includes a tested **ingest adapter**, not a working live SLCM connector.
No student password, portal scraping or invented upstream endpoint is used.

See the running app at `/docs` for the ingest API schema.
A university-approved API or export, its field definitions and permission
to access it are still required for an actual automatic university connection.

### Verification

The original 13 backend integration tests passed on Windows/Python 3.12.14 before the upgrade. For Python 3.14.6 upgrade validation, see UPGRADE-PYTHON314.md. These tests cover auth,
CSRF rejection, validation, session expiry, preferences, every revocation source,
warning boundaries, idempotent imports, stale-snapshot rejection, transaction
rollback, key scope/rotation and preservation of revoked access.

Headless Edge tests verified actual frontend form submission, theme persistence,
large text/contrast settings, grants, warnings, revocation and profile activity.
Desktop and mobile screenshots were inspected. These checks are not a formal
screen-reader or WCAG certification.

Additional browser checks passed for cross-client live updates, mapped ERP import, system light/dark switching, and keyboard skip navigation.

### Team handoff

The frontend is plain HTML, CSS and JavaScript (`index.html`, `app.js`,
`features.js`, `styles.css`, `palette.css`), served by FastAPI. It is not Streamlit.
On Windows, run `Start.cmd` to set up the Python environment and launch the server
through `bootstrap.py`. Keep the terminal open during the demo.

### Mobile risk dashboard

See [RISK-MODEL.md](RISK-MODEL.md) for the current grant-risk algorithm, mobile
components, API contracts, source semantics and Windows test commands.

### Login-first shell and device previews

See [AUTH-AND-DEVICE-VIEWS.md](AUTH-AND-DEVICE-VIEWS.md) for login state management,
backend protection, HTML/CSS/JS file locations and the device dropdown.

### Forgotten administrator password

Use **Forgot password?** on the login page and `Reset-Password.cmd` to obtain an
owner-issued recovery code. See [PASSWORD-RESET.md](PASSWORD-RESET.md). No email
service is connected; all existing data is retained during reset.
