# Deploy AccessLease through GitHub to Vercel

Repository: https://github.com/Rookie-exe-muj/access-lease

## 1. Upload the complete source

Download accesslease-vercel-github.zip and extract it. On GitHub, open the repository,
choose Add file > Upload files, then upload the extracted files and folders to the
repository root. Do not upload the ZIP itself. The root must contain:

```text
app.py
requirements.txt
vercel.json
.python-version
.gitignore
.vercelignore
backend/
frontend/
```

The repository inspected for this task had only README.md, Start.cmd and the old
SLCM-INTEGRATION.md. That is insufficient to deploy. Replace the old README and
Start.cmd with the packaged versions; the obsolete SLCM document can be removed.
Never upload .env, .venv, accesslease.db or the work folder. The supplied ZIP excludes
these. Hidden dotfiles may need to be shown in Windows Explorer.

## 2. Import in Vercel

Sign in to https://vercel.com/new with GitHub, allow access to this repository and
select Import. Use Framework Preset FastAPI, Root Directory ./ and automatic build
and install settings. No npm build or frontend output directory is needed. The
FastAPI function serves both the frontend and /api under the same HTTPS origin.

## 3. Connect a persistent PostgreSQL database

In Vercel Marketplace/Storage, create or connect a PostgreSQL database (for example
Neon). Connect it to this project. Use the provider's connection string as DATABASE_URL,
including its SSL settings. The application accepts postgres://, postgresql:// or
postgresql+psycopg:// and uses psycopg 3. Local SQLite cannot persist on Vercel.
Use a separate database/branch for preview deployments and production.

If the initial deployment runs before storage and environment settings exist, it
will fail intentionally. Finish the settings below and redeploy.

## 4. Set private environment variables

Add these in Project Settings > Environment Variables for the intended environment:

| Name | Value |
| --- | --- |
| DATABASE_URL | PostgreSQL connection string from the provider, with SSL enabled |
| BOOTSTRAP_ADMIN_USERNAME | Your chosen admin username (3–100 letters/digits/._@-) |
| BOOTSTRAP_ADMIN_PASSWORD | Your private 10–128 character password |
| SEED_DEMO_DATA | true for synthetic hackathon cases; false for an empty workspace |

Do not paste secrets into source code, GitHub or chat. Vercel supplies VERCEL=1 itself.
The first startup creates the administrator from these private settings, hashes the
password and disables public first-admin signup. Subsequent deployments keep the
existing account; changing the bootstrap variables does not reset its password.
Hosted demo seeding is off unless explicitly enabled. The local SQLite database and
local administrator are not copied into PostgreSQL automatically.

## 5. Deploy / redeploy and verify

Deploy after all variables are configured (or open Deployments > Redeploy). Open the
assigned HTTPS .vercel.app URL. Before login, the login screen should be the only
view and /api/dashboard must return 401. Sign in with the hosted bootstrap account,
check desktop/phone views, create a test user, sign out and sign back in, and verify
the test record persists. Check /api/health for a basic service response. Use Vercel
runtime logs for startup/build errors, without sharing connection strings.

Once GitHub is connected, later commits to the production branch trigger deployment.
Start.cmd is for local Windows use; it is not a Vercel build/start command.

## Changes made for hosting

- Root app.py exports the existing FastAPI app. .python-version selects Python 3.14.
- Root requirements.txt adds pinned psycopg[binary] 3.3.6 to existing dependencies.
- vercel.json selects FastAPI and a 60-second function duration.
- Hosted storage requires PostgreSQL; local SQLite still works unchanged.
- PostgreSQL transaction-level advisory locking serializes governance mutations
  and initial schema/admin/demo setup across function instances. NullPool avoids
  keeping idle app-side database pools alive.
- Failed-login counts live in the database rather than process-local memory.
- Hosted session cookies are Secure. Login-first API protections remain in force.

## Validation and remaining work

21 existing backend tests passed after the hosting changes. Additional isolated
checks passed for PostgreSQL schema compilation, driver import, hosted bootstrap,
blocked public setup and secure cookies. No local database was reset.
A real PostgreSQL connection and a Vercel build have not been tested yet: those
require your connected database/project. No GitHub upload or Vercel deployment was
completed by this session.

Official references:
- https://vercel.com/docs/frameworks/backend/fastapi
- https://vercel.com/docs/functions/runtimes/python
- https://vercel.com/kb/guide/is-sqlite-supported-in-vercel
- https://vercel.com/docs/marketplace-storage
