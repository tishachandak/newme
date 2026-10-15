# Login-first workspace and device previews

## Updated code

- `frontend/index.html`: login/setup form, password visibility toggle, authenticated
  toolbar and view-mode selector. No dashboard iframe or dataset is preloaded.
- `frontend/session.js`: session check, credential submission, iframe lifecycle,
  sign-out, periodic session checks, back/forward-cache handling and device mode.
- `frontend/session.css`: login layout, toolbar and Android/iPhone phone frames.
- `frontend/workspace.html`: the existing dashboard markup and scripts, initially
  hidden until its own session check succeeds.
- `frontend/app.js`: clears audit state on 401; ignores stale request results after
  session invalidation and tells the parent to remove the workspace frame.
- `frontend/features.js`: checks authentication before fetching any dataset.
- `backend/main.py`: global authentication dependency for data endpoints and
  `/workspace`; no-store response headers for API and workspace responses.
- `backend/test_privacy.py`: anonymous GET coverage, expiry, logout and cache checks.

## State flow

1. `/` renders only the login shell and requests `/api/auth/status`.
2. With no session, no iframe is created and no audit API is fetched. On a fresh
   installation, the first local admin can be created with a 10–128 character
   password. Existing installations require their configured admin credentials.
3. Successful sign-in uses the existing server-side session and HttpOnly cookie.
   A still-valid session from a previous sign-in is accepted on reload.
4. The shell creates `/workspace` only after the server confirms authentication.
   That route and the audit APIs independently require a valid session.
5. Desktop uses the available width. Android uses a 390px app viewport; iPhone
   uses 393px with different frame chrome. At narrower window widths the frame
   shrinks to fit. These are responsive layout previews, not OS/browser emulators.
6. Logout removes the iframe immediately, clearing its in-memory data, and
   invalidates the server session. A failed sign-out is surfaced with a retry;
   the workspace stays hidden. A 401 or failed session verification locks the UI.

The iframe stays mounted during device changes: navigation, form state and the
session are preserved. Real viewport widths activate the existing mobile CSS and
card components. Only the chosen device mode is saved in localStorage; credentials,
session tokens and audit records are not stored there. Existing visual preferences
remain local as before.

## Backend access rules

Sensitive API GETs and mutations are authenticated. Public exceptions are the login
shell, static assets, health, session status, login, initial setup and logout.
The SLCM ingestion endpoint keeps its separate scoped integration-key or admin
check. API documentation describes contracts but exposes no audit records.
Responses use no-store, and same-origin frame embedding is enforced. Existing
scrypt password hashes, eight-hour HttpOnly sessions, login throttling and browser
write-origin checks remain in place.

This is local administrator authentication. Enterprise SSO is explicitly shown as
not configured; it requires an actual identity-provider integration. The first-admin
setup is intended for the local installation. This change does not add multi-tenant
enterprise provisioning. Existing demo records remain stored but are available
only after sign-in; nothing deletes existing user data.

## Verification

21 backend tests passed on Python 3.14.6. Browser checks verified no audit requests
or iframe before login, setup/sign-in, invalid password, logout, session invalidation,
390px Android and 393px iPhone views, desktop mode and narrow-screen login layout.

Run `Start.cmd`, open http://127.0.0.1:8000/, then Ctrl+F5. Use the existing admin
credentials or create the first account if prompted. After sign-in, choose a mode
from the top toolbar. No password reset or account change was performed.
