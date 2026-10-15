# AccessLease: mobile review and explainable risk

## Code structure

```text
backend/
  risk_engine.py       Pure grant-scoring function, weights and tier boundaries
  risk_service.py      Current access queue, source deduplication, person summaries
  features.py          GET /api/risk-dashboard; admin extension/revocation APIs
  policy_engine.py     Existing scan-time policy findings and access provenance
  test_risk.py         Formula, date, aggregation, audit and remediation tests
frontend/
  index.html           Login-first shell and device selector
  workspace.html       Authenticated application document
  risk-ui.js           Summary cards, risk queue, disclosure cards and action forms
  mobile.css          Mobile layouts, touch targets, reduced-motion support
  app.js              Existing routing, findings and policy views
  features.js         Live data fetching, people management and preferences
  styles.css          Base components
  palette.css         Light/dark/high-contrast theme
```

## Scoring algorithm

This is a deterministic, explainable prioritization model, not trained machine
learning and not a probability of compromise. It uses recorded metadata; there
is no login/activity anomaly detector or AI service integration.

```python
from datetime import date
from risk_engine import calculate_grant_risk

result = calculate_grant_risk(
    permission_level="ADMIN", sensitivity="CRITICAL",
    expiry_date=date(2026, 10, 1), owner=None, purpose=None,
    is_temporary=True, as_of=date(2026, 10, 15),
)
# score=100, tier=HIGH_CRITICAL
# temporal=35, privilege=45, metadata=20
```

Score = min(100, temporal + privilege + metadata).

| Factor | Points |
| --- | --- |
| Temporal delinquency | 0 until overdue; then min(35, 10 + 2 × overdue days) |
| Permission | READ 5; WRITE 15; EXECUTE 20; ADMIN 30 |
| Resource sensitivity | LOW 0; STANDARD 5; HIGH 10; CRITICAL 15 |
| Missing owner | +12 |
| Missing business justification | +8 |
| Temporary access without expiry | +15 |

Privilege is permission points plus resource-sensitivity points. Missing metadata
recognizes blank values and placeholders such as `unknown` and `n/a`.
Expiry today is not overdue: dates represent calendar days, not timestamps.
A permanent grant without expiry has no missing-expiry penalty.
Administrative access on a critical database thus carries greater inherent risk
than read-only access. Valid privileged access may still warrant review.

Tiers: Low 0–39, Medium 40–69, High / Critical 70–100.
A person's score is the maximum of their active grant scores. People with no
active access score 0 and display zero permission relationships. The queue sorts
by score descending, then overdue days descending, with deterministic tie breaks.
Weights are initial product heuristics and should be calibrated against reviewed
incidents before using them for enterprise decisions. No automatic revocation
is triggered by a score.

## Source semantics and metrics

Direct grants use their recorded owner. Role assignments use `assigned_by` as
the accountable owner and the role's temporary flag. Delegations use their active
delegator as the accountable owner and are treated as temporary access.
The service scores each effective user/resource/permission relationship, including
role inheritance and delegation. Revoked sources and deleted users are excluded.

- **High Risk:** distinct people whose highest current score is at least 70.
- **Stale Accounts:** distinct people with expired access still enabled. This does
  not infer inactivity or last-login age.
- **Clean Leases:** distinct source records for which every provided relationship
  has score below 40, no overdue date, and complete modeled metadata. This is not
  a compliance certification. A role providing many resources counts once.
- **Effective access provided:** permission relationships, not deduplicated people
  or user/resource pairs. Multiple access paths can coexist.

Current risk is recalculated on each GET using the server date. Historical policy
findings preserve their scan-time severity/classification scores, including
simulated dates. The UI labels the two models separately.

## Mobile UI and interactions

Summary cards come first. Tap a card or filter to review high-risk, past-expiry,
clean or all access. Queue cards initially show person, resource, expiry and score;
expand to see factor meters, reasons, ownership, justification and quick actions.
The queue initially renders 12 records, with a Show next button. Per-person scores
and the older policy chart are secondary expandable sections.

On screens up to 760px, existing People, Permissions, Findings, Warnings and audit
tables become compact expandable cards. Desktop tables remain available at wider
widths. Native `details`/`summary` controls support keyboard navigation. Quick
buttons use 44px minimum touch targets; gestures are not required. Reduced-motion,
large-text, high-contrast and system/light/dark preferences remain supported.

Ten-second polling updates visible data. Open disclosures and focused controls
are preserved during refresh so an administrator can finish reading. Collapse the
card or navigate to see updated content on the next refresh.

## API and remediation

- `GET /api/risk-dashboard`: `{as_of, model_version, summary, people, queue}`.
  Each queue row includes score, tier, factors, reasons, source and resource IDs.
- `POST /api/access/{DIRECT|DELEGATED|ROLE_INHERITED}/{id}/extend`:
  `{expiry_date, expected_expiry_date, reason}`. `expected_expiry_date` must be
  supplied, including null for an undated source. Changed expiry gives 409.
- Existing `POST /api/access/{type}/{id}/revoke`: `{reason}`.

Mutations require the existing admin cookie and same-origin browser checks.
Extension requires a date after today and later than the stored expiry. Revoked
sources and inactive users cannot be extended. Extension/revocation write an audit
record and user activity, then rescan policies in the same transaction. A role
action changes the entire assignment across all resources, explained before
confirmation. Other access sources may remain. Updates affect Sentinel only;
there is no external IAM/SLCM enforcement integration.

## Run and verify on Windows

Run `Start.cmd` from the project folder. Open http://127.0.0.1:8000/ and sign in
on the initial login screen to remediate access. Ctrl+F5 reloads changed frontend assets.

For tests, from the backend folder with the project environment installed:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m unittest -v test_features test_integration test_risk
```

The test harness uses an isolated temporary database. No schema migration or new
third-party dependency is required for this upgrade.

Verification: all 19 backend tests passed on Python 3.14.6. Browser checks covered
390px mobile and 1440px desktop, disclosures through a polling cycle, extension
and revocation, responsive table alternatives, dark mode, high contrast and large
text. The risk tests were rerun after the clean-source filter refinement.
