"""Explainable current-access risk model v1; no trained AI or login telemetry."""
from datetime import date

MODEL_VERSION = "access-risk-v1"
PRIVILEGE_POINTS = {"READ": 5, "WRITE": 15, "EXECUTE": 20, "ADMIN": 30}
SENSITIVITY_POINTS = {"LOW": 0, "STANDARD": 5, "HIGH": 10, "CRITICAL": 15}


def risk_tier(score):
    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100")
    return "LOW" if score < 40 else "MEDIUM" if score < 70 else "HIGH_CRITICAL"


def missing(value):
    return not value or str(value).strip().lower() in {"", "n/a", "none", "unknown", "-"}


def calculate_grant_risk(*, permission_level, sensitivity, expiry_date=None,
                         owner=None, purpose=None, is_temporary=False, as_of=None):
    """Return 0..100 with factor contributions; dates are server calendar dates.

    Temporal: 0 until overdue; then min(35, 10 + 2 * days_overdue).
    Privilege: permission 5/15/20/30 + resource sensitivity 0/5/10/15.
    Metadata: missing owner 12 + missing purpose 8 + undated temporary lease 15.
    Total: min(100, sum). Person-level aggregation uses max, never an average
    that could hide one dangerous grant. This is a prioritization heuristic,
    not a calibrated breach probability or compliance certification.
    """
    as_of = as_of or date.today()
    permission_level = getattr(permission_level, "value", permission_level)
    sensitivity = getattr(sensitivity, "value", sensitivity)
    if permission_level not in PRIVILEGE_POINTS or sensitivity not in SENSITIVITY_POINTS:
        raise ValueError("Unsupported permission or resource sensitivity")
    overdue = max(0, (as_of - expiry_date).days) if expiry_date else 0
    temporal = min(35, 10 + 2 * overdue) if overdue else 0
    privilege = PRIVILEGE_POINTS[permission_level] + SENSITIVITY_POINTS[sensitivity]
    metadata = 0
    reasons = []
    if overdue:
        reasons.append(f"Access is {overdue} day(s) past expiry")
    if missing(owner):
        metadata += 12
        reasons.append("No accountable owner recorded")
    if missing(purpose):
        metadata += 8
        reasons.append("No business justification recorded")
    if is_temporary and expiry_date is None:
        metadata += 15
        reasons.append("Temporary access has no expiry date")
    if permission_level == "ADMIN":
        reasons.append("Administrative privilege")
    if sensitivity in {"HIGH", "CRITICAL"}:
        reasons.append(f"{sensitivity.title()} sensitivity resource")
    raw = temporal + privilege + metadata
    score = min(100, raw)
    return {"score": score, "tier": risk_tier(score), "days_overdue": overdue,
            "factors": {"temporal": temporal, "privilege": privilege, "metadata": metadata},
            "raw_score": raw, "cap_adjustment": max(0, raw-100), "reasons": reasons,
            "clean": overdue == 0 and metadata == 0 and score < 40,
            "model_version": MODEL_VERSION}
