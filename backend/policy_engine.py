"""
AccessLease Sentinel - Policy Engine & Effective Access Calculator
Core evaluation logic: deterministic, documented, testable.
"""
from datetime import date, datetime
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session
import json
import uuid

from models import (
    User, Role, Resource, RoleAssignment, RolePermission,
    Grant, Delegation, Policy, ScanRun, Finding, AuditEvent,
    FindingClassification, FindingSeverity, FindingStatus
)

# Permission level hierarchy (higher index = more privileged)
PERMISSION_HIERARCHY = {"READ": 0, "WRITE": 1, "EXECUTE": 2, "ADMIN": 3}


def permission_exceeds(level_a: str, level_b: str) -> bool:
    """Returns True if level_a is strictly more privileged than level_b."""
    return PERMISSION_HIERARCHY.get(level_a, 0) > PERMISSION_HIERARCHY.get(level_b, 0)


def highest_permission(levels: List[str]) -> str:
    """Return the highest permission level from a list."""
    if not levels:
        return "READ"
    return max(levels, key=lambda l: PERMISSION_HIERARCHY.get(l, 0))


# ── Effective Access Engine ────────────────────────────────────────────

class EffectiveAccess:
    """Represents a single effective-access relationship with full provenance."""
    def __init__(
        self,
        user_id: int,
        resource_id: int,
        permission_level: str,
        source_type: str,  # DIRECT, ROLE_INHERITED, DELEGATED
        source_id: int,    # grant.id, role_assignment.id, or delegation.id
        access_path: List[Dict[str, Any]],
    ):
        self.user_id = user_id
        self.resource_id = resource_id
        self.permission_level = permission_level
        self.source_type = source_type
        self.source_id = source_id
        self.access_path = access_path


def calculate_effective_access(db: Session, user_id: Optional[int] = None) -> List[EffectiveAccess]:
    """
    Calculate all effective access relationships.
    Combines direct grants, role-inherited grants, and delegated grants.
    If user_id is specified, calculate only for that user.
    """
    results: List[EffectiveAccess] = []

    # Build user filter
    user_filter = []
    if user_id is not None:
        user_filter = [Grant.user_id == user_id]

    # 1. Direct grants
    direct_grants = db.query(Grant).filter(
        Grant.status.in_(["ACTIVE", "PENDING_REVIEW"]),
        *user_filter
    ).all()

    for g in direct_grants:
        user = db.query(User).get(g.user_id)
        resource = db.query(Resource).get(g.resource_id)
        results.append(EffectiveAccess(
            user_id=g.user_id,
            resource_id=g.resource_id,
            permission_level=g.permission_level,
            source_type="DIRECT",
            source_id=g.id,
            access_path=[{
                "step": "Direct Grant",
                "grant_id": g.id,
                "user": user.full_name if user else str(g.user_id),
                "resource": resource.name if resource else str(g.resource_id),
                "permission": g.permission_level,
                "owner": g.owner,
                "expiry": str(g.expiry_date) if g.expiry_date else None,
                "status": g.status,
            }]
        ))

    # 2. Role-inherited access
    role_filter = []
    if user_id is not None:
        role_filter = [RoleAssignment.user_id == user_id]

    active_assignments = db.query(RoleAssignment).filter(
        RoleAssignment.is_active == True,
        *role_filter
    ).all()

    for ra in active_assignments:
        role = db.query(Role).get(ra.role_id)
        user = db.query(User).get(ra.user_id)
        role_perms = db.query(RolePermission).filter(
            RolePermission.role_id == ra.role_id
        ).all()

        for rp in role_perms:
            resource = db.query(Resource).get(rp.resource_id)
            results.append(EffectiveAccess(
                user_id=ra.user_id,
                resource_id=rp.resource_id,
                permission_level=rp.permission_level,
                source_type="ROLE_INHERITED",
                source_id=ra.id,
                access_path=[
                    {
                        "step": "Role Assignment",
                        "role_assignment_id": ra.id,
                        "user": user.full_name if user else str(ra.user_id),
                        "role": role.name if role else str(ra.role_id),
                        "assigned_by": ra.assigned_by,
                        "expiry": str(ra.expiry_date) if ra.expiry_date else None,
                    },
                    {
                        "step": "Role Permission",
                        "role": role.name if role else str(ra.role_id),
                        "resource": resource.name if resource else str(rp.resource_id),
                        "permission": rp.permission_level,
                    }
                ]
            ))

    # 3. Delegated access
    deleg_filter = []
    if user_id is not None:
        deleg_filter = [Delegation.delegate_id == user_id]

    active_delegations = db.query(Delegation).filter(
        Delegation.status.in_(["ACTIVE", "PENDING_REVIEW"]),
        *deleg_filter
    ).all()

    for d in active_delegations:
        delegator = db.query(User).get(d.delegator_id)
        delegate = db.query(User).get(d.delegate_id)
        resource = db.query(Resource).get(d.resource_id)
        results.append(EffectiveAccess(
            user_id=d.delegate_id,
            resource_id=d.resource_id,
            permission_level=d.permission_level,
            source_type="DELEGATED",
            source_id=d.id,
            access_path=[{
                "step": "Delegated Grant",
                "delegation_id": d.id,
                "delegator": delegator.full_name if delegator else str(d.delegator_id),
                "delegate": delegate.full_name if delegate else str(d.delegate_id),
                "resource": resource.name if resource else str(d.resource_id),
                "permission": d.permission_level,
                "expiry": str(d.expiry_date) if d.expiry_date else None,
                "purpose": d.purpose,
                "status": d.status,
            }]
        ))

    return results


# ── Policy Engine ──────────────────────────────────────────────────────

def generate_finding_uid() -> str:
    """Generate a unique finding ID."""
    return f"FND-{uuid.uuid4().hex[:8].upper()}"


def calculate_risk_score(severity: str, classification: str, resource_sensitivity: str) -> float:
    """
    Deterministic risk scoring.
    Score = severity_weight * classification_weight * sensitivity_multiplier
    Range: 0.0 to 100.0
    """
    severity_weights = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10}
    classification_weights = {"CONFIRMED_VIOLATION": 2.5, "NEEDS_REVIEW": 1.5, "COMPLIANT": 0.0}
    sensitivity_multipliers = {"CRITICAL": 1.0, "HIGH": 0.8, "STANDARD": 0.6, "LOW": 0.4}

    base = severity_weights.get(severity, 10)
    cls_w = classification_weights.get(classification, 1.0)
    sens = sensitivity_multipliers.get(resource_sensitivity, 0.6)

    return round(min(base * cls_w * sens, 100.0), 1)


def run_policy_scan(
    db: Session,
    simulated_date: Optional[date] = None
) -> ScanRun:
    """
    Run a full policy scan. Creates a ScanRun and generates Findings.
    Uses simulated_date for time-travel scans (defaults to today).
    """
    eval_date = simulated_date or date.today()

    # Create scan run
    scan = ScanRun(
        scan_type="FULL",
        simulated_date=simulated_date,
    )
    db.add(scan)
    db.flush()

    # Load active policies
    policies = db.query(Policy).filter(Policy.is_active == True).all()
    policy_map = {p.policy_id: p for p in policies}

    # Calculate effective access
    all_access = calculate_effective_access(db)
    findings: List[Finding] = []
    finding_count = 0

    # Load all users for type checks
    users_map = {u.id: u for u in db.query(User).all()}
    resources_map = {r.id: r for r in db.query(Resource).all()}
    roles_map = {r.id: r for r in db.query(Role).all()}

    # Track processed to avoid duplicate findings for same user-resource-policy
    processed = set()

    # ── Check direct grants ────────────────────────────────────────
    active_grants = db.query(Grant).filter(
        Grant.status.in_(["ACTIVE", "PENDING_REVIEW"])
    ).all()

    for grant in active_grants:
        user = users_map.get(grant.user_id)
        resource = resources_map.get(grant.resource_id)
        if not user or not resource:
            continue

        # POL-006: Expired but still active
        if "POL-006" in policy_map and grant.expiry_date and grant.expiry_date < eval_date and grant.status == "ACTIVE":
            key = (grant.user_id, grant.resource_id, "POL-006", grant.id)
            if key not in processed:
                processed.add(key)
                days_expired = (eval_date - grant.expiry_date).days
                severity = "CRITICAL" if days_expired > 30 else "HIGH"
                findings.append(Finding(
                    finding_uid=generate_finding_uid(),
                    scan_run_id=scan.id,
                    user_id=grant.user_id,
                    resource_id=grant.resource_id,
                    grant_id=grant.id,
                    policy_id="POL-006",
                    effective_permission=grant.permission_level,
                    expected_state=f"Grant should be EXPIRED/REVOKED (expired {grant.expiry_date})",
                    observed_state=f"Grant is still ACTIVE, {days_expired} days past expiry",
                    evidence_source=f"Grant #{grant.id}: expiry_date={grant.expiry_date}, status={grant.status}",
                    access_path=json.dumps([{
                        "step": "Direct Grant (Expired)",
                        "grant_id": grant.id,
                        "user": user.full_name,
                        "resource": resource.name,
                        "permission": grant.permission_level,
                        "expiry": str(grant.expiry_date),
                        "days_expired": days_expired,
                    }]),
                    classification="CONFIRMED_VIOLATION",
                    severity=severity,
                    risk_score=calculate_risk_score(severity, "CONFIRMED_VIOLATION", resource.sensitivity),
                    recommended_action=f"Revoke access immediately. Grant expired {days_expired} days ago.",
                    status="OPEN",
                ))

        # POL-002: Guest admin prohibition
        if "POL-002" in policy_map and user.user_type == "guest" and grant.permission_level == "ADMIN":
            key = (grant.user_id, grant.resource_id, "POL-002", grant.id)
            if key not in processed:
                processed.add(key)
                findings.append(Finding(
                    finding_uid=generate_finding_uid(),
                    scan_run_id=scan.id,
                    user_id=grant.user_id,
                    resource_id=grant.resource_id,
                    grant_id=grant.id,
                    policy_id="POL-002",
                    effective_permission="ADMIN",
                    expected_state="Guest accounts must not have ADMIN permissions",
                    observed_state=f"Guest user '{user.full_name}' has ADMIN on '{resource.name}'",
                    evidence_source=f"Grant #{grant.id}: user_type={user.user_type}, permission={grant.permission_level}",
                    access_path=json.dumps([{
                        "step": "Direct Grant (Prohibited)",
                        "grant_id": grant.id,
                        "user": user.full_name,
                        "user_type": user.user_type,
                        "resource": resource.name,
                        "permission": "ADMIN",
                    }]),
                    classification="CONFIRMED_VIOLATION",
                    severity="CRITICAL",
                    risk_score=calculate_risk_score("CRITICAL", "CONFIRMED_VIOLATION", resource.sensitivity),
                    recommended_action="Revoke ADMIN access. Guest accounts are prohibited from holding ADMIN permissions.",
                    status="OPEN",
                ))

        # POL-003: Missing owner
        if "POL-003" in policy_map and (grant.owner is None or grant.owner.strip() == ""):
            key = (grant.user_id, grant.resource_id, "POL-003", grant.id)
            if key not in processed:
                processed.add(key)
                # Missing metadata → NEEDS_REVIEW, not confirmed violation
                sev = "HIGH" if resource.sensitivity in ("CRITICAL", "HIGH") else "MEDIUM"
                findings.append(Finding(
                    finding_uid=generate_finding_uid(),
                    scan_run_id=scan.id,
                    user_id=grant.user_id,
                    resource_id=grant.resource_id,
                    grant_id=grant.id,
                    policy_id="POL-003",
                    effective_permission=grant.permission_level,
                    expected_state="Every active grant must have a designated owner",
                    observed_state=f"Grant #{grant.id} has no owner assigned",
                    evidence_source=f"Grant #{grant.id}: owner=NULL, resource_sensitivity={resource.sensitivity}",
                    access_path=json.dumps([{
                        "step": "Direct Grant (Missing Owner)",
                        "grant_id": grant.id,
                        "user": user.full_name,
                        "resource": resource.name,
                        "owner": None,
                    }]),
                    classification="NEEDS_REVIEW",
                    severity=sev,
                    risk_score=calculate_risk_score(sev, "NEEDS_REVIEW", resource.sensitivity),
                    recommended_action="Assign an owner to this grant or verify if access is still needed.",
                    status="OPEN",
                ))

        # POL-004: Temporary grant missing expiry
        if "POL-004" in policy_map and grant.is_temporary and grant.expiry_date is None:
            key = (grant.user_id, grant.resource_id, "POL-004", grant.id)
            if key not in processed:
                processed.add(key)
                findings.append(Finding(
                    finding_uid=generate_finding_uid(),
                    scan_run_id=scan.id,
                    user_id=grant.user_id,
                    resource_id=grant.resource_id,
                    grant_id=grant.id,
                    policy_id="POL-004",
                    effective_permission=grant.permission_level,
                    expected_state="Temporary grants must have an expiry date",
                    observed_state=f"Temporary grant #{grant.id} has no expiry date set",
                    evidence_source=f"Grant #{grant.id}: is_temporary=True, expiry_date=NULL",
                    access_path=json.dumps([{
                        "step": "Direct Grant (Missing Expiry)",
                        "grant_id": grant.id,
                        "user": user.full_name,
                        "resource": resource.name,
                        "is_temporary": True,
                        "expiry": None,
                    }]),
                    classification="NEEDS_REVIEW",
                    severity="HIGH",
                    risk_score=calculate_risk_score("HIGH", "NEEDS_REVIEW", resource.sensitivity),
                    recommended_action="Set an expiry date for this temporary grant.",
                    status="OPEN",
                ))

        # POL-005: Missing purpose
        if "POL-005" in policy_map and (grant.purpose is None or grant.purpose.strip() == ""):
            key = (grant.user_id, grant.resource_id, "POL-005", grant.id)
            if key not in processed:
                processed.add(key)
                findings.append(Finding(
                    finding_uid=generate_finding_uid(),
                    scan_run_id=scan.id,
                    user_id=grant.user_id,
                    resource_id=grant.resource_id,
                    grant_id=grant.id,
                    policy_id="POL-005",
                    effective_permission=grant.permission_level,
                    expected_state="Every grant must have a documented purpose",
                    observed_state=f"Grant #{grant.id} has no purpose/justification",
                    evidence_source=f"Grant #{grant.id}: purpose=NULL",
                    access_path=json.dumps([{
                        "step": "Direct Grant (Missing Purpose)",
                        "grant_id": grant.id,
                        "user": user.full_name,
                        "resource": resource.name,
                        "purpose": None,
                    }]),
                    classification="NEEDS_REVIEW",
                    severity="MEDIUM",
                    risk_score=calculate_risk_score("MEDIUM", "NEEDS_REVIEW", resource.sensitivity),
                    recommended_action="Document the purpose/justification for this grant.",
                    status="OPEN",
                ))

        # POL-001: Duration exceeds max
        if "POL-001" in policy_map and grant.is_temporary and grant.granted_date:
            params = json.loads(policy_map["POL-001"].parameters)
            max_days = params.get("max_days", 30)
            duration = (eval_date - grant.granted_date).days
            if duration > max_days and grant.status == "ACTIVE":
                key = (grant.user_id, grant.resource_id, "POL-001", grant.id)
                if key not in processed:
                    processed.add(key)
                    findings.append(Finding(
                        finding_uid=generate_finding_uid(),
                        scan_run_id=scan.id,
                        user_id=grant.user_id,
                        resource_id=grant.resource_id,
                        grant_id=grant.id,
                        policy_id="POL-001",
                        effective_permission=grant.permission_level,
                        expected_state=f"Temporary access should not exceed {max_days} days",
                        observed_state=f"Grant active for {duration} days (granted {grant.granted_date})",
                        evidence_source=f"Grant #{grant.id}: granted={grant.granted_date}, duration={duration}d, max={max_days}d",
                        access_path=json.dumps([{
                            "step": "Direct Grant (Over Duration)",
                            "grant_id": grant.id,
                            "user": user.full_name,
                            "resource": resource.name,
                            "granted_date": str(grant.granted_date),
                            "duration_days": duration,
                            "max_days": max_days,
                        }]),
                        classification="CONFIRMED_VIOLATION" if duration > max_days * 2 else "NEEDS_REVIEW",
                        severity="HIGH" if duration > max_days * 2 else "MEDIUM",
                        risk_score=calculate_risk_score(
                            "HIGH" if duration > max_days * 2 else "MEDIUM",
                            "CONFIRMED_VIOLATION" if duration > max_days * 2 else "NEEDS_REVIEW",
                            resource.sensitivity
                        ),
                        recommended_action=f"Review and re-approve or revoke. Grant has been active {duration} days (limit: {max_days}).",
                        status="OPEN",
                    ))

    # ── Check role-inherited access for POL-007 (role boundary) ────
    if "POL-007" in policy_map:
        for ea in all_access:
            if ea.source_type == "ROLE_INHERITED":
                user = users_map.get(ea.user_id)
                resource = resources_map.get(ea.resource_id)
                if not user or not resource:
                    continue

                # Check if user also has a direct grant that exceeds the role max
                user_direct_grants = [
                    g for g in active_grants
                    if g.user_id == ea.user_id and g.resource_id == ea.resource_id
                ]
                # Get the role's max permission
                ra = db.query(RoleAssignment).get(ea.source_id)
                if ra:
                    role = roles_map.get(ra.role_id)
                    if role:
                        for dg in user_direct_grants:
                            if permission_exceeds(dg.permission_level, role.max_permission_level):
                                key = (ea.user_id, ea.resource_id, "POL-007", dg.id)
                                if key not in processed:
                                    processed.add(key)
                                    findings.append(Finding(
                                        finding_uid=generate_finding_uid(),
                                        scan_run_id=scan.id,
                                        user_id=ea.user_id,
                                        resource_id=ea.resource_id,
                                        grant_id=dg.id,
                                        role_assignment_id=ra.id,
                                        policy_id="POL-007",
                                        effective_permission=dg.permission_level,
                                        expected_state=f"Permission should not exceed role max: {role.max_permission_level} (role: {role.name})",
                                        observed_state=f"User has {dg.permission_level} via direct grant, exceeding role max {role.max_permission_level}",
                                        evidence_source=f"Grant #{dg.id} ({dg.permission_level}) > Role '{role.name}' max ({role.max_permission_level})",
                                        access_path=json.dumps([
                                            {"step": "Direct Grant", "grant_id": dg.id, "permission": dg.permission_level},
                                            {"step": "Role Boundary", "role": role.name, "max_permission": role.max_permission_level},
                                        ]),
                                        classification="CONFIRMED_VIOLATION",
                                        severity="HIGH",
                                        risk_score=calculate_risk_score("HIGH", "CONFIRMED_VIOLATION", resource.sensitivity),
                                        recommended_action=f"Reduce permission to {role.max_permission_level} or approve exception.",
                                        status="OPEN",
                                    ))

    # ── Check delegations ──────────────────────────────────────────
    active_delegations = db.query(Delegation).filter(
        Delegation.status.in_(["ACTIVE", "PENDING_REVIEW"])
    ).all()

    for deleg in active_delegations:
        user = users_map.get(deleg.delegate_id)
        resource = resources_map.get(deleg.resource_id)
        if not user or not resource:
            continue

        # POL-008: Expired delegation
        if "POL-008" in policy_map and deleg.expiry_date and deleg.expiry_date < eval_date:
            key = (deleg.delegate_id, deleg.resource_id, "POL-008", deleg.id)
            if key not in processed:
                processed.add(key)
                delegator = users_map.get(deleg.delegator_id)
                days_expired = (eval_date - deleg.expiry_date).days
                findings.append(Finding(
                    finding_uid=generate_finding_uid(),
                    scan_run_id=scan.id,
                    user_id=deleg.delegate_id,
                    resource_id=deleg.resource_id,
                    delegation_id=deleg.id,
                    policy_id="POL-008",
                    effective_permission=deleg.permission_level,
                    expected_state=f"Delegation should be deactivated (expired {deleg.expiry_date})",
                    observed_state=f"Delegation still ACTIVE, {days_expired} days past expiry",
                    evidence_source=f"Delegation #{deleg.id}: delegator={delegator.full_name if delegator else 'unknown'}, expiry={deleg.expiry_date}",
                    access_path=json.dumps([{
                        "step": "Delegated Grant (Expired)",
                        "delegation_id": deleg.id,
                        "delegator": delegator.full_name if delegator else "unknown",
                        "delegate": user.full_name,
                        "resource": resource.name,
                        "permission": deleg.permission_level,
                        "expiry": str(deleg.expiry_date),
                        "days_expired": days_expired,
                    }]),
                    classification="CONFIRMED_VIOLATION",
                    severity="HIGH",
                    risk_score=calculate_risk_score("HIGH", "CONFIRMED_VIOLATION", resource.sensitivity),
                    recommended_action=f"Revoke delegated access. Delegation expired {days_expired} days ago.",
                    status="OPEN",
                ))

        # POL-002: Guest with admin via delegation
        if "POL-002" in policy_map and user.user_type == "guest" and deleg.permission_level == "ADMIN":
            key = (deleg.delegate_id, deleg.resource_id, "POL-002", f"deleg-{deleg.id}")
            if key not in processed:
                processed.add(key)
                findings.append(Finding(
                    finding_uid=generate_finding_uid(),
                    scan_run_id=scan.id,
                    user_id=deleg.delegate_id,
                    resource_id=deleg.resource_id,
                    delegation_id=deleg.id,
                    policy_id="POL-002",
                    effective_permission="ADMIN",
                    expected_state="Guest accounts must not have ADMIN permissions",
                    observed_state=f"Guest '{user.full_name}' has delegated ADMIN on '{resource.name}'",
                    evidence_source=f"Delegation #{deleg.id}: user_type={user.user_type}, permission=ADMIN",
                    access_path=json.dumps([{
                        "step": "Delegated Grant (Guest Admin)",
                        "delegation_id": deleg.id,
                        "user": user.full_name,
                        "user_type": user.user_type,
                        "resource": resource.name,
                        "permission": "ADMIN",
                    }]),
                    classification="CONFIRMED_VIOLATION",
                    severity="CRITICAL",
                    risk_score=calculate_risk_score("CRITICAL", "CONFIRMED_VIOLATION", resource.sensitivity),
                    recommended_action="Revoke ADMIN delegation. Guest accounts are prohibited from ADMIN.",
                    status="OPEN",
                ))

    # ── Finalize scan ──────────────────────────────────────────────
    for f in findings:
        db.add(f)

    scan.total_permissions_scanned = len(active_grants) + len(active_delegations)
    scan.total_findings = len(findings)
    scan.critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    scan.high_count = sum(1 for f in findings if f.severity == "HIGH")
    scan.medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
    scan.low_count = sum(1 for f in findings if f.severity == "LOW")
    scan.needs_review_count = sum(1 for f in findings if f.classification == "NEEDS_REVIEW")
    scan.completed_at = datetime.utcnow()

    # Audit event
    db.add(AuditEvent(
        actor="SYSTEM",
        action="POLICY_SCAN",
        target_type="scan",
        target_id=str(scan.id),
        new_state=json.dumps({
            "total_findings": scan.total_findings,
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "simulated_date": str(simulated_date) if simulated_date else None,
        }),
        reason=f"Full policy scan {'(simulated date: ' + str(simulated_date) + ')' if simulated_date else ''}"
    ))

    db.commit()
    return scan
