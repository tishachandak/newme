"""
AccessLease Sentinel - Pydantic Schemas
Request/response models for the API.
"""
# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import date, datetime


# ── Users ──────────────────────────────────────────────────────────────
class UserOut(BaseModel):
    id: int
    username: str
    full_name: str
    email: str
    department: str
    user_type: str
    is_active: bool
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Roles ──────────────────────────────────────────────────────────────
class RoleOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    max_permission_level: str
    department: Optional[str] = None
    is_temporary: bool

    class Config:
        from_attributes = True


class RoleAssignmentOut(BaseModel):
    id: int
    user_id: int
    role_id: int
    assigned_date: date
    expiry_date: Optional[date] = None
    assigned_by: Optional[str] = None
    purpose: Optional[str] = None
    is_active: bool
    user: Optional[UserOut] = None
    role: Optional[RoleOut] = None

    class Config:
        from_attributes = True


# ── Resources ──────────────────────────────────────────────────────────
class ResourceOut(BaseModel):
    id: int
    name: str
    resource_type: str
    department: str
    sensitivity: str
    description: Optional[str] = None

    class Config:
        from_attributes = True


# ── Grants ─────────────────────────────────────────────────────────────
class GrantOut(BaseModel):
    id: int
    user_id: int
    resource_id: int
    permission_level: str
    grant_source: str
    owner: Optional[str] = None
    purpose: Optional[str] = None
    granted_date: date
    expiry_date: Optional[date] = None
    status: str
    is_temporary: bool
    user: Optional[UserOut] = None
    resource: Optional[ResourceOut] = None

    class Config:
        from_attributes = True


class DelegationOut(BaseModel):
    id: int
    delegator_id: int
    delegate_id: int
    resource_id: int
    permission_level: str
    purpose: Optional[str] = None
    granted_date: date
    expiry_date: Optional[date] = None
    status: str

    class Config:
        from_attributes = True


# ── Policies ───────────────────────────────────────────────────────────
class PolicyOut(BaseModel):
    id: int
    policy_id: str
    name: str
    description: Optional[str] = None
    rule_type: str
    parameters: Optional[str] = None
    severity: str
    is_active: bool

    class Config:
        from_attributes = True


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    parameters: Optional[str] = None
    severity: Optional[str] = None
    is_active: Optional[bool] = None


# ── Scan ───────────────────────────────────────────────────────────────
class ScanRunOut(BaseModel):
    id: int
    scan_date: datetime
    scan_type: str
    total_permissions_scanned: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    needs_review_count: int
    simulated_date: Optional[date] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScanRequest(BaseModel):
    simulated_date: Optional[date] = None


# ── Findings ───────────────────────────────────────────────────────────
class FindingOut(BaseModel):
    id: int
    finding_uid: str
    scan_run_id: int
    user_id: int
    resource_id: int
    grant_id: Optional[int] = None
    delegation_id: Optional[int] = None
    role_assignment_id: Optional[int] = None
    policy_id: str
    effective_permission: str
    expected_state: str
    observed_state: str
    evidence_source: str
    access_path: Optional[str] = None
    classification: str
    severity: str
    risk_score: float
    recommended_action: Optional[str] = None
    status: str
    reviewer: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    user: Optional[UserOut] = None
    resource: Optional[ResourceOut] = None

    class Config:
        from_attributes = True


# ── Review ─────────────────────────────────────────────────────────────
class ReviewRequest(BaseModel):
    action: str  # MARK_REVIEWED, SIMULATE_REVOKE, EXTEND_ACCESS, REQUEST_OWNER_REVIEW, DISMISS
    reviewer: str
    justification: str
    extension_date: Optional[date] = None


class ReviewActionOut(BaseModel):
    id: int
    finding_id: int
    action: str
    reviewer: str
    justification: str
    previous_status: str
    new_status: str
    previous_grant_status: Optional[str] = None
    new_grant_status: Optional[str] = None
    extension_date: Optional[date] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ── Audit ──────────────────────────────────────────────────────────────
class AuditEventOut(BaseModel):
    id: int
    timestamp: datetime
    actor: str
    action: str
    target_type: str
    target_id: str
    previous_state: Optional[str] = None
    new_state: Optional[str] = None
    reason: Optional[str] = None
    related_finding_id: Optional[str] = None

    class Config:
        from_attributes = True


# ── Dashboard ──────────────────────────────────────────────────────────
class DashboardMetrics(BaseModel):
    total_users: int
    total_active_permissions: int
    expired_active_permissions: int
    overbroad_grants: int
    ownerless_grants: int
    confirmed_violations: int
    needs_review: int
    resolved_findings: int
    last_scan: Optional[ScanRunOut] = None


class EffectiveAccessOut(BaseModel):
    user_id: int
    resource_id: int
    permission_level: str
    source_type: str
    source_id: int
    access_path: List[Any]
    user_name: Optional[str] = None
    resource_name: Optional[str] = None
