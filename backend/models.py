"""
AccessLease Sentinel - Database Models
Normalized schema for identity, permissions, policies, findings and audit.
"""
from datetime import datetime, date
from typing import Optional
# pyrefly: ignore [missing-import]
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, Date,
    Boolean, Float, ForeignKey, UniqueConstraint, Index, Enum as SAEnum
)
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import declarative_base, relationship, Session
import enum

Base = declarative_base()


# ── Enums ──────────────────────────────────────────────────────────────
class PermissionLevel(str, enum.Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    ADMIN = "ADMIN"


class GrantSource(str, enum.Enum):
    DIRECT = "DIRECT"
    ROLE_INHERITED = "ROLE_INHERITED"
    DELEGATED = "DELEGATED"


class GrantStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    PENDING_REVIEW = "PENDING_REVIEW"


class FindingClassification(str, enum.Enum):
    CONFIRMED_VIOLATION = "CONFIRMED_VIOLATION"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    COMPLIANT = "COMPLIANT"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ReviewAction(str, enum.Enum):
    MARK_REVIEWED = "MARK_REVIEWED"
    SIMULATE_REVOKE = "SIMULATE_REVOKE"
    EXTEND_ACCESS = "EXTEND_ACCESS"
    REQUEST_OWNER_REVIEW = "REQUEST_OWNER_REVIEW"
    DISMISS = "DISMISS"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


# ── Core Tables ────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(200), nullable=False)
    email = Column(String(200), unique=True, nullable=False)
    department = Column(String(100), nullable=False)
    user_type = Column(String(50), nullable=False)  # staff, faculty, student, guest, visiting_faculty, temp_staff
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    role_assignments = relationship("RoleAssignment", back_populates="user")
    grants = relationship("Grant", back_populates="user", foreign_keys="Grant.user_id")
    delegated_grants = relationship("Delegation", back_populates="delegator", foreign_keys="Delegation.delegator_id")
    received_delegations = relationship("Delegation", back_populates="delegate", foreign_keys="Delegation.delegate_id")


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    max_permission_level = Column(String(20), nullable=False)  # PermissionLevel value
    department = Column(String(100))
    is_temporary = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    assignments = relationship("RoleAssignment", back_populates="role")
    role_permissions = relationship("RolePermission", back_populates="role")


class Resource(Base):
    __tablename__ = "resources"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), unique=True, nullable=False)
    resource_type = Column(String(100), nullable=False)  # server, database, application, lab_equipment, file_share
    department = Column(String(100), nullable=False)
    sensitivity = Column(String(50), default="STANDARD")  # LOW, STANDARD, HIGH, CRITICAL
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    grants = relationship("Grant", back_populates="resource")
    role_permissions = relationship("RolePermission", back_populates="resource")


class RoleAssignment(Base):
    __tablename__ = "role_assignments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    assigned_date = Column(Date, nullable=False)
    expiry_date = Column(Date, nullable=True)
    assigned_by = Column(String(100))
    purpose = Column(Text)
    is_active = Column(Boolean, default=True)

    user = relationship("User", back_populates="role_assignments")
    role = relationship("Role", back_populates="assignments")

    __table_args__ = (
        Index("ix_role_assignments_user_role", "user_id", "role_id"),
    )


class RolePermission(Base):
    """Defines what permissions a role grants on which resources."""
    __tablename__ = "role_permissions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    resource_id = Column(Integer, ForeignKey("resources.id"), nullable=False)
    permission_level = Column(String(20), nullable=False)

    role = relationship("Role", back_populates="role_permissions")
    resource = relationship("Resource", back_populates="role_permissions")

    __table_args__ = (
        UniqueConstraint("role_id", "resource_id", "permission_level", name="uq_role_resource_perm"),
    )


class Grant(Base):
    """Direct permission grant from a user to a resource."""
    __tablename__ = "grants"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    resource_id = Column(Integer, ForeignKey("resources.id"), nullable=False)
    permission_level = Column(String(20), nullable=False)
    grant_source = Column(String(20), default="DIRECT")
    owner = Column(String(200), nullable=True)
    purpose = Column(Text, nullable=True)
    granted_date = Column(Date, nullable=False)
    expiry_date = Column(Date, nullable=True)
    status = Column(String(20), default="ACTIVE")
    is_temporary = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="grants")
    resource = relationship("Resource", back_populates="grants")

    __table_args__ = (
        Index("ix_grants_user_resource", "user_id", "resource_id"),
        Index("ix_grants_status", "status"),
        Index("ix_grants_expiry", "expiry_date"),
    )


class Delegation(Base):
    """Delegated access from one user to another."""
    __tablename__ = "delegations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    delegator_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    delegate_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    resource_id = Column(Integer, ForeignKey("resources.id"), nullable=False)
    permission_level = Column(String(20), nullable=False)
    purpose = Column(Text, nullable=True)
    granted_date = Column(Date, nullable=False)
    expiry_date = Column(Date, nullable=True)
    status = Column(String(20), default="ACTIVE")
    created_at = Column(DateTime, default=datetime.utcnow)

    delegator = relationship("User", foreign_keys=[delegator_id], back_populates="delegated_grants")
    delegate = relationship("User", foreign_keys=[delegate_id], back_populates="received_delegations")
    resource = relationship("Resource")


# ── Policy ─────────────────────────────────────────────────────────────
class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_id = Column(String(50), unique=True, nullable=False)  # e.g. POL-001
    name = Column(String(200), nullable=False)
    description = Column(Text)
    rule_type = Column(String(50), nullable=False)  # max_duration, privilege_restriction, ownership_required, etc.
    parameters = Column(Text)  # JSON string for rule parameters
    severity = Column(String(20), default="MEDIUM")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ── Scan & Findings ───────────────────────────────────────────────────
class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_date = Column(DateTime, default=datetime.utcnow)
    scan_type = Column(String(50), default="FULL")  # FULL, INCREMENTAL
    total_permissions_scanned = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    needs_review_count = Column(Integer, default=0)
    simulated_date = Column(Date, nullable=True)  # For time-travel scans
    completed_at = Column(DateTime, nullable=True)

    findings = relationship("Finding", back_populates="scan_run")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_uid = Column(String(50), unique=True, nullable=False)  # e.g. FND-00001
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    resource_id = Column(Integer, ForeignKey("resources.id"), nullable=False)
    grant_id = Column(Integer, ForeignKey("grants.id"), nullable=True)
    delegation_id = Column(Integer, ForeignKey("delegations.id"), nullable=True)
    role_assignment_id = Column(Integer, ForeignKey("role_assignments.id"), nullable=True)
    policy_id = Column(String(50), nullable=False)
    effective_permission = Column(String(20), nullable=False)
    expected_state = Column(Text, nullable=False)
    observed_state = Column(Text, nullable=False)
    evidence_source = Column(Text, nullable=False)
    access_path = Column(Text)  # JSON: explanation of inheritance chain
    classification = Column(String(30), nullable=False)
    severity = Column(String(20), nullable=False)
    risk_score = Column(Float, default=0.0)
    recommended_action = Column(Text)
    status = Column(String(20), default="OPEN")
    reviewer = Column(String(200), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_run = relationship("ScanRun", back_populates="findings")
    user = relationship("User")
    resource = relationship("Resource")
    grant = relationship("Grant")
    review_actions = relationship("ReviewActionRecord", back_populates="finding")

    __table_args__ = (
        Index("ix_findings_classification", "classification"),
        Index("ix_findings_severity", "severity"),
        Index("ix_findings_status", "status"),
        Index("ix_findings_scan", "scan_run_id"),
    )


class ReviewActionRecord(Base):
    __tablename__ = "review_actions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    action = Column(String(30), nullable=False)
    reviewer = Column(String(200), nullable=False)
    justification = Column(Text, nullable=False)
    previous_status = Column(String(20), nullable=False)
    new_status = Column(String(20), nullable=False)
    previous_grant_status = Column(String(20), nullable=True)
    new_grant_status = Column(String(20), nullable=True)
    extension_date = Column(Date, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="review_actions")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    actor = Column(String(200), nullable=False)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=False)  # finding, grant, delegation, user, policy, scan
    target_id = Column(String(50), nullable=False)
    previous_state = Column(Text)  # JSON
    new_state = Column(Text)  # JSON
    reason = Column(Text)
    related_finding_id = Column(String(50), nullable=True)
    ip_address = Column(String(50), default="127.0.0.1")

    __table_args__ = (
        Index("ix_audit_timestamp", "timestamp"),
        Index("ix_audit_actor", "actor"),
        Index("ix_audit_target", "target_type", "target_id"),
    )


def create_tables(engine):
    """Create all tables."""
    Base.metadata.create_all(engine)
