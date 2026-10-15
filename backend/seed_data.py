"""
AccessLease Sentinel - Demo Data Seeder
30+ synthetic permission grants across departments with labelled scenarios.
"""
from datetime import date, datetime, timedelta
from sqlalchemy.orm import Session
from models import (
    Base, User, Role, Resource, RoleAssignment, RolePermission,
    Grant, Delegation, Policy, AuditEvent
)


def seed_demo_data(db: Session):
    """Seed all demo data. Idempotent — checks if data exists."""
    if db.query(User).count() > 0:
        return False  # Already seeded

    # ── Users ──────────────────────────────────────────────────────────
    users = [
        User(username="admin.sharma", full_name="Dr. Ananya Sharma", email="ananya.sharma@manipal.edu", department="University IT", user_type="staff"),
        User(username="prof.patel", full_name="Prof. Rajesh Patel", email="rajesh.patel@manipal.edu", department="Computer Science", user_type="faculty"),
        User(username="dr.chen", full_name="Dr. Wei Chen", email="wei.chen@visiting.edu", department="Research Lab", user_type="visiting_faculty"),
        User(username="staff.kumar", full_name="Vikram Kumar", email="vikram.kumar@manipal.edu", department="Finance", user_type="staff"),
        User(username="temp.jones", full_name="Sarah Jones", email="sarah.jones@temp.edu", department="Library", user_type="temp_staff"),
        User(username="guest.williams", full_name="James Williams", email="james.williams@guest.edu", department="Event Management", user_type="guest"),
        User(username="student.rao", full_name="Priya Rao", email="priya.rao@student.manipal.edu", department="Computer Science", user_type="student"),
        User(username="prof.garcia", full_name="Prof. Maria Garcia", email="maria.garcia@manipal.edu", department="Research Lab", user_type="faculty"),
        User(username="tech.singh", full_name="Arjun Singh", email="arjun.singh@manipal.edu", department="University IT", user_type="staff"),
        User(username="lib.nair", full_name="Meera Nair", email="meera.nair@manipal.edu", department="Library", user_type="staff"),
        User(username="guest.brown", full_name="Robert Brown", email="robert.brown@guest.edu", department="Research Lab", user_type="guest"),
        User(username="temp.davis", full_name="Emily Davis", email="emily.davis@temp.edu", department="Finance", user_type="temp_staff"),
        User(username="prof.muller", full_name="Prof. Hans Müller", email="hans.muller@visiting.edu", department="Research Lab", user_type="visiting_faculty"),
        User(username="staff.reddy", full_name="Karthik Reddy", email="karthik.reddy@manipal.edu", department="Event Management", user_type="staff"),
        User(username="student.lee", full_name="Min-Jun Lee", email="minjun.lee@student.manipal.edu", department="Computer Science", user_type="student"),
    ]
    db.add_all(users)
    db.flush()

    # ── Roles ──────────────────────────────────────────────────────────
    roles = [
        Role(name="System Administrator", description="Full system admin access", max_permission_level="ADMIN", department="University IT"),
        Role(name="IT Support", description="IT helpdesk and system maintenance", max_permission_level="WRITE", department="University IT"),
        Role(name="Research Lead", description="Lead researcher with lab access", max_permission_level="ADMIN", department="Research Lab", is_temporary=True),
        Role(name="Research Assistant", description="Temporary research assistant role", max_permission_level="WRITE", department="Research Lab", is_temporary=True),
        Role(name="Library Staff", description="Library system access", max_permission_level="WRITE", department="Library"),
        Role(name="Finance Analyst", description="Financial reporting access", max_permission_level="READ", department="Finance"),
        Role(name="Event Coordinator", description="Event management access", max_permission_level="WRITE", department="Event Management", is_temporary=True),
        Role(name="Student Researcher", description="Student project access", max_permission_level="READ", department="Computer Science", is_temporary=True),
        Role(name="Visiting Professor", description="Visiting faculty temporary access", max_permission_level="WRITE", department="Research Lab", is_temporary=True),
        Role(name="Guest Speaker", description="Limited guest event access", max_permission_level="READ", department="Event Management", is_temporary=True),
    ]
    db.add_all(roles)
    db.flush()

    # ── Resources ──────────────────────────────────────────────────────
    resources = [
        Resource(name="Central Authentication Server", resource_type="server", department="University IT", sensitivity="CRITICAL", description="LDAP/SSO authentication system"),
        Resource(name="Student Records Database", resource_type="database", department="University IT", sensitivity="HIGH", description="Student enrollment and grades"),
        Resource(name="Research Data Cluster", resource_type="server", department="Research Lab", sensitivity="HIGH", description="HPC cluster for research computations"),
        Resource(name="Lab Equipment Controller", resource_type="lab_equipment", department="Research Lab", sensitivity="STANDARD", description="IoT controller for lab instruments"),
        Resource(name="Library Management System", resource_type="application", department="Library", sensitivity="STANDARD", description="Cataloging and lending system"),
        Resource(name="Financial Reporting Portal", resource_type="application", department="Finance", sensitivity="HIGH", description="Budget and expense tracking"),
        Resource(name="Event Booking Platform", resource_type="application", department="Event Management", sensitivity="LOW", description="Room and event scheduling"),
        Resource(name="Code Repository Server", resource_type="server", department="Computer Science", sensitivity="STANDARD", description="GitLab instance for projects"),
        Resource(name="Email Server", resource_type="server", department="University IT", sensitivity="HIGH", description="Exchange mail server"),
        Resource(name="Backup Storage Array", resource_type="server", department="University IT", sensitivity="CRITICAL", description="Centralized backup infrastructure"),
        Resource(name="Research Publications DB", resource_type="database", department="Research Lab", sensitivity="STANDARD", description="Internal publication repository"),
        Resource(name="Campus Network Firewall", resource_type="server", department="University IT", sensitivity="CRITICAL", description="Perimeter firewall management"),
    ]
    db.add_all(resources)
    db.flush()

    # ── Role Permissions ───────────────────────────────────────────────
    role_perms = [
        # System Administrator → full access to IT resources
        RolePermission(role_id=roles[0].id, resource_id=resources[0].id, permission_level="ADMIN"),
        RolePermission(role_id=roles[0].id, resource_id=resources[1].id, permission_level="ADMIN"),
        RolePermission(role_id=roles[0].id, resource_id=resources[8].id, permission_level="ADMIN"),
        RolePermission(role_id=roles[0].id, resource_id=resources[9].id, permission_level="ADMIN"),
        RolePermission(role_id=roles[0].id, resource_id=resources[11].id, permission_level="ADMIN"),
        # IT Support → write to IT resources
        RolePermission(role_id=roles[1].id, resource_id=resources[0].id, permission_level="WRITE"),
        RolePermission(role_id=roles[1].id, resource_id=resources[8].id, permission_level="WRITE"),
        # Research Lead → admin on research resources
        RolePermission(role_id=roles[2].id, resource_id=resources[2].id, permission_level="ADMIN"),
        RolePermission(role_id=roles[2].id, resource_id=resources[3].id, permission_level="ADMIN"),
        RolePermission(role_id=roles[2].id, resource_id=resources[10].id, permission_level="WRITE"),
        # Research Assistant → write on research resources
        RolePermission(role_id=roles[3].id, resource_id=resources[2].id, permission_level="WRITE"),
        RolePermission(role_id=roles[3].id, resource_id=resources[3].id, permission_level="WRITE"),
        RolePermission(role_id=roles[3].id, resource_id=resources[10].id, permission_level="READ"),
        # Library Staff
        RolePermission(role_id=roles[4].id, resource_id=resources[4].id, permission_level="WRITE"),
        # Finance Analyst
        RolePermission(role_id=roles[5].id, resource_id=resources[5].id, permission_level="READ"),
        # Event Coordinator
        RolePermission(role_id=roles[6].id, resource_id=resources[6].id, permission_level="WRITE"),
        # Student Researcher
        RolePermission(role_id=roles[7].id, resource_id=resources[7].id, permission_level="READ"),
        RolePermission(role_id=roles[7].id, resource_id=resources[10].id, permission_level="READ"),
        # Visiting Professor
        RolePermission(role_id=roles[8].id, resource_id=resources[2].id, permission_level="WRITE"),
        RolePermission(role_id=roles[8].id, resource_id=resources[3].id, permission_level="READ"),
        RolePermission(role_id=roles[8].id, resource_id=resources[10].id, permission_level="READ"),
        # Guest Speaker
        RolePermission(role_id=roles[9].id, resource_id=resources[6].id, permission_level="READ"),
    ]
    db.add_all(role_perms)
    db.flush()

    today = date.today()
    past_30 = today - timedelta(days=30)
    past_60 = today - timedelta(days=60)
    past_90 = today - timedelta(days=90)
    past_120 = today - timedelta(days=120)
    future_30 = today + timedelta(days=30)
    future_60 = today + timedelta(days=60)
    past_10 = today - timedelta(days=10)
    past_5 = today - timedelta(days=5)

    # ── Role Assignments ───────────────────────────────────────────────
    role_assigns = [
        # Admin Sharma → System Administrator (permanent)
        RoleAssignment(user_id=users[0].id, role_id=roles[0].id, assigned_date=past_120, assigned_by="HR System", purpose="Primary system administrator"),
        # Prof Patel → Student Researcher (supervising)
        RoleAssignment(user_id=users[1].id, role_id=roles[7].id, assigned_date=past_60, assigned_by="Dept Head", purpose="CS project supervision"),
        # Dr Chen → Research Lead (visiting, EXPIRED but still active — SCENARIO)
        RoleAssignment(user_id=users[2].id, role_id=roles[2].id, assigned_date=past_90, expiry_date=past_10, assigned_by="Research Director", purpose="Collaboration on ML project", is_active=True),
        # Vikram Kumar → Finance Analyst
        RoleAssignment(user_id=users[3].id, role_id=roles[5].id, assigned_date=past_60, assigned_by="Finance Head", purpose="Quarterly reporting"),
        # Sarah Jones → Library Staff (temp)
        RoleAssignment(user_id=users[4].id, role_id=roles[4].id, assigned_date=past_30, expiry_date=future_30, assigned_by="Library Director", purpose="Summer catalog digitization"),
        # James Williams → Guest Speaker (expired)
        RoleAssignment(user_id=users[5].id, role_id=roles[9].id, assigned_date=past_60, expiry_date=past_30, assigned_by="Event Team", purpose="Guest lecture series", is_active=True),
        # Priya Rao → Student Researcher
        RoleAssignment(user_id=users[6].id, role_id=roles[7].id, assigned_date=past_30, expiry_date=future_60, assigned_by="Prof. Patel", purpose="Final year project"),
        # Prof Garcia → Research Lead
        RoleAssignment(user_id=users[7].id, role_id=roles[2].id, assigned_date=past_120, assigned_by="Dean of Research", purpose="Principal investigator"),
        # Arjun Singh → IT Support
        RoleAssignment(user_id=users[8].id, role_id=roles[1].id, assigned_date=past_90, assigned_by="IT Director", purpose="Helpdesk operations"),
        # Meera Nair → Library Staff
        RoleAssignment(user_id=users[9].id, role_id=roles[4].id, assigned_date=past_120, assigned_by="Library Director", purpose="Senior librarian"),
        # Robert Brown → Guest (NO role assignment — only direct grant scenario)
        # Emily Davis → Finance (temp, NO expiry — SCENARIO)
        RoleAssignment(user_id=users[11].id, role_id=roles[5].id, assigned_date=past_60, assigned_by="Finance Head", purpose="Temporary audit support"),
        # Prof Müller → Visiting Professor
        RoleAssignment(user_id=users[12].id, role_id=roles[8].id, assigned_date=past_30, expiry_date=future_30, assigned_by="Research Director", purpose="Guest research collaboration"),
        # Karthik Reddy → Event Coordinator
        RoleAssignment(user_id=users[13].id, role_id=roles[6].id, assigned_date=past_30, expiry_date=future_30, assigned_by="Admin Office", purpose="Annual tech fest"),
        # Min-Jun Lee → Student Researcher
        RoleAssignment(user_id=users[14].id, role_id=roles[7].id, assigned_date=past_30, expiry_date=future_60, assigned_by="Prof. Garcia", purpose="Research internship"),
    ]
    db.add_all(role_assigns)
    db.flush()

    # ── Direct Grants (30+ across departments) ────────────────────────
    grants = [
        # 1. SCENARIO: Valid permanent admin grant
        Grant(user_id=users[0].id, resource_id=resources[0].id, permission_level="ADMIN",
              grant_source="DIRECT", owner="IT Director", purpose="System administration duties",
              granted_date=past_120, status="ACTIVE"),

        # 2. SCENARIO: Expired but still active (Dr. Chen still has access after project ended)
        Grant(user_id=users[2].id, resource_id=resources[2].id, permission_level="WRITE",
              grant_source="DIRECT", owner="Research Director", purpose="ML research collaboration",
              granted_date=past_90, expiry_date=past_10, status="ACTIVE", is_temporary=True),

        # 3. SCENARIO: Guest with ADMIN — PROHIBITED
        Grant(user_id=users[5].id, resource_id=resources[6].id, permission_level="ADMIN",
              grant_source="DIRECT", owner="Event Team Lead", purpose="Event setup emergency access",
              granted_date=past_60, expiry_date=past_30, status="ACTIVE", is_temporary=True),

        # 4. SCENARIO: Missing owner
        Grant(user_id=users[10].id, resource_id=resources[2].id, permission_level="READ",
              grant_source="DIRECT", owner=None, purpose="Data analysis for paper",
              granted_date=past_60, expiry_date=future_30, status="ACTIVE", is_temporary=True),

        # 5. SCENARIO: Missing purpose
        Grant(user_id=users[3].id, resource_id=resources[5].id, permission_level="READ",
              grant_source="DIRECT", owner="Finance Head", purpose=None,
              granted_date=past_60, status="ACTIVE"),

        # 6. SCENARIO: Missing expiry on temporary grant
        Grant(user_id=users[11].id, resource_id=resources[5].id, permission_level="READ",
              grant_source="DIRECT", owner="Finance Head", purpose="Audit support",
              granted_date=past_60, expiry_date=None, status="ACTIVE", is_temporary=True),

        # 7. SCENARIO: Valid temporary permission (not expired)
        Grant(user_id=users[4].id, resource_id=resources[4].id, permission_level="WRITE",
              grant_source="DIRECT", owner="Library Director", purpose="Catalog digitization project",
              granted_date=past_30, expiry_date=future_30, status="ACTIVE", is_temporary=True),

        # 8. SCENARIO: Inherited excessive permission (Dr. Chen inherits ADMIN from Research Lead role on Lab Equipment)
        # This is tracked via role assignment + role_permissions; no direct grant needed but we add a READ direct grant
        Grant(user_id=users[2].id, resource_id=resources[3].id, permission_level="READ",
              grant_source="DIRECT", owner="Lab Manager", purpose="Lab equipment monitoring",
              granted_date=past_90, expiry_date=past_10, status="ACTIVE", is_temporary=True),

        # 9. SCENARIO: Legitimate approved extension
        Grant(user_id=users[12].id, resource_id=resources[2].id, permission_level="WRITE",
              grant_source="DIRECT", owner="Research Director", purpose="Extended collaboration - approved by Dean",
              granted_date=past_30, expiry_date=future_60, status="ACTIVE", is_temporary=True),

        # 10. SCENARIO: Revoked permission
        Grant(user_id=users[5].id, resource_id=resources[0].id, permission_level="READ",
              grant_source="DIRECT", owner="IT Director", purpose="Temp auth system check",
              granted_date=past_90, expiry_date=past_60, status="REVOKED", is_temporary=True),

        # 11. Prof Patel direct access to code repo
        Grant(user_id=users[1].id, resource_id=resources[7].id, permission_level="ADMIN",
              grant_source="DIRECT", owner="CS Department Head", purpose="Course project management",
              granted_date=past_60, status="ACTIVE"),

        # 12. Student Priya Rao → code repo
        Grant(user_id=users[6].id, resource_id=resources[7].id, permission_level="WRITE",
              grant_source="DIRECT", owner="Prof. Patel", purpose="Final year project repository",
              granted_date=past_30, expiry_date=future_60, status="ACTIVE", is_temporary=True),

        # 13. Arjun Singh → email server
        Grant(user_id=users[8].id, resource_id=resources[8].id, permission_level="WRITE",
              grant_source="DIRECT", owner="IT Director", purpose="Mail server maintenance",
              granted_date=past_90, status="ACTIVE"),

        # 14. SCENARIO: Ownerless grant on sensitive resource
        Grant(user_id=users[8].id, resource_id=resources[9].id, permission_level="WRITE",
              grant_source="DIRECT", owner=None, purpose="Backup rotation duties",
              granted_date=past_60, status="ACTIVE"),

        # 15. Meera Nair library system
        Grant(user_id=users[9].id, resource_id=resources[4].id, permission_level="WRITE",
              grant_source="DIRECT", owner="Library Director", purpose="Senior librarian duties",
              granted_date=past_120, status="ACTIVE"),

        # 16. SCENARIO: Guest with no expiry accessing research data
        Grant(user_id=users[10].id, resource_id=resources[10].id, permission_level="READ",
              grant_source="DIRECT", owner="Prof. Garcia", purpose="Publication review",
              granted_date=past_30, expiry_date=None, status="ACTIVE", is_temporary=True),

        # 17. Prof Garcia → research cluster admin
        Grant(user_id=users[7].id, resource_id=resources[2].id, permission_level="ADMIN",
              grant_source="DIRECT", owner="Dean of Research", purpose="Principal investigator",
              granted_date=past_120, status="ACTIVE"),

        # 18. SCENARIO: Over-broad — student with WRITE on research cluster
        Grant(user_id=users[14].id, resource_id=resources[2].id, permission_level="WRITE",
              grant_source="DIRECT", owner="Prof. Garcia", purpose="Research internship computations",
              granted_date=past_30, expiry_date=future_60, status="ACTIVE", is_temporary=True),

        # 19. Karthik Reddy → event platform
        Grant(user_id=users[13].id, resource_id=resources[6].id, permission_level="WRITE",
              grant_source="DIRECT", owner="Admin Office", purpose="Tech fest coordination",
              granted_date=past_30, expiry_date=future_30, status="ACTIVE", is_temporary=True),

        # 20. Admin Sharma → campus firewall
        Grant(user_id=users[0].id, resource_id=resources[11].id, permission_level="ADMIN",
              grant_source="DIRECT", owner="IT Director", purpose="Firewall policy management",
              granted_date=past_120, status="ACTIVE"),

        # 21. SCENARIO: Expired temp grant on email - still active
        Grant(user_id=users[11].id, resource_id=resources[8].id, permission_level="READ",
              grant_source="DIRECT", owner="IT Director", purpose="Email access for audit comms",
              granted_date=past_60, expiry_date=past_5, status="ACTIVE", is_temporary=True),

        # 22. Min-Jun Lee → publications DB
        Grant(user_id=users[14].id, resource_id=resources[10].id, permission_level="READ",
              grant_source="DIRECT", owner="Prof. Garcia", purpose="Literature review for internship",
              granted_date=past_30, expiry_date=future_60, status="ACTIVE", is_temporary=True),

        # 23. Prof Müller → lab equipment read
        Grant(user_id=users[12].id, resource_id=resources[3].id, permission_level="READ",
              grant_source="DIRECT", owner="Lab Manager", purpose="Equipment familiarization",
              granted_date=past_30, expiry_date=future_30, status="ACTIVE", is_temporary=True),

        # 24. SCENARIO: Missing purpose AND missing owner on HIGH sensitivity resource
        Grant(user_id=users[10].id, resource_id=resources[1].id, permission_level="READ",
              grant_source="DIRECT", owner=None, purpose=None,
              granted_date=past_30, expiry_date=future_30, status="ACTIVE", is_temporary=True),

        # 25. Admin backup access
        Grant(user_id=users[0].id, resource_id=resources[9].id, permission_level="ADMIN",
              grant_source="DIRECT", owner="IT Director", purpose="Backup administration",
              granted_date=past_120, status="ACTIVE"),

        # 26. Priya Rao → publications DB
        Grant(user_id=users[6].id, resource_id=resources[10].id, permission_level="READ",
              grant_source="DIRECT", owner="Prof. Patel", purpose="Project literature review",
              granted_date=past_30, expiry_date=future_60, status="ACTIVE", is_temporary=True),

        # 27. SCENARIO: Expired 90+ day old grant still active
        Grant(user_id=users[2].id, resource_id=resources[10].id, permission_level="WRITE",
              grant_source="DIRECT", owner="Research Director", purpose="Publication submissions",
              granted_date=past_120, expiry_date=past_60, status="ACTIVE", is_temporary=True),

        # 28. Sarah Jones library temp — valid
        Grant(user_id=users[4].id, resource_id=resources[4].id, permission_level="READ",
              grant_source="DIRECT", owner="Library Director", purpose="Catalog research",
              granted_date=past_30, expiry_date=future_30, status="ACTIVE", is_temporary=True),

        # 29. SCENARIO: Student direct ADMIN on code repo — over-broad
        Grant(user_id=users[6].id, resource_id=resources[7].id, permission_level="ADMIN",
              grant_source="DIRECT", owner="Prof. Patel", purpose="Emergency repo admin for demo day",
              granted_date=past_5, expiry_date=future_30, status="ACTIVE", is_temporary=True),

        # 30. SCENARIO: Visiting faculty accessing finance — cross-department
        Grant(user_id=users[12].id, resource_id=resources[5].id, permission_level="READ",
              grant_source="DIRECT", owner=None, purpose="Travel reimbursement access",
              granted_date=past_30, expiry_date=future_30, status="ACTIVE", is_temporary=True),

        # 31. IT support on student records
        Grant(user_id=users[8].id, resource_id=resources[1].id, permission_level="READ",
              grant_source="DIRECT", owner="IT Director", purpose="Student system maintenance support",
              granted_date=past_60, status="ACTIVE"),

        # 32. SCENARIO: Delegated grant — tracked in delegations table
        # Prof Garcia → Dr. Chen on research cluster (separate delegation record)
    ]
    db.add_all(grants)
    db.flush()

    # ── Delegations ────────────────────────────────────────────────────
    delegations = [
        # SCENARIO: Delegated access from Prof Garcia to Dr Chen
        Delegation(
            delegator_id=users[7].id,  # Prof Garcia
            delegate_id=users[2].id,    # Dr Chen
            resource_id=resources[2].id, # Research Data Cluster
            permission_level="ADMIN",
            purpose="Delegated admin for ML project while Garcia on sabbatical",
            granted_date=past_60,
            expiry_date=past_10,
            status="ACTIVE"
        ),
        # SCENARIO: Valid delegation
        Delegation(
            delegator_id=users[1].id,   # Prof Patel
            delegate_id=users[6].id,    # Priya Rao
            resource_id=resources[7].id, # Code Repository
            permission_level="WRITE",
            purpose="Project code review delegation",
            granted_date=past_30,
            expiry_date=future_30,
            status="ACTIVE"
        ),
        # SCENARIO: Expired delegation still active
        Delegation(
            delegator_id=users[0].id,   # Admin Sharma
            delegate_id=users[8].id,    # Arjun Singh
            resource_id=resources[11].id, # Campus Firewall
            permission_level="ADMIN",
            purpose="Emergency firewall access during admin leave",
            granted_date=past_60,
            expiry_date=past_30,
            status="ACTIVE"
        ),
    ]
    db.add_all(delegations)
    db.flush()

    # ── Policies ───────────────────────────────────────────────────────
    policies = [
        Policy(
            policy_id="POL-001", name="Temporary Access Maximum Duration",
            description="Temporary access grants must not exceed 30 days without re-approval",
            rule_type="max_duration", parameters='{"max_days": 30}',
            severity="HIGH"
        ),
        Policy(
            policy_id="POL-002", name="Guest Admin Prohibition",
            description="Guest accounts must not have ADMIN-level permissions on any resource",
            rule_type="privilege_restriction",
            parameters='{"user_types": ["guest"], "prohibited_levels": ["ADMIN"]}',
            severity="CRITICAL"
        ),
        Policy(
            policy_id="POL-003", name="Grant Ownership Required",
            description="Every active permission grant must have a designated owner",
            rule_type="ownership_required", parameters='{}',
            severity="MEDIUM"
        ),
        Policy(
            policy_id="POL-004", name="Temporary Grant Expiry Required",
            description="Every temporary permission grant must have an expiry date",
            rule_type="expiry_required", parameters='{}',
            severity="HIGH"
        ),
        Policy(
            policy_id="POL-005", name="Grant Purpose Required",
            description="Every active permission grant must have a documented purpose/justification",
            rule_type="purpose_required", parameters='{}',
            severity="MEDIUM"
        ),
        Policy(
            policy_id="POL-006", name="Expired Access Must Be Deactivated",
            description="Permissions past their expiry date must not remain in ACTIVE status",
            rule_type="expired_active", parameters='{}',
            severity="CRITICAL"
        ),
        Policy(
            policy_id="POL-007", name="Role Permission Boundary",
            description="Effective access must not exceed the maximum permission level defined for the user's assigned role",
            rule_type="role_boundary", parameters='{}',
            severity="HIGH"
        ),
        Policy(
            policy_id="POL-008", name="Delegation Expiry Enforcement",
            description="Delegated access past its expiry date must not remain active",
            rule_type="delegation_expired", parameters='{}',
            severity="HIGH"
        ),
    ]
    db.add_all(policies)
    db.flush()

    # ── Initial Audit Event ────────────────────────────────────────────
    db.add(AuditEvent(
        actor="SYSTEM",
        action="SEED_DATA",
        target_type="system",
        target_id="demo_data",
        new_state='{"status": "seeded"}',
        reason="Initial demo data seed for AccessLease Sentinel"
    ))

    db.commit()
    return True


def reset_demo_data(db: Session, engine):
    """Drop all data and re-seed."""
    from models import Base
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return seed_demo_data(db)


def seed_expiry_examples(db):
    """Add labelled examples once to an existing synthetic demo, never reset dates."""
    marker='expiry_examples_v1'
    if db.query(AuditEvent).filter(AuditEvent.target_id==marker).first():
        return False
    if not db.query(AuditEvent).filter(AuditEvent.action=='SEED_DATA', AuditEvent.target_id=='demo_data').first():
        return False
    users=db.query(User).order_by(User.id).limit(3).all()
    resource=db.query(Resource).order_by(Resource.id).first()
    if len(users)<3 or not resource:
        return False
    today=date.today()
    for i,offset in enumerate([0,1,1,-1,-3]):
        db.add(Grant(user_id=users[i%3].id, resource_id=resource.id,
            permission_level='READ', owner='Demo Administrator',
            purpose='Expiry demonstration (synthetic case '+str(i+1)+')',
            granted_date=today-timedelta(days=7), expiry_date=today+timedelta(days=offset),
            status='ACTIVE', is_temporary=True))
    db.add(AuditEvent(actor='SYSTEM',action='SEED_EXPIRY_EXAMPLES',target_type='system',
        target_id=marker,reason='Added five synthetic expiry examples once'))
    db.commit()
    return True
