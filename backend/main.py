"""AccessLease Sentinel demo API. Run from backend: python -m uvicorn main:app."""
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
import os
from typing import Optional

from fastapi import Body, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi import Request
from sqlalchemy.orm import Session, joinedload

from database import engine, SessionLocal, get_db, HOSTED
from models import (create_tables, User, Resource, Grant, Delegation,
                    RoleAssignment, Finding, ScanRun, Policy,
                    FindingSeverity, FindingClassification, FindingStatus, GrantStatus)
from policy_engine import calculate_effective_access, run_policy_scan
from seed_data import seed_demo_data, seed_expiry_examples
from schemas import (DashboardMetrics, ScanRunOut, ScanRequest, FindingOut,
                     GrantOut, EffectiveAccessOut, UserOut, ResourceOut,
                     PolicyOut, DelegationOut, RoleAssignmentOut)

# Serializes seed/scan writes for the single-process local demo.
from features import router as feature_router, require_admin, current_admin, write_lock
from integrations import router as integration_router


def latest_scan(db):
    return db.query(ScanRun).filter(ScanRun.completed_at.isnot(None)).order_by(ScanRun.id.desc()).first()


@asynccontextmanager
async def lifespan(app):
    with write_lock(), SessionLocal() as db:
        create_tables(engine)
        try:
            if HOSTED:
                from features import AdminAccount, Credentials, hash_password
                if db.query(AdminAccount).first() is None:
                    try:
                        credentials=Credentials(username=os.getenv('BOOTSTRAP_ADMIN_USERNAME',''),password=os.getenv('BOOTSTRAP_ADMIN_PASSWORD',''))
                    except ValueError:
                        raise RuntimeError('Configure a valid BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD in deployment settings') from None
                    db.add(AdminAccount(username=credentials.username,password_hash=hash_password(credentials.password)))
                    db.commit()
            if os.getenv("SEED_DEMO_DATA", "false" if HOSTED else "true").lower() in {"true", "1", "yes"}:
                seed_demo_data(db)
                if seed_expiry_examples(db):
                    run_policy_scan(db)
            if latest_scan(db) is None and db.query(User).first() is not None:
                run_policy_scan(db)
        except Exception:
            db.rollback()
            raise
    yield


def protect_api(request:Request,db:Session=Depends(get_db)):
    # The bridge endpoint has its own scoped Bearer-token dependency.
    public={'/','/reset-password','/api/health','/api/auth/status','/api/auth/login','/api/auth/setup','/api/auth/logout','/api/auth/reset-password','/api/auth/reset-challenge'}
    path=request.url.path.rstrip('/') or '/'
    if path in public or path=='/api/integrations/slcm/sync':return
    if not current_admin(request,db):raise HTTPException(401,'Admin sign-in required')


app = FastAPI(dependencies=[Depends(protect_api)],title="AccessLease Sentinel", version="1.0.0", lifespan=lifespan,
              description="Local hackathon demo for permission governance and policy findings.")
app.include_router(feature_router)
app.include_router(integration_router)

@app.middleware('http')
async def protect_browser_writes(request: Request, call_next):
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        origin = request.headers.get('origin')
        expected = f'{request.url.scheme}://{request.url.netloc}'
        if (origin and origin != expected) or request.headers.get('sec-fetch-site') == 'cross-site':
            return JSONResponse({'detail': 'Cross-origin writes are not allowed'}, status_code=403)
    response=await call_next(request)
    if request.url.path.startswith('/api/') or request.url.path in {'/','/workspace','/reset-password'}:
        response.headers['Cache-Control']='no-store'
        response.headers['Pragma']='no-cache'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['X-Frame-Options']='SAMEORIGIN'
    return response
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173",
                   "http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST"], allow_headers=["Content-Type"],
)


FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND.is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND), name="frontend")


@app.get("/reset-password", include_in_schema=False)
@app.get("/", include_in_schema=False)
def root():
    if (FRONTEND / "index.html").is_file():
        return FileResponse(FRONTEND / "index.html")
    return {"name": "AccessLease Sentinel", "docs": "/docs", "health": "/api/health"}


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/seed")
def seed(db: Session = Depends(get_db), admin=Depends(require_admin)):
    with write_lock():
        try:
            seeded = seed_demo_data(db)
            if latest_scan(db) is None and db.query(User).first() is not None:
                run_policy_scan(db)
            return {"seeded": seeded, "message": "Demo data seeded" if seeded else "Data already exists"}
        except Exception:
            db.rollback()
            raise


@app.post("/api/scan", response_model=ScanRunOut)
def scan(request: Optional[ScanRequest] = Body(default=None), db: Session = Depends(get_db), admin=Depends(require_admin)):
    with write_lock():
        try:
            return run_policy_scan(db, simulated_date=request.simulated_date if request else None)
        except Exception:
            db.rollback()
            raise


@app.get("/api/scans", response_model=list[ScanRunOut])
def scans(limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    return db.query(ScanRun).order_by(ScanRun.id.desc()).limit(limit).all()


@app.get("/api/dashboard", response_model=DashboardMetrics)
@app.get("/api/dashboard/metrics", response_model=DashboardMetrics)
def dashboard(db: Session = Depends(get_db)):
    scan_run = latest_scan(db)
    findings = db.query(Finding).filter(Finding.scan_run_id == scan_run.id).all() if scan_run else []
    # Metrics count access paths, not distinct user/resource pairs. Expired paths
    # remain visible while their underlying permission is still active.
    access = calculate_effective_access(db)
    grants = {g.id: g for g in db.query(Grant).all()}
    delegations = {d.id: d for d in db.query(Delegation).all()}
    assignments = {a.id: a for a in db.query(RoleAssignment).all()}
    sources = {"DIRECT": grants, "DELEGATED": delegations, "ROLE_INHERITED": assignments}
    evaluation_date = (scan_run.simulated_date if scan_run else None) or date.today()
    expired = 0
    for entry in access:
        source = sources[entry.source_type][entry.source_id]
        active = source.is_active if entry.source_type == "ROLE_INHERITED" else source.status == "ACTIVE"
        expired += bool(active and source.expiry_date and source.expiry_date < evaluation_date)
    return DashboardMetrics(
        total_users=db.query(User).filter(User.is_active==True).count(), total_active_permissions=len(access),
        expired_active_permissions=expired,
        overbroad_grants=sum(f.policy_id == "POL-007" for f in findings),
        ownerless_grants=sum(g.status in {"ACTIVE", "PENDING_REVIEW"} and not (g.owner or "").strip() for g in grants.values()),
        confirmed_violations=sum(f.classification == "CONFIRMED_VIOLATION" for f in findings),
        needs_review=sum(f.classification == "NEEDS_REVIEW" for f in findings),
        resolved_findings=sum(f.status == "RESOLVED" for f in findings),
        last_scan=ScanRunOut.model_validate(scan_run) if scan_run else None,
    )


@app.get("/api/findings", response_model=list[FindingOut])
def findings(scan_id: Optional[int] = Query(None, ge=1),
             severity: Optional[FindingSeverity] = None,
             classification: Optional[FindingClassification] = None,
             status: Optional[FindingStatus] = None,
             user_id: Optional[int] = Query(None, ge=1), department: Optional[str] = None,
             offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000),
             db: Session = Depends(get_db)):
    selected = db.get(ScanRun, scan_id) if scan_id is not None else latest_scan(db)
    if selected is None:
        if scan_id is not None:
            raise HTTPException(404, "Scan not found")
        return []
    query = db.query(Finding).options(joinedload(Finding.user), joinedload(Finding.resource)).filter(Finding.scan_run_id == selected.id)
    for column, value in [(Finding.severity, severity), (Finding.classification, classification),
                          (Finding.status, status), (Finding.user_id, user_id)]:
        if value is not None:
            query = query.filter(column == value)
    if department is not None:
        query = query.join(User).filter(User.department == department)
    return query.order_by(Finding.risk_score.desc(), Finding.id).offset(offset).limit(limit).all()


@app.get("/api/findings/{finding_id}", response_model=FindingOut)
def finding_detail(finding_id: str, db: Session = Depends(get_db)):
    result = db.get(Finding, int(finding_id)) if finding_id.isdecimal() else db.query(Finding).filter(Finding.finding_uid == finding_id).first()
    if result is None:
        raise HTTPException(404, "Finding not found")
    return result


@app.get("/api/permissions/effective", response_model=list[EffectiveAccessOut])
def effective_permissions(user_id: Optional[int] = Query(None, ge=1),
                          resource_id: Optional[int] = Query(None, ge=1),
                          db: Session = Depends(get_db)):
    users = {u.id: u.full_name for u in db.query(User).all()}
    resources = {r.id: r.name for r in db.query(Resource).all()}
    if user_id is not None and user_id not in users:
        raise HTTPException(404, "User not found")
    if resource_id is not None and resource_id not in resources:
        raise HTTPException(404, "Resource not found")
    return [EffectiveAccessOut(**vars(a), user_name=users.get(a.user_id), resource_name=resources.get(a.resource_id))
            for a in calculate_effective_access(db, user_id=user_id)
            if resource_id is None or a.resource_id == resource_id]


@app.get("/api/permissions", response_model=list[GrantOut])
def permissions(user_id: Optional[int] = Query(None, ge=1),
                resource_id: Optional[int] = Query(None, ge=1), status: Optional[GrantStatus] = None,
                offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000),
                db: Session = Depends(get_db)):
    query = db.query(Grant).options(joinedload(Grant.user), joinedload(Grant.resource))
    for column, value in [(Grant.user_id, user_id), (Grant.resource_id, resource_id), (Grant.status, status)]:
        if value is not None:
            query = query.filter(column == value)
    return query.order_by(Grant.id).offset(offset).limit(limit).all()


@app.get("/api/users", response_model=list[UserOut])
def users(db: Session = Depends(get_db)):
    return db.query(User).filter(User.is_active==True).order_by(User.id).all()


@app.get("/api/resources", response_model=list[ResourceOut])
def resources(db: Session = Depends(get_db)):
    return db.query(Resource).order_by(Resource.id).all()


@app.get("/api/policies", response_model=list[PolicyOut])
def policies(db: Session = Depends(get_db)):
    return db.query(Policy).order_by(Policy.policy_id).all()


@app.get("/api/delegations", response_model=list[DelegationOut])
def delegations(db: Session = Depends(get_db)):
    return db.query(Delegation).order_by(Delegation.id).all()


@app.get("/api/role-assignments", response_model=list[RoleAssignmentOut])
def role_assignments(db: Session = Depends(get_db)):
    return db.query(RoleAssignment).order_by(RoleAssignment.id).all()


@app.get('/workspace',include_in_schema=False)
def workspace():
    return FileResponse(FRONTEND / 'workspace.html')
