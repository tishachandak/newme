"""Admin sessions, accessibility preferences, data entry and governance actions."""
from datetime import date, datetime, timedelta
from typing import Literal, Optional
import hashlib
import hmac
import json
import secrets
import os
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from database import get_db, write_lock, HOSTED
from models import Base, User, Resource, Grant, Delegation, RoleAssignment, AuditEvent, Finding, ScanRun, PermissionLevel
from schemas import UserOut, ResourceOut, GrantOut
from policy_engine import calculate_effective_access, run_policy_scan

router = APIRouter(prefix='/api')

class AdminAccount(Base):
    __tablename__ = 'admin_accounts'
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password_hash = Column(Text, nullable=False)
    preferences = Column(Text, default='{}')

class AdminSession(Base):
    __tablename__ = 'admin_sessions'
    token_hash = Column(String(64), primary_key=True)
    admin_id = Column(Integer, ForeignKey('admin_accounts.id'), nullable=False)
    expires_at = Column(DateTime, nullable=False)

class UserActivity(Base):
    __tablename__ = 'user_activity'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    actor = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    details = Column(Text, nullable=False)

class Input(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra='forbid')

class Credentials(Input):
    model_config = ConfigDict(str_strip_whitespace=False, extra="forbid")
    username: str = Field(min_length=3, max_length=100, pattern=r'^[\w.@-]+$')
    password: str = Field(min_length=10, max_length=128)
    @field_validator('password', mode='before')
    @classmethod
    def keep_password(cls, value):
        return value

class Preferences(Input):
    theme: Literal['system','light','dark'] = 'system'
    high_contrast: bool = False
    large_text: bool = False
    reduced_motion: bool = False
    warning_days: int = Field(7, ge=1, le=90)

class UserInput(Input):
    username: str = Field(min_length=3,max_length=100,pattern=r'^[\w.@-]+$')
    full_name: str = Field(min_length=2,max_length=200)
    email: str = Field(min_length=5,max_length=200,pattern=r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
    department: str = Field(min_length=2,max_length=100)
    user_type: Literal['staff','faculty','student','guest','visiting_faculty','temp_staff'] = 'student'

class ResourceInput(Input):
    name: str = Field(min_length=2,max_length=200)
    resource_type: Literal['server','database','application','lab_equipment','file_share'] = 'application'
    department: str = Field(min_length=2,max_length=100)
    sensitivity: Literal['LOW','STANDARD','HIGH','CRITICAL'] = 'STANDARD'
    description: str = Field('',max_length=2000)

class GrantInput(Input):
    user_id: int = Field(gt=0)
    resource_id: int = Field(gt=0)
    permission_level: PermissionLevel
    owner: str = Field(min_length=2,max_length=200)
    purpose: str = Field(min_length=3,max_length=2000)
    granted_date: date = Field(default_factory=date.today)
    expiry_date: Optional[date] = None
    is_temporary: bool = False
    @model_validator(mode='after')
    def check_dates(self):
        if self.granted_date > date.today():
            raise ValueError('Grant date cannot be in the future')
        if self.is_temporary and not self.expiry_date:
            raise ValueError('Temporary access requires an expiry date')
        if self.expiry_date and self.expiry_date < max(self.granted_date, date.today()):
            raise ValueError('Expiry must be today or later and not before the grant date')
        return self

class RevokeInput(Input):
    reason: str = Field(min_length=5,max_length=2000)


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()

def hash_password(value):
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(value.encode(),salt=salt.encode(),n=16384,r=8,p=1).hex()
    return salt + ':' + digest

def valid_password(value, encoded):
    salt, digest = encoded.split(':')
    return hmac.compare_digest(digest, hashlib.scrypt(value.encode(),salt=salt.encode(),n=16384,r=8,p=1).hex())

def current_admin(request: Request, db: Session = Depends(get_db)):
    value = request.cookies.get('sentinel_session','')
    session = db.get(AdminSession,token_hash(value)) if value else None
    return db.get(AdminAccount,session.admin_id) if session and session.expires_at > datetime.utcnow() else None

def require_admin(admin=Depends(current_admin)):
    if not admin:
        raise HTTPException(401,'Admin sign-in required')
    return admin

def session_cookie(admin, request, response, db):
    token = secrets.token_urlsafe(32)
    db.add(AdminSession(token_hash=token_hash(token),admin_id=admin.id,expires_at=datetime.utcnow()+timedelta(hours=8)))
    db.commit()
    response.set_cookie('sentinel_session',token,httponly=True,samesite='strict',secure=HOSTED or request.url.scheme=='https',max_age=28800)

@router.get('/auth/status')
def auth_status(admin=Depends(current_admin), db: Session=Depends(get_db)):
    return {'setup_required':db.query(AdminAccount).first() is None,'authenticated':bool(admin),'username':admin.username if admin else None}

@router.post('/auth/setup',status_code=201)
def setup(body: Credentials, request: Request,response: Response,db: Session=Depends(get_db)):
    if HOSTED: raise HTTPException(403,'Hosted administrator is configured by the deployment owner')
    with write_lock():
        if db.query(AdminAccount).first():
            raise HTTPException(409,'Admin already configured. Please sign in.')
        admin=AdminAccount(username=body.username,password_hash=hash_password(body.password))
        db.add(admin);db.flush();session_cookie(admin,request,response,db)
        return {'username':admin.username}

class LoginAttempt(Base):
    __tablename__='login_attempts'
    id=Column(Integer,primary_key=True)
    host_hash=Column(String(64),nullable=False,index=True)
    timestamp=Column(DateTime,nullable=False,index=True)

@router.post('/auth/login')
def login(body: Credentials,request:Request,response:Response,db:Session=Depends(get_db)):
    host=request.client.host if request.client else 'unknown'
    now=datetime.utcnow()
    with write_lock():
        cutoff=now-timedelta(minutes=5)
        db.query(LoginAttempt).filter(LoginAttempt.timestamp<=cutoff).delete()
        host_hash=token_hash(host)
        attempts=db.query(LoginAttempt).filter(LoginAttempt.host_hash==host_hash)
        if attempts.count()>=10: raise HTTPException(429,'Too many login attempts. Retry in five minutes.')
        admin=db.query(AdminAccount).filter(AdminAccount.username==body.username).first()
        if not admin or not valid_password(body.password,admin.password_hash):
            db.add(LoginAttempt(host_hash=host_hash,timestamp=now));db.commit()
            raise HTTPException(401,'Invalid username or password')
        attempts.delete()
        session_cookie(admin,request,response,db)
        return {'username':admin.username}

@router.post('/auth/logout')
def logout(request:Request,response:Response,db:Session=Depends(get_db)):
    row=db.get(AdminSession,token_hash(request.cookies.get('sentinel_session','')))
    if row: db.delete(row);db.commit()
    response.delete_cookie('sentinel_session')
    return {'ok':True}

@router.get('/preferences',response_model=Preferences)
def get_preferences(admin=Depends(require_admin)):
    return Preferences(**json.loads(admin.preferences or '{}'))

@router.put('/preferences',response_model=Preferences)
def save_preferences(body:Preferences,admin=Depends(require_admin),db:Session=Depends(get_db)):
    admin.preferences=body.model_dump_json();db.commit()
    return body

def record(db, actor, action, kind, target_id, details, user_id=None, previous=None):
    db.add(AuditEvent(actor=actor,action=action,target_type=kind,target_id=str(target_id),reason=details,previous_state=json.dumps(previous) if previous else None))
    if user_id is not None:
        db.add(UserActivity(user_id=user_id,actor=actor,action=action,details=details))

def finish_change(db):
    try:
        db.flush()
        scan=run_policy_scan(db)  # engine commits the mutation, audit and scan together
        return scan.id
    except Exception:
        db.rollback()
        raise

@router.post('/users',response_model=UserOut,status_code=201)
def create_user(body:UserInput,admin=Depends(require_admin),db:Session=Depends(get_db)):
    with write_lock():
        try:
            user=User(**body.model_dump());db.add(user);db.flush()
            record(db,admin.username,'USER_CREATED','user',user.id,'User added to Sentinel',user.id)
            db.commit();db.refresh(user);return user
        except IntegrityError:
            db.rollback();raise HTTPException(409,'Username or email already exists')

@router.put('/users/{user_id}',response_model=UserOut)
def update_user(user_id:int,body:UserInput,admin=Depends(require_admin),db:Session=Depends(get_db)):
    with write_lock():
        user=db.get(User,user_id)
        if not user or not user.is_active: raise HTTPException(404,'Active user not found')
        try:
            previous={k:getattr(user,k) for k in body.model_dump()}
            for key,value in body.model_dump().items():setattr(user,key,value)
            record(db,admin.username,'USER_UPDATED','user',user.id,'User details updated',user.id,previous)
            finish_change(db)
            return user
        except IntegrityError:
            db.rollback();raise HTTPException(409,'Username or email already exists')

@router.delete('/users/{user_id}')
def delete_user(user_id:int,body:RevokeInput,admin=Depends(require_admin),db:Session=Depends(get_db)):
    with write_lock():
        user=db.get(User,user_id)
        if not user: raise HTTPException(404,'User not found')
        if not user.is_active:return {'changed':False,'message':'User already deleted'}
        user.is_active=False
        for g in db.query(Grant).filter(Grant.user_id==user_id,Grant.status!='REVOKED'):g.status='REVOKED'
        for d in db.query(Delegation).filter((Delegation.delegate_id==user_id)|(Delegation.delegator_id==user_id),Delegation.status!='REVOKED'):d.status='REVOKED'
        for r in db.query(RoleAssignment).filter(RoleAssignment.user_id==user_id):r.is_active=False
        record(db,admin.username,'USER_DELETED','user',user_id,body.reason+'; account deactivated and access revoked; history retained',user_id)
        finish_change(db)
        return {'changed':True,'message':'User removed from People and Sentinel access revoked. Audit history retained.'}

@router.post('/resources',response_model=ResourceOut,status_code=201)
def create_resource(body:ResourceInput,admin=Depends(require_admin),db:Session=Depends(get_db)):
    with write_lock():
        try:
            resource=Resource(**body.model_dump());db.add(resource);db.flush()
            record(db,admin.username,'RESOURCE_CREATED','resource',resource.id,'Resource added to Sentinel')
            db.commit();return resource
        except IntegrityError:
            db.rollback();raise HTTPException(409,'Resource name already exists')

@router.post('/permissions',response_model=GrantOut,status_code=201)
def create_grant(body:GrantInput,admin=Depends(require_admin),db:Session=Depends(get_db)):
    with write_lock():
        user=db.get(User,body.user_id)
        if not user or not user.is_active: raise HTTPException(404,'Active user not found')
        if not db.get(Resource,body.resource_id): raise HTTPException(404,'Resource not found')
        grant=Grant(**body.model_dump(),status='ACTIVE',grant_source='DIRECT');db.add(grant);db.flush()
        record(db,admin.username,'ACCESS_GRANTED','grant',grant.id,f'{grant.permission_level} on resource #{grant.resource_id}: {grant.purpose}',grant.user_id)
        finish_change(db);return grant

@router.post('/access/{source_type}/{source_id}/revoke')
def revoke(source_type:Literal['DIRECT','DELEGATED','ROLE_INHERITED'],source_id:int,body:RevokeInput,admin=Depends(require_admin),db:Session=Depends(get_db)):
    with write_lock():
        model={'DIRECT':Grant,'DELEGATED':Delegation,'ROLE_INHERITED':RoleAssignment}[source_type]
        row=db.get(model,source_id)
        if row is None: raise HTTPException(404,'Access source not found')
        active=row.is_active if source_type=='ROLE_INHERITED' else row.status in {'ACTIVE','PENDING_REVIEW'}
        if not active: return {'changed':False,'message':'Access already inactive'}
        before={'is_active':row.is_active} if source_type=='ROLE_INHERITED' else {'status':row.status}
        if source_type=='ROLE_INHERITED': row.is_active=False
        else: row.status='REVOKED'
        uid=row.delegate_id if source_type=='DELEGATED' else row.user_id
        record(db,admin.username,'ACCESS_REVOKED',source_type,source_id,body.reason,uid,before)
        scan_id=finish_change(db)
        remaining=calculate_effective_access(db,user_id=uid)
        return {'changed':True,'scan_id':scan_id,'remaining_access_paths':len(remaining),'message':'Source revoked in Sentinel. Other access paths may remain.'}

@router.get('/warnings')
def expiry_warnings(days:int=Query(7,ge=1,le=90),db:Session=Depends(get_db)):
    return expiry_sources(db, days)

@router.get('/expiry-status')
def expiry_status(db:Session=Depends(get_db)):
    return {'upcoming': expiry_sources(db, 1), 'expired': expiry_sources(db, 1, expired=True)}

def expiry_sources(db, days, expired=False):
    today=date.today();end=today+timedelta(days=days);result=[]
    users={u.id:u.full_name for u in db.query(User)}
    for model,kind,active in [(Grant,'DIRECT',Grant.status.in_(['ACTIVE','PENDING_REVIEW'])),(Delegation,'DELEGATED',Delegation.status.in_(['ACTIVE','PENDING_REVIEW'])),(RoleAssignment,'ROLE_INHERITED',RoleAssignment.is_active==True)]:
        if expired and model in (Grant, Delegation):
            active=model.status.in_(['ACTIVE','PENDING_REVIEW','EXPIRED'])
        bounds=[model.expiry_date<today] if expired else [model.expiry_date>=today,model.expiry_date<=end]
        for row in db.query(model).filter(active,*bounds):
            uid=row.delegate_id if kind=='DELEGATED' else row.user_id
            label=row.role.name if kind=='ROLE_INHERITED' else row.resource.name
            result.append({'source_type':kind,'source_id':row.id,'user_id':uid,'user_name':users.get(uid),'resource_name':label,'expiry_date':row.expiry_date,'days_remaining':(row.expiry_date-today).days})
    return sorted(result,key=lambda x:(x['days_remaining'],x['user_id'],x['source_id']))

@router.get('/users/{user_id}/profile')
def user_profile(user_id:int,db:Session=Depends(get_db)):
    user=db.get(User,user_id)
    if not user: raise HTTPException(404,'User not found')
    events=db.query(UserActivity).filter(UserActivity.user_id==user_id).order_by(UserActivity.id.desc()).limit(200).all()
    grants=db.query(Grant).filter(Grant.user_id==user_id).order_by(Grant.id.desc()).all()
    delegations=db.query(Delegation).filter((Delegation.delegate_id==user_id)|(Delegation.delegator_id==user_id)).all()
    roles=db.query(RoleAssignment).filter(RoleAssignment.user_id==user_id).all()
    return {'user':UserOut.model_validate(user),'activity':[{'id':e.id,'timestamp':e.timestamp,'actor':e.actor,'action':e.action,'details':e.details} for e in events],
            'grant_history':[GrantOut.model_validate(g) for g in grants],
            'delegations':[{'id':d.id,'resource':d.resource.name,'status':d.status,'granted_date':d.granted_date,'expiry_date':d.expiry_date,'direction':'received' if d.delegate_id==user_id else 'issued'} for d in delegations],
            'roles':[{'id':r.id,'role':r.role.name,'assigned_date':r.assigned_date,'expiry_date':r.expiry_date,'active':r.is_active} for r in roles],
            'effective_access':[vars(a) for a in calculate_effective_access(db,user_id=user_id)]}

@router.get('/admin/dashboard')
def admin_dashboard(admin=Depends(require_admin),db:Session=Depends(get_db)):
    events=db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(50).all()
    return {'users':db.query(User).count(),'resources':db.query(Resource).count(),'revoked_grants':db.query(Grant).filter(Grant.status=='REVOKED').count(),'active_sessions':db.query(AdminSession).filter(AdminSession.expires_at>datetime.utcnow()).count(),
            'activity':[{'id':e.id,'timestamp':e.timestamp,'actor':e.actor,'action':e.action,'target_type':e.target_type,'target_id':e.target_id,'reason':e.reason} for e in events]}


class ExtendInput(RevokeInput):
    expiry_date: date
    expected_expiry_date: Optional[date] = Field(...)

@router.get('/risk-dashboard')
def current_risk_dashboard(db:Session=Depends(get_db)):
    from risk_service import risk_dashboard
    return risk_dashboard(db)

@router.post('/access/{source_type}/{source_id}/extend')
def extend_lease(source_type:Literal['DIRECT','DELEGATED','ROLE_INHERITED'],source_id:int,
                 body:ExtendInput,admin=Depends(require_admin),db:Session=Depends(get_db)):
    with write_lock():
        model={'DIRECT':Grant,'DELEGATED':Delegation,'ROLE_INHERITED':RoleAssignment}[source_type]
        row=db.get(model,source_id)
        if row is None: raise HTTPException(404,'Access source not found')
        active=row.is_active if source_type=='ROLE_INHERITED' else row.status in {'ACTIVE','PENDING_REVIEW'}
        if not active: raise HTTPException(409,'Inactive or revoked access cannot be extended')
        uid=row.delegate_id if source_type=='DELEGATED' else row.user_id
        if not db.get(User,uid).is_active: raise HTTPException(409,'Deleted user cannot receive access')
        if source_type=='DELEGATED' and not db.get(User,row.delegator_id).is_active:
            raise HTTPException(409,'Delegator is inactive')
        if row.expiry_date != body.expected_expiry_date:
            raise HTTPException(409,'Expiry changed since you opened this form. Refresh and review it again.')
        if body.expiry_date <= date.today() or (row.expiry_date and body.expiry_date <= row.expiry_date):
            raise HTTPException(422,'New expiry must be after today and later than the current expiry')
        previous={'expiry_date':str(row.expiry_date) if row.expiry_date else None}
        row.expiry_date=body.expiry_date
        record(db,admin.username,'LEASE_EXTENDED',source_type,source_id,
               f'Expiry set to {body.expiry_date}: {body.reason}',uid,previous)
        scan_id=finish_change(db)
        return {'changed':True,'expiry_date':row.expiry_date,'scan_id':scan_id,
                'message':'Lease updated in Sentinel and policies rescanned. External systems are unchanged.'}


class PasswordRecovery(Base):
    __tablename__='password_recovery'
    token_hash=Column(String(64),primary_key=True)
    admin_id=Column(Integer,ForeignKey('admin_accounts.id'),nullable=False,index=True)
    expires_at=Column(DateTime,nullable=False)

class RecoveryAttempt(Base):
    __tablename__='recovery_attempts'
    code_hash=Column(String(64),primary_key=True)
    failures=Column(Integer,nullable=False,default=0)

class ResetCaptcha(Base):
    __tablename__='reset_captcha'
    token_hash=Column(String(64),primary_key=True)
    answer_hash=Column(String(64),nullable=False)
    question=Column(String(100),nullable=False)

class ResetChallengeInput(BaseModel):
    token:str=Field(pattern=r'^[a-f0-9]{64}$')

@router.post('/auth/reset-challenge')
def reset_challenge(body:ResetChallengeInput,db:Session=Depends(get_db)):
    with write_lock():
        recovery=db.get(PasswordRecovery,token_hash(body.token))
        if not recovery or recovery.expires_at<=datetime.utcnow():
            raise HTTPException(400,'Reset link expired or invalid. Run Reset-Password.cmd again.')
        challenge=db.get(ResetCaptcha,recovery.token_hash)
        if not challenge:
            a,b=secrets.randbelow(8)+2,secrets.randbelow(8)+2
            challenge=ResetCaptcha(token_hash=recovery.token_hash,answer_hash=token_hash(body.token+':'+str(a+b)),question=f'{a} + {b} = ?')
            db.add(challenge);db.commit()
        return {'question':challenge.question,'username':db.get(AdminAccount,recovery.admin_id).username}

class PasswordResetInput(Credentials):
    recovery_code:str=Field(pattern=r'^(?:[0-9]{6}|[a-f0-9]{64})$')
    captcha_answer:str=Field(default='',max_length=10)

def issue_password_recovery(db,username,link=False):
    """Operator-only helper. Never expose code generation through a public API."""
    with write_lock():
        admin=db.query(AdminAccount).filter(AdminAccount.username==username).first()
        if not admin:raise ValueError('Administrator username not found')
        token=secrets.token_hex(32) if link else f'{secrets.randbelow(1000000):06d}'
        while db.get(PasswordRecovery,token_hash(token)):
            token=secrets.token_hex(32) if link else f'{secrets.randbelow(1000000):06d}'
        for old in db.query(PasswordRecovery).filter(PasswordRecovery.admin_id==admin.id):
            db.query(RecoveryAttempt).filter(RecoveryAttempt.code_hash==old.token_hash).delete()
        db.query(PasswordRecovery).filter(PasswordRecovery.admin_id==admin.id).delete()
        db.add(PasswordRecovery(token_hash=token_hash(token),admin_id=admin.id,expires_at=datetime.utcnow()+timedelta(minutes=15)))
        record(db,'LOCAL_OPERATOR','PASSWORD_RECOVERY_ISSUED','admin',admin.id,'One-time recovery code issued; valid for 15 minutes')
        db.commit()
        return token

@router.post('/auth/reset-password')
def reset_password(body:PasswordResetInput,request:Request,response:Response,db:Session=Depends(get_db)):
    with write_lock():
        now=datetime.utcnow()
        host=request.client.host if request.client else 'unknown'
        host_hash=token_hash('password-reset:'+host)
        db.query(LoginAttempt).filter(LoginAttempt.timestamp<=now-timedelta(minutes=5)).delete()
        attempts=db.query(LoginAttempt).filter(LoginAttempt.host_hash==host_hash)
        if attempts.count()>=10:raise HTTPException(429,'Too many recovery attempts. Retry in five minutes.')
        admin=db.query(AdminAccount).filter(AdminAccount.username==body.username).first()
        recovery=db.query(PasswordRecovery).filter(PasswordRecovery.admin_id==admin.id).first() if admin else None
        valid=recovery and recovery.expires_at>now and hmac.compare_digest(recovery.token_hash,token_hash(body.recovery_code))
        if valid and len(body.recovery_code)==64:
            challenge=db.get(ResetCaptcha,recovery.token_hash)
            valid=challenge and hmac.compare_digest(challenge.answer_hash,token_hash(body.recovery_code+':'+body.captcha_answer.strip()))
        if not valid:
            if recovery:
                counter=db.get(RecoveryAttempt,recovery.token_hash)
                if counter is None:
                    counter=RecoveryAttempt(code_hash=recovery.token_hash,failures=0);db.add(counter)
                counter.failures+=1
                if counter.failures>=5:
                    db.delete(recovery)
                    db.flush()
                    db.query(RecoveryAttempt).filter(RecoveryAttempt.code_hash==counter.code_hash).delete()
            db.add(LoginAttempt(host_hash=host_hash,timestamp=now));db.commit()
            raise HTTPException(400,'Invalid or expired reset details, or incorrect CAPTCHA. Run Reset-Password.cmd for a fresh link if needed.')
        db.query(RecoveryAttempt).filter(RecoveryAttempt.code_hash==recovery.token_hash).delete()
        db.query(ResetCaptcha).filter(ResetCaptcha.token_hash==recovery.token_hash).delete()
        admin.password_hash=hash_password(body.password)
        db.query(AdminSession).filter(AdminSession.admin_id==admin.id).delete()
        db.query(PasswordRecovery).filter(PasswordRecovery.admin_id==admin.id).delete()
        attempts.delete()
        # Allow the owner to sign in after repeated forgotten-password attempts on this host.
        db.query(LoginAttempt).filter(LoginAttempt.host_hash==token_hash(host)).delete()
        record(db,admin.username,'PASSWORD_RESET','admin',admin.id,'Password reset using a one-time recovery code; all sessions revoked')
        db.commit();response.delete_cookie('sentinel_session')
        return {'message':'Password reset successfully. Sign in with your new password.'}
