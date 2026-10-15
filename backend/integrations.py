"""Push adapter contract for an approved MUJ SLCM export; no portal scraping."""
from datetime import datetime, timezone, timedelta
from typing import Literal
import hashlib
import hmac
import json
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field, model_validator
from sqlalchemy import Column, Integer, String, Text, DateTime, UniqueConstraint
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from database import get_db
from models import Base, User, Resource, Grant
from features import Input, UserInput, ResourceInput, GrantInput, require_admin, current_admin, write_lock, record, finish_change

router=APIRouter(prefix='/api/integrations/slcm')
class IntegrationConfig(Base):
    __tablename__='integration_config'
    id=Column(Integer,primary_key=True)
    key_hash=Column(String(64))
class ExternalMapping(Base):
    __tablename__='external_mappings'
    id=Column(Integer,primary_key=True)
    kind=Column(String(20),nullable=False)
    external_id=Column(String(100),nullable=False)
    local_id=Column(Integer,nullable=False)
    __table_args__=(UniqueConstraint('kind','external_id'),)
class SyncRun(Base):
    __tablename__='sync_runs'
    id=Column(Integer,primary_key=True)
    snapshot_at=Column(DateTime,nullable=False)
    received_at=Column(DateTime,default=datetime.utcnow)
    digest=Column(String(64),unique=True,nullable=False)
    summary=Column(Text,nullable=False)
class ExternalUser(UserInput):
    external_id:str=Field(min_length=1,max_length=100)
class ExternalResource(ResourceInput):
    external_id:str=Field(min_length=1,max_length=100)
class ExternalGrant(Input):
    external_id:str=Field(min_length=1,max_length=100)
    user_external_id:str=Field(min_length=1,max_length=100)
    resource_external_id:str=Field(min_length=1,max_length=100)
    permission_level:Literal['READ','WRITE','EXECUTE','ADMIN']
    owner:str=Field(min_length=2,max_length=200)
    purpose:str=Field(min_length=3,max_length=2000)
    granted_date: str
    expiry_date: str | None = None
    is_temporary:bool=False
    status:Literal['ACTIVE','REVOKED']='ACTIVE'
class SyncInput(Input):
    snapshot_at:datetime
    users:list[ExternalUser]=Field(default_factory=list,max_length=500)
    resources:list[ExternalResource]=Field(default_factory=list,max_length=500)
    grants:list[ExternalGrant]=Field(default_factory=list,max_length=1000)
    @model_validator(mode='after')
    def validate_batch(self):
        if self.snapshot_at.tzinfo is None: raise ValueError('snapshot_at must include a timezone')
        if self.snapshot_at>datetime.now(timezone.utc)+timedelta(minutes=5): raise ValueError('Snapshot timestamp is in the future')
        for rows in [self.users,self.resources,self.grants]:
            ids=[r.external_id for r in rows]
            if len(ids)!=len(set(ids)): raise ValueError('Duplicate external IDs in batch')
        return self

@router.get('/status')
def status(admin=Depends(require_admin),db:Session=Depends(get_db)):
    config=db.get(IntegrationConfig,1);last=db.query(SyncRun).order_by(SyncRun.id.desc()).first()
    return {'provider':'MUJ SLCM','mode':'approved-export push adapter','api_key_configured':bool(config and config.key_hash),'university_connection':'Not configured: university-approved API/export bridge required','last_sync':{'id':last.id,'snapshot_at':last.snapshot_at,'received_at':last.received_at,'summary':json.loads(last.summary)} if last else None}

@router.post('/key')
def rotate_key(admin=Depends(require_admin),db:Session=Depends(get_db)):
    with write_lock():
        token=secrets.token_urlsafe(40);config=db.get(IntegrationConfig,1)
        if not config: config=IntegrationConfig(id=1);db.add(config)
        config.key_hash=hashlib.sha256(token.encode()).hexdigest()
        record(db,admin.username,'INTEGRATION_KEY_ROTATED','integration','slcm','SLCM ingest key rotated')
        db.commit();return {'token':token,'message':'Shown once. Configure it in your approved export bridge as a Bearer token.'}

def sync_actor(request:Request,admin=Depends(current_admin),db:Session=Depends(get_db)):
    if admin: return admin.username
    header=request.headers.get('Authorization','')
    config=db.get(IntegrationConfig,1)
    if not config or not config.key_hash or not header.startswith('Bearer ') or not hmac.compare_digest(config.key_hash,hashlib.sha256(header[7:].encode()).hexdigest()):
        raise HTTPException(401,'Valid integration key or admin session required')
    return 'SLCM_SYNC'

@router.post('/sync')
def sync(body:SyncInput,actor=Depends(sync_actor),db:Session=Depends(get_db)):
    digest=hashlib.sha256(body.model_dump_json().encode()).hexdigest()
    timestamp=body.snapshot_at.astimezone(timezone.utc).replace(tzinfo=None)
    with write_lock():
        duplicate=db.query(SyncRun).filter(SyncRun.digest==digest).first()
        if duplicate: return {'duplicate':True,**json.loads(duplicate.summary)}
        last=db.query(SyncRun).order_by(SyncRun.snapshot_at.desc()).first()
        if last and timestamp<=last.snapshot_at: raise HTTPException(409,'Stale snapshot. Provide a newer snapshot_at.')
        summary={'users':0,'resources':0,'grants':0,'revocations_preserved':0}
        try:
            def mapping(kind,external_id):
                return db.query(ExternalMapping).filter_by(kind=kind,external_id=external_id).first()
            for kind,items,model in [('user',body.users,User),('resource',body.resources,Resource)]:
                for item in items:
                    ref=mapping(kind,item.external_id);values=item.model_dump(exclude={'external_id'})
                    obj=db.get(model,ref.local_id) if ref else None
                    if ref and obj is None: raise HTTPException(409,'External mapping points to missing data')
                    changed=obj is None or any(getattr(obj,k)!=v for k,v in values.items())
                    if obj is None:
                        obj=model(**values);db.add(obj);db.flush()
                        db.add(ExternalMapping(kind=kind,external_id=item.external_id,local_id=obj.id))
                    else:
                        for k,v in values.items():setattr(obj,k,v)
                    if changed:
                        summary[kind+'s']+=1
                        record(db,actor,'ERP_RECORD_SYNCED',kind,obj.id,'Approved export record imported',obj.id if kind=='user' else None)
                    db.flush()
            for item in body.grants:
                u=mapping('user',item.user_external_id);r=mapping('resource',item.resource_external_id)
                if not u or not r: raise HTTPException(422,'Grant references an unknown external user or resource')
                if not db.get(User,u.local_id).is_active: raise HTTPException(409,'Cannot import access for a deleted user')
                # Historical dates are permitted in imports, since stale access is what scans detect.
                from datetime import date
                try:
                    granted=date.fromisoformat(item.granted_date);expiry=date.fromisoformat(item.expiry_date) if item.expiry_date else None
                except ValueError:raise HTTPException(422,'Invalid grant date: use YYYY-MM-DD')
                if granted>date.today() or (expiry and expiry<granted):raise HTTPException(422,'Invalid grant date range')
                values=item.model_dump(exclude={'external_id','user_external_id','resource_external_id'})
                values.update(user_id=u.local_id,resource_id=r.local_id,granted_date=granted,expiry_date=expiry)
                ref=mapping('grant',item.external_id);obj=db.get(Grant,ref.local_id) if ref else None
                if ref and not obj:raise HTTPException(409,'Grant mapping points to missing data')
                if obj and (obj.user_id!=u.local_id or obj.resource_id!=r.local_id):raise HTTPException(409,'External grant identity cannot change user/resource')
                if obj and obj.status=='REVOKED' and item.status=='ACTIVE':
                    summary['revocations_preserved']+=1
                    continue
                changed=obj is None or any(getattr(obj,k)!=v for k,v in values.items())
                if not obj:
                    obj=Grant(**values,grant_source='DIRECT');db.add(obj);db.flush();db.add(ExternalMapping(kind='grant',external_id=item.external_id,local_id=obj.id))
                else:
                    for k,v in values.items():setattr(obj,k,v)
                if changed:
                    summary['grants']+=1
                    record(db,actor,'ERP_ACCESS_SYNCED','grant',obj.id,f'ERP access record synced: {obj.permission_level}, {obj.status}',obj.user_id)
                db.flush()
            db.add(SyncRun(snapshot_at=timestamp,digest=digest,summary=json.dumps(summary)))
            record(db,actor,'ERP_SYNC','integration','slcm',json.dumps(summary))
            finish_change(db)
            return {'duplicate':False,**summary}
        except IntegrityError:
            db.rollback();raise HTTPException(409,'Conflicting username, email or resource name. Existing local records are not automatically linked.')
        except Exception:
            db.rollback();raise
