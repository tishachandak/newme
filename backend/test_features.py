"""Feature integration tests; imports test_integration to select its isolated DB."""
import unittest
import copy
from datetime import date, datetime, timedelta, timezone
import test_integration as baseline
from fastapi.testclient import TestClient
from main import app
from database import engine, SessionLocal
from models import Base, Grant, User, Resource, RoleAssignment, Delegation
from features import AdminSession, UserActivity

class Features(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine)
        self.client=TestClient(app);self.client.__enter__()
        self.credentials={'username':'feature-admin','password':'secure-test-password'}
        self.assertEqual(self.client.post('/api/auth/setup',json=self.credentials).status_code,201)
    def tearDown(self):
        self.client.__exit__(None,None,None)
    def grant(self,**changes):
        body={'user_id':1,'resource_id':1,'permission_level':'READ','owner':'Test Admin','purpose':'Time limited research','expiry_date':(date.today()+timedelta(days=3)).isoformat(),'is_temporary':True}
        body.update(changes)
        return self.client.post('/api/permissions',json=body)
    def test_expiry_tables_boundaries_revocation_and_demo_idempotence(self):
        from seed_data import seed_expiry_examples
        with SessionLocal() as db:
            before=db.query(Grant).count()
            self.assertFalse(seed_expiry_examples(db))
            self.assertEqual(before,db.query(Grant).count())
            ids={}
            for offset in [-1,0,1,2]:
                g=Grant(user_id=1,resource_id=1,permission_level='READ',owner='Test',purpose='Boundary',
                    granted_date=date.today()-timedelta(days=7),expiry_date=date.today()+timedelta(days=offset),status='ACTIVE')
                db.add(g);db.flush();ids[offset]=g.id
            db.commit()
        result=self.client.get('/api/expiry-status')
        self.assertEqual(result.status_code,200)
        data=result.json()
        upcoming={r['source_id'] for r in data['upcoming'] if r['source_type']=='DIRECT'}
        expired={r['source_id'] for r in data['expired'] if r['source_type']=='DIRECT'}
        self.assertTrue({ids[0],ids[1]}<=upcoming)
        self.assertNotIn(ids[2],upcoming)
        self.assertIn(ids[-1],expired)
        self.assertTrue(all(0<=r['days_remaining']<=1 for r in data['upcoming']))
        self.assertTrue(all(r['days_remaining']<0 for r in data['expired']))
        self.client.post('/api/access/DIRECT/'+str(ids[-1])+'/revoke',json={'reason':'Expiry test revocation'})
        self.assertFalse(any(r['source_type']=='DIRECT' and r['source_id']==ids[-1] for r in self.client.get('/api/expiry-status').json()['expired']))

    def test_user_edit_delete_and_authorization(self):
        body={'username':'crud.person','full_name':'CRUD Person','email':'crud@example.edu','department':'Library','user_type':'student'}
        uid=self.client.post('/api/users',json=body).json()['id']
        g=self.grant(user_id=uid);self.assertEqual(g.status_code,201)
        with TestClient(app) as guest:
            self.assertEqual(guest.put(f'/api/users/{uid}',json=body).status_code,401)
            self.assertEqual(guest.request('DELETE',f'/api/users/{uid}',json={'reason':'Remove test'}).status_code,401)
        edited=self.client.put(f'/api/users/{uid}',json={**body,'full_name':'Updated Person','user_type':'guest'})
        self.assertEqual(edited.status_code,200)
        self.assertEqual(edited.json()['full_name'],'Updated Person')
        self.assertEqual(self.client.put(f'/api/users/{uid}',json={**body,'email':'bad'}).status_code,422)
        with SessionLocal() as db:
            other=db.get(User,1)
            duplicate=other.username
        self.assertEqual(self.client.put(f'/api/users/{uid}',json={**body,'username':duplicate}).status_code,409)
        r=self.client.request('DELETE',f'/api/users/{uid}',json={'reason':'Testing removal'})
        self.assertEqual(r.status_code,200)
        self.assertNotIn(uid,[u['id'] for u in self.client.get('/api/users').json()])
        self.assertEqual(self.client.get(f'/api/permissions/effective?user_id={uid}').json(),[])
        profile=self.client.get(f'/api/users/{uid}/profile').json()
        self.assertIn('USER_DELETED',{a['action'] for a in profile['activity']})
        self.assertEqual(profile['grant_history'][0]['status'],'REVOKED')
        self.assertEqual(self.grant(user_id=uid).status_code,404)
        self.assertFalse(self.client.request('DELETE',f'/api/users/{uid}',json={'reason':'Repeat removal'}).json()['changed'])

    def test_authorization_cookie_logout_and_csrf(self):
        with TestClient(app) as guest:
            self.assertEqual(guest.post('/api/scan').status_code,401)
            self.assertEqual(guest.post('/api/access/DIRECT/1/revoke',json={'reason':'Test revoke'}).status_code,401)
            self.assertEqual(guest.get('/api/admin/dashboard').status_code,401)
            self.assertEqual(guest.post('/api/auth/setup',json=self.credentials).status_code,409)
        self.assertEqual(self.client.post('/api/scan',headers={'Origin':'https://attacker.invalid'}).status_code,403)
        token=self.client.cookies.get('sentinel_session')
        self.client.post('/api/auth/logout')
        self.client.cookies.set('sentinel_session',token)
        self.assertEqual(self.client.get('/api/admin/dashboard').status_code,401)
        self.assertEqual(self.client.post('/api/auth/login',json={**self.credentials,'password':'wrong-password'}).status_code,401)
        response=self.client.post('/api/auth/login',json=self.credentials)
        self.assertEqual(response.status_code,200)
        self.assertIn('HttpOnly',response.headers['set-cookie'])
        self.assertIn('SameSite=strict',response.headers['set-cookie'])
    def test_data_validation_conflicts_and_profile(self):
        body={'username':'new.person','full_name':'New Person','email':'new@example.edu','department':'Library','user_type':'student'}
        r=self.client.post('/api/users',json=body);self.assertEqual(r.status_code,201,r.text)
        uid=r.json()['id']
        self.assertEqual(self.client.post('/api/users',json=body).status_code,409)
        self.assertEqual(self.client.post('/api/users',json={**body,'email':'bad'}).status_code,422)
        self.assertEqual(self.grant(user_id=99999).status_code,404)
        self.assertEqual(self.grant(expiry_date=None).status_code,422)
        self.assertEqual(self.grant(expiry_date=(date.today()-timedelta(days=1)).isoformat()).status_code,422)
        g=self.grant(user_id=uid);self.assertEqual(g.status_code,201,g.text)
        profile=self.client.get(f'/api/users/{uid}/profile').json()
        self.assertEqual({x['action'] for x in profile['activity']},{'USER_CREATED','ACCESS_GRANTED'})
        self.assertEqual(len(profile['grant_history']),1)
    def test_revoke_all_sources_retains_other_paths_and_is_idempotent(self):
        for kind,model in [('DIRECT',Grant),('DELEGATED',Delegation),('ROLE_INHERITED',RoleAssignment)]:
            with SessionLocal() as db:
                row=db.query(model).first();source_id=row.id
                uid=row.delegate_id if kind=='DELEGATED' else row.user_id
            result=self.client.post(f'/api/access/{kind}/{source_id}/revoke',json={'reason':'Project access ended'})
            self.assertEqual(result.status_code,200,result.text);self.assertTrue(result.json()['changed'])
            paths=self.client.get(f'/api/permissions/effective?user_id={uid}').json()
            self.assertFalse(any(p['source_type']==kind and p['source_id']==source_id for p in paths))
            self.assertEqual(len(paths),result.json()['remaining_access_paths'])
            again=self.client.post(f'/api/access/{kind}/{source_id}/revoke',json={'reason':'Project access ended'})
            self.assertFalse(again.json()['changed'])
            profile=self.client.get(f'/api/users/{uid}/profile').json()
            self.assertTrue(any(a['action']=='ACCESS_REVOKED' for a in profile['activity']))
    def test_preferences_roundtrip_and_session_expiry(self):
        prefs={'theme':'dark','high_contrast':True,'large_text':True,'reduced_motion':True,'warning_days':14}
        self.assertEqual(self.client.put('/api/preferences',json=prefs).json(),prefs)
        self.assertEqual(self.client.get('/api/preferences').json(),prefs)
        self.assertEqual(self.client.put('/api/preferences',json={**prefs,'warning_days':0}).status_code,422)
        with SessionLocal() as db:
            for s in db.query(AdminSession):s.expires_at=datetime.utcnow()-timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.client.get('/api/preferences').status_code,401)
    def test_warning_boundaries_and_revoked_exclusion(self):
        ids={}
        for days in [0,7,8]:
            r=self.grant(expiry_date=(date.today()+timedelta(days=days)).isoformat());self.assertEqual(r.status_code,201,r.text);ids[days]=r.json()['id']
        before=self.client.get('/api/warnings?days=7').json()
        selected={x['source_id'] for x in before if x['source_type']=='DIRECT'}
        self.assertIn(ids[0],selected);self.assertIn(ids[7],selected);self.assertNotIn(ids[8],selected)
        self.client.post('/api/scan',json={'simulated_date':(date.today()+timedelta(days=365)).isoformat()})
        self.assertEqual(before,self.client.get('/api/warnings?days=7').json())
        self.client.post(f"/api/access/DIRECT/{ids[0]}/revoke",json={'reason':'Revoke expiring access'})
        self.assertFalse(any(w['source_type']=='DIRECT' and w['source_id']==ids[0] for w in self.client.get('/api/warnings?days=7').json()))
    def payload(self):
        return {'snapshot_at':datetime.now(timezone.utc).isoformat(),'users':[{'external_id':'student-1','username':'erp.student','full_name':'ERP Student','email':'erp@example.edu','department':'Engineering','user_type':'student'}],
        'resources':[{'external_id':'app-1','name':'ERP Research Workspace','department':'Engineering','resource_type':'application','sensitivity':'STANDARD'}],
        'grants':[{'external_id':'grant-1','user_external_id':'student-1','resource_external_id':'app-1','permission_level':'READ','owner':'ERP Admin','purpose':'Approved research','granted_date':date.today().isoformat(),'expiry_date':(date.today()+timedelta(days=7)).isoformat(),'is_temporary':True}]}
    def test_erp_idempotency_revocation_and_stale_snapshot(self):
        p=self.payload();r=self.client.post('/api/integrations/slcm/sync',json=p);self.assertEqual(r.status_code,200,r.text)
        self.assertEqual(r.json()['grants'],1)
        self.assertTrue(self.client.post('/api/integrations/slcm/sync',json=p).json()['duplicate'])
        with SessionLocal() as db:g=db.query(Grant).order_by(Grant.id.desc()).first();gid=g.id
        self.client.post(f'/api/access/DIRECT/{gid}/revoke',json={'reason':'Admin override revoked'})
        p['snapshot_at']=(datetime.now(timezone.utc)+timedelta(seconds=1)).isoformat()
        r=self.client.post('/api/integrations/slcm/sync',json=p);self.assertEqual(r.json()['revocations_preserved'],1)
        with SessionLocal() as db:self.assertEqual(db.get(Grant,gid).status,'REVOKED')
        p['snapshot_at']=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
        self.assertEqual(self.client.post('/api/integrations/slcm/sync',json=p).status_code,409)
    def test_erp_rollback_and_integration_key_scope(self):
        p=self.payload();p['grants'][0]['resource_external_id']='missing'
        r=self.client.post('/api/integrations/slcm/sync',json=p);self.assertEqual(r.status_code,422,r.text)
        with SessionLocal() as db:self.assertIsNone(db.query(User).filter_by(username='erp.student').first())
        key=self.client.post('/api/integrations/slcm/key').json()['token']
        with TestClient(app) as bridge:
            headers={'Authorization':'Bearer '+key}
            self.assertEqual(bridge.post('/api/integrations/slcm/sync',json=self.payload(),headers=headers).status_code,200)
            self.assertEqual(bridge.post('/api/scan',headers=headers).status_code,401)
            self.client.post('/api/integrations/slcm/key')
            self.assertEqual(bridge.post('/api/integrations/slcm/sync',json=self.payload(),headers=headers).status_code,401)

if __name__=='__main__':unittest.main()
