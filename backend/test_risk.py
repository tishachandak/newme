"""Risk model and remediation invariants; isolated database via baseline harness."""
import unittest
from datetime import date, timedelta
import test_integration as baseline
from fastapi.testclient import TestClient
from main import app
from database import engine, SessionLocal
from models import Base, Grant, Delegation, RoleAssignment
from risk_engine import calculate_grant_risk, risk_tier


class RiskFormula(unittest.TestCase):
    def test_tiers_and_input_validation(self):
        for score,tier in [(0,'LOW'),(39,'LOW'),(40,'MEDIUM'),(69,'MEDIUM'),(70,'HIGH_CRITICAL'),(100,'HIGH_CRITICAL')]:
            self.assertEqual(risk_tier(score),tier)
        for score in [-1,101]:
            with self.assertRaises(ValueError):risk_tier(score)
        with self.assertRaises(ValueError):calculate_grant_risk(permission_level='ROOT',sensitivity='LOW')

    def test_dates_monotonicity_and_metadata(self):
        today=date(2026,10,15)
        args=dict(permission_level='READ',sensitivity='LOW',owner='Owner',purpose='Research',as_of=today)
        future=calculate_grant_risk(**args,expiry_date=today+timedelta(days=1))
        self.assertEqual(future['score'],5);self.assertTrue(future['clean'])
        self.assertEqual(calculate_grant_risk(**args,expiry_date=today)['factors']['temporal'],0)
        scores=[calculate_grant_risk(**args,expiry_date=today-timedelta(days=d))['score'] for d in range(60)]
        self.assertEqual(scores,sorted(scores))
        self.assertEqual(scores[1],17)
        worst=calculate_grant_risk(permission_level='ADMIN',sensitivity='CRITICAL',owner=' ',purpose='n/a',expiry_date=today-timedelta(days=90),as_of=today)
        self.assertEqual(worst['score'],100)
        self.assertEqual(worst['factors'],{'temporal':35,'privilege':45,'metadata':20})
        undated=calculate_grant_risk(permission_level='ADMIN',sensitivity='CRITICAL',is_temporary=True,as_of=today)
        self.assertEqual(undated['factors']['metadata'],35)
        self.assertEqual(undated['score'],80)


class RiskAPI(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine)
        self.client=TestClient(app);self.client.__enter__()
        self.client.post('/api/auth/setup',json={'username':'risk-admin','password':'risk-test-password'})
    def tearDown(self):self.client.__exit__(None,None,None)
    def test_queue_person_max_source_counts_and_current_date(self):
        data=self.client.get('/api/risk-dashboard').json()
        rows=data['queue']
        self.assertTrue(rows)
        self.assertEqual([r['score'] for r in rows],sorted([r['score'] for r in rows],reverse=True))
        self.assertEqual(data['as_of'],date.today().isoformat())
        self.assertEqual(set(r['source_type'] for r in rows),{'DIRECT','DELEGATED','ROLE_INHERITED'})
        for p in data['people']:
            grants=[r for r in rows if r['user_id']==p['user_id']]
            self.assertEqual(p['score'],max((r['score'] for r in grants),default=0))
        sources={(r['source_type'],r['source_id']) for r in rows}
        bad={(r['source_type'],r['source_id']) for r in rows if not r['clean']}
        self.assertEqual(data['summary']['clean_leases'],len(sources-bad))
        self.assertEqual({(r['source_type'],r['source_id']) for r in rows if r['clean_source']},sources-bad)
        self.client.post('/api/scan',json={'simulated_date':(date.today()+timedelta(days=500)).isoformat()})
        self.assertEqual(data,self.client.get('/api/risk-dashboard').json())

    def test_extend_each_source_audit_and_stale_write(self):
        for kind,model in [('DIRECT',Grant),('DELEGATED',Delegation),('ROLE_INHERITED',RoleAssignment)]:
            with SessionLocal() as db:
                row=db.query(model).filter(model.is_active==True).first() if kind=='ROLE_INHERITED' else db.query(model).filter(model.status=='ACTIVE').first()
                row.expiry_date=date.today()-timedelta(days=3);db.commit();source_id=row.id
                uid=row.delegate_id if kind=='DELEGATED' else row.user_id
            path=f'/api/access/{kind}/{source_id}/extend'
            body={'expected_expiry_date':(date.today()-timedelta(days=3)).isoformat(),'expiry_date':(date.today()+timedelta(days=20)).isoformat(),'reason':'Approved project extension'}
            with TestClient(app) as guest:self.assertEqual(guest.post(path,json=body).status_code,401)
            self.assertEqual(self.client.post(path,json={**body,'expiry_date':date.today().isoformat()}).status_code,422)
            response=self.client.post(path,json=body)
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(self.client.post(path,json=body).status_code,409)
            rows=[r for r in self.client.get('/api/risk-dashboard').json()['queue'] if r['source_type']==kind and r['source_id']==source_id]
            self.assertTrue(rows);self.assertTrue(all(r['days_overdue']==0 and r['factors']['temporal']==0 for r in rows))
            profile=self.client.get(f'/api/users/{uid}/profile').json()
            self.assertIn('LEASE_EXTENDED',{a['action'] for a in profile['activity']})
            self.client.post(f'/api/access/{kind}/{source_id}/revoke',json={'reason':'Project complete'})
            self.assertEqual(self.client.post(path,json={**body,'expected_expiry_date':body['expiry_date'],'expiry_date':(date.today()+timedelta(days=30)).isoformat()}).status_code,409)
            self.assertFalse(any(r['source_type']==kind and r['source_id']==source_id for r in self.client.get('/api/risk-dashboard').json()['queue']))
