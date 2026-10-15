import unittest
import importlib.util
from pathlib import Path
from datetime import datetime,timedelta
import test_integration as baseline
from fastapi.testclient import TestClient
from main import app
from database import engine,SessionLocal
from models import Grant,User,AuditEvent
from features import AdminAccount,PasswordRecovery,issue_password_recovery,token_hash,valid_password

class Recovery(unittest.TestCase):
    def setUp(self):
        assert Path(engine.url.database).resolve().is_relative_to(Path(baseline.temp.name).resolve())
        baseline.IntegrationTests.setUp(self)
    def tearDown(self):baseline.IntegrationTests.tearDown(self)
    def code(self):
        with SessionLocal() as db:return issue_password_recovery(db,'test-admin')
    def payload(self,code):return {'username':'test-admin','password':'new-secure-password','recovery_code':code}
    def test_single_use_sessions_revoked_and_data_preserved(self):
        with SessionLocal() as db:counts=(db.query(User).count(),db.query(Grant).count())
        code=self.code()
        self.assertRegex(code,r'^[0-9]{6}$')
        with SessionLocal() as db:
            stored=db.query(PasswordRecovery).one()
            self.assertEqual(stored.token_hash,token_hash(code));self.assertNotEqual(stored.token_hash,code)
            self.assertTrue(valid_password('test-password-123',db.query(AdminAccount).first().password_hash))
        with TestClient(app) as anonymous:
            result=anonymous.post('/api/auth/reset-password',json=self.payload(code))
            self.assertEqual(result.status_code,200,result.text)
            self.assertEqual(anonymous.get('/api/dashboard').status_code,401)
            self.assertEqual(anonymous.post('/api/auth/reset-password',json=self.payload(code)).status_code,400)
            self.assertEqual(anonymous.post('/api/auth/login',json={'username':'test-admin','password':'test-password-123'}).status_code,401)
            self.assertEqual(anonymous.post('/api/auth/login',json={'username':'test-admin','password':'new-secure-password'}).status_code,200)
        self.assertEqual(self.client.get('/api/dashboard').status_code,401)
        with SessionLocal() as db:
            self.assertEqual(counts,(db.query(User).count(),db.query(Grant).count()))
            self.assertEqual(db.query(PasswordRecovery).count(),0)
            self.assertEqual(db.query(AuditEvent).filter(AuditEvent.action=='PASSWORD_RESET').count(),1)
    def test_expiry_rotation_wrong_username_validation_csrf(self):
        old=self.code();code=self.code()
        self.assertEqual(self.client.post('/api/auth/reset-password',json=self.payload(old)).status_code,400)
        self.assertEqual(self.client.post('/api/auth/reset-password',json={**self.payload(code),'username':'not-the-admin'}).status_code,400)
        self.assertEqual(self.client.post('/api/auth/reset-password',json={**self.payload(code),'password':'short'}).status_code,422)
        self.assertEqual(self.client.post('/api/auth/reset-password',headers={'Origin':'https://evil.example'},json=self.payload(code)).status_code,403)
        with SessionLocal() as db:
            db.query(PasswordRecovery).first().expires_at=datetime.utcnow()-timedelta(seconds=1);db.commit()
        self.assertEqual(self.client.post('/api/auth/reset-password',json=self.payload(code)).status_code,400)
    def test_operator_helper_and_rate_limit(self):
        path=Path(__file__).resolve().parent.parent/'recover_admin.py'
        spec=importlib.util.spec_from_file_location('recovery_helper',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        code=module.issue_local_code(engine.url.database,'test-admin')
        with SessionLocal() as db:self.assertIsNotNone(db.get(PasswordRecovery,token_hash(code)))
        for _ in range(10):self.assertEqual(self.client.post('/api/auth/reset-password',json=self.payload('000000' if code!='000000' else '111111')).status_code,400)
        self.assertEqual(self.client.post('/api/auth/reset-password',json=self.payload(code)).status_code,429)

    def test_five_attempts_invalidate_code_across_hosts(self):
        code=self.code()
        wrong='000000' if code!='000000' else '111111'
        for i in range(5):
            with TestClient(app,client=(f'192.0.2.{i+1}',1234)) as guest:
                self.assertEqual(guest.post('/api/auth/reset-password',json=self.payload(wrong)).status_code,400)
        with SessionLocal() as db:self.assertIsNone(db.get(PasswordRecovery,token_hash(code)))
        self.assertEqual(self.client.post('/api/auth/reset-password',json=self.payload(code)).status_code,400)
        fresh=self.code()
        self.assertEqual(self.client.post('/api/auth/reset-password',json=self.payload(fresh)).status_code,200)
