"""Anonymous access is denied server-side, including direct endpoint requests."""
import unittest
from datetime import datetime,timedelta
import test_integration as baseline
from fastapi.testclient import TestClient
from main import app
from database import engine,SessionLocal
from models import Base
from features import AdminSession

class Privacy(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine)
        self.client=TestClient(app);self.client.__enter__()
    def tearDown(self):self.client.__exit__(None,None,None)
    def test_all_sensitive_get_routes_require_auth(self):
        public={'/api/health','/api/auth/status'}
        for route in app.routes:
            path=getattr(route,'path','')
            if path.startswith('/api/') and 'GET' in getattr(route,'methods',set()) and path not in public:
                import re
                url=re.sub(r'{[^}]+}','1',path)
                response=self.client.get(url)
                self.assertEqual(response.status_code,401,url)
                self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertEqual(self.client.get('/workspace').status_code,401)
        root=self.client.get('/')
        self.assertEqual(root.status_code,200)
        self.assertIn('login-screen',root.text)
        self.assertNotIn('src="/workspace',root.text)
    def test_session_expiry_logout_and_cache(self):
        self.client.post('/api/auth/setup',json={'username':'privacy-admin','password':'privacy-test-password'})
        self.assertEqual(self.client.get('/workspace').status_code,200)
        self.assertEqual(self.client.get('/api/dashboard').status_code,200)
        self.assertEqual(self.client.get('/api/risk-dashboard').headers['cache-control'],'no-store')
        with SessionLocal() as db:
            for row in db.query(AdminSession):row.expires_at=datetime.utcnow()-timedelta(seconds=1)
            db.commit()
        self.assertEqual(self.client.get('/api/dashboard').status_code,401)
        self.client.post('/api/auth/login',json={'username':'privacy-admin','password':'privacy-test-password'})
        self.assertEqual(self.client.get('/api/dashboard').status_code,200)
        self.client.post('/api/auth/logout')
        self.assertEqual(self.client.get('/api/users').status_code,401)
