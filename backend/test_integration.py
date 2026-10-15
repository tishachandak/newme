"""Run: python -m unittest -v test_integration (uses a temporary database)."""
import os
import atexit
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

temp = tempfile.TemporaryDirectory(prefix="accesslease-test-")
os.environ["DATABASE_URL"] = "sqlite:///" + (Path(temp.name) / "test.db").as_posix()
os.environ["SEED_DEMO_DATA"] = "true"

from fastapi.testclient import TestClient
from main import app
from database import SessionLocal, engine
from models import Base, Finding, Grant, ScanRun, User


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine)
        self.client = TestClient(app)
        self.client.__enter__()
        response = self.client.post('/api/auth/setup', json={'username':'test-admin','password':'test-password-123'})
        self.assertEqual(response.status_code, 201, response.text)

    def tearDown(self):
        self.client.__exit__(None, None, None)

    def test_startup_and_idempotent_seed_restart(self):
        metrics = self.client.get("/api/dashboard").json()
        self.assertEqual(metrics["total_users"], 15)
        self.assertGreater(metrics["last_scan"]["total_findings"], 0)
        with SessionLocal() as db:
            counts = (db.query(User).count(), db.query(Grant).count(), db.query(ScanRun).count())
        self.assertFalse(self.client.post("/api/seed").json()["seeded"])
        with TestClient(app) as restarted:
            restarted.cookies.update(self.client.cookies)
            self.assertEqual(restarted.get("/api/dashboard").json(), metrics)
        with SessionLocal() as db:
            self.assertEqual(counts, (db.query(User).count(), db.query(Grant).count(), db.query(ScanRun).count()))

    def test_scan_history_filters_and_dashboard(self):
        first = self.client.get("/api/dashboard").json()
        response = self.client.post("/api/scan")
        self.assertEqual(response.status_code, 200, response.text)
        second = response.json()
        rows = self.client.get("/api/findings").json()
        self.assertEqual(len(rows), second["total_findings"])
        self.assertTrue(all(f["scan_run_id"] == second["id"] for f in rows))
        metrics = self.client.get("/api/dashboard/metrics").json()
        self.assertEqual(metrics["confirmed_violations"], first["confirmed_violations"])
        self.assertEqual(metrics["confirmed_violations"], sum(f["classification"] == "CONFIRMED_VIOLATION" for f in rows))
        old = self.client.get("/api/findings", params={"scan_id": first["last_scan"]["id"]}).json()
        self.assertEqual(len(old), first["last_scan"]["total_findings"])
        critical = self.client.get("/api/findings?severity=CRITICAL").json()
        self.assertTrue(critical)
        self.assertTrue(all(f["severity"] == "CRITICAL" for f in critical))
        for identifier in [rows[0]["id"], rows[0]["finding_uid"]]:
            self.assertEqual(self.client.get(f"/api/findings/{identifier}").json(), rows[0])
        self.assertEqual(self.client.get("/api/findings?limit=1&offset=1").json(), rows[1:2])

    def test_effective_access_and_permissions(self):
        rows = self.client.get("/api/permissions/effective").json()
        self.assertEqual({r["source_type"] for r in rows}, {"DIRECT", "ROLE_INHERITED", "DELEGATED"})
        self.assertTrue(all(r["access_path"] and r["user_name"] and r["resource_name"] for r in rows))
        metrics = self.client.get("/api/dashboard").json()
        self.assertEqual(metrics["total_active_permissions"], len(rows))
        restricted = self.client.get("/api/permissions/effective?user_id=3&resource_id=3").json()
        self.assertTrue(restricted)
        self.assertTrue(all(r["user_id"] == 3 and r["resource_id"] == 3 for r in restricted))
        revoked = self.client.get("/api/permissions?status=REVOKED").json()
        self.assertTrue(revoked)
        for grant in revoked:
            self.assertNotIn(("DIRECT", grant["id"]), {(r["source_type"], r["source_id"]) for r in rows})

    def test_time_travel_is_non_destructive(self):
        with SessionLocal() as db:
            before = [(g.id, g.status, g.expiry_date) for g in db.query(Grant).order_by(Grant.id)]
        future = (date.today() + timedelta(days=365)).isoformat()
        response = self.client.post("/api/scan", json={"simulated_date": future})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["simulated_date"], future)
        with SessionLocal() as db:
            self.assertEqual(before, [(g.id, g.status, g.expiry_date) for g in db.query(Grant).order_by(Grant.id)])
            self.assertEqual(db.query(Finding).filter(Finding.scan_run_id == response.json()["id"]).count(), response.json()["total_findings"])

    def test_validation_and_reference_routes(self):
        for route in ["/api/findings/missing", "/api/findings?scan_id=999999", "/api/permissions/effective?user_id=999999"]:
            self.assertEqual(self.client.get(route).status_code, 404)
        for route in ["/api/findings?severity=INVALID", "/api/findings?limit=0", "/api/permissions?status=INVALID"]:
            self.assertEqual(self.client.get(route).status_code, 422)
        self.assertEqual(self.client.post("/api/scan", json={"simulated_date": "bad-date"}).status_code, 422)
        for route in ["/", "/api/health", "/docs", "/openapi.json", "/api/users", "/api/resources", "/api/policies", "/api/delegations", "/api/role-assignments", "/api/scans"]:
            self.assertEqual(self.client.get(route).status_code, 200, route)

    def test_empty_database_without_demo_seed(self):
        Base.metadata.drop_all(engine)
        os.environ["SEED_DEMO_DATA"] = "false"
        try:
            with TestClient(app) as empty:
                empty.post('/api/auth/setup', json={'username':'test-admin','password':'test-password-123'})
                metrics = empty.get("/api/dashboard").json()
                self.assertEqual(metrics["total_users"], 0)
                self.assertIsNone(metrics["last_scan"])
                self.assertEqual(empty.get("/api/findings").json(), [])
                empty.post('/api/auth/setup', json={'username':'test-admin','password':'test-password-123'})
                self.assertTrue(empty.post("/api/seed").json()["seeded"])
                self.assertEqual(empty.get("/api/dashboard").json()["total_users"], 15)
        finally:
            os.environ["SEED_DEMO_DATA"] = "true"


def cleanup_test_database():
    engine.dispose()
    temp.cleanup()


atexit.register(cleanup_test_database)

if __name__ == "__main__":
    unittest.main()
