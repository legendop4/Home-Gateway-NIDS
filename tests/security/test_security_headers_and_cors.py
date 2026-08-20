"""
Security Tests: Security Headers and CORS Boundary Enforcement.
Verifies:
1. All responses include X-Content-Type-Options: nosniff.
2. X-Frame-Options: SAMEORIGIN is present.
3. Content-Security-Policy header is configured.
4. Cache-Control: no-store is applied on API responses.
5. CORS headers are strictly applied to allowed origins and rejected for disallowed origins.
"""

import pytest
from nids.storage.database import NidsDatabase
from nids.dashboard.app import create_dashboard_app


@pytest.fixture
def client(tmp_path):
    db_file = str(tmp_path / "test_headers.db")
    db = NidsDatabase(db_path=db_file)
    cfg = {
        "security": {
            "allowed_origins": ["https://trusted-dashboard.local"]
        }
    }
    app = create_dashboard_app(db=db, config=cfg)
    app.config["TESTING"] = True
    return app.test_client()


def test_security_headers_present(client):
    res = client.get("/api/stats")
    headers = res.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "Content-Security-Policy" in headers
    assert "no-store" in headers.get("Cache-Control", "")


def test_cors_allowed_origin(client):
    res = client.get("/api/stats", headers={"Origin": "https://trusted-dashboard.local"})
    assert res.headers.get("Access-Control-Allow-Origin") == "https://trusted-dashboard.local"


def test_cors_disallowed_origin(client):
    res = client.get("/api/stats", headers={"Origin": "https://malicious-attacker.com"})
    # Must NOT echo malicious origin
    assert res.headers.get("Access-Control-Allow-Origin") != "https://malicious-attacker.com"
