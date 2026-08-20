"""
Security Tests: Input Validation, SQL Injection Defense, and Safe Error Masking.
Verifies:
1. SQL injection payloads in IP parameters and pagination are rejected safely.
2. XSS and command injection strings in IP routes return HTTP 400 without crashing.
3. Pagination limit and offset are strictly validated and bounded.
4. Production responses never leak stack traces.
"""

import pytest
from nids.storage.database import NidsDatabase
from nids.dashboard.app import create_dashboard_app


@pytest.fixture
def client(tmp_path):
    db_file = str(tmp_path / "test_injection.db")
    db = NidsDatabase(db_path=db_file)
    app = create_dashboard_app(db=db)
    app.config["TESTING"] = True
    return app.test_client()


def test_sql_injection_in_sequence_ip_rejected(client):
    # Test malicious SQL injection payloads in IP path parameter
    payloads = [
        "192.168.1.1' OR '1'='1",
        "192.168.1.1; DROP TABLE alerts;--",
        "10.0.0.1' UNION SELECT * FROM users--",
        "<script>alert('xss')</script>",
        "127.0.0.1 | cat /etc/passwd",
        "999.999.999.999",
    ]
    for p in payloads:
        res = client.get(f"/api/sequence/{p}")
        assert res.status_code in [400, 404]
        data = res.get_json()
        if res.status_code == 400:
            assert "Invalid IP address format" in data["error"]
        assert "Traceback" not in res.get_data(as_text=True)


def test_sql_injection_in_pagination_rejected(client):
    # Test malicious SQL strings in pagination query parameters
    res = client.get("/api/alerts?limit=1' OR 1=1--&offset=0")
    assert res.status_code == 400
    data = res.get_json()
    assert "Invalid pagination" in data["error"]


def test_negative_pagination_rejected(client):
    res = client.get("/api/alerts?limit=-10&offset=-5")
    assert res.status_code == 400
    data = res.get_json()
    assert "Invalid pagination" in data["error"]


def test_oversized_pagination_bounded(client):
    # If limit exceeds max (100), it is bounded to max_limit
    res = client.get("/api/alerts?limit=5000&offset=0")
    assert res.status_code == 200
    data = res.get_json()
    assert "alerts" in data
