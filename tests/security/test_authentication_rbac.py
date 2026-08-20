"""
Security Tests: Authentication, API Keys, and Role-Based Access Control (RBAC).
Verifies:
1. Production mode rejects unauthenticated API requests with HTTP 401.
2. Invalid API keys are rejected with HTTP 401.
3. VIEWER role can access read-only telemetry but receives HTTP 403 on ADMIN endpoints.
4. ADMIN role can access both read-only and administrative/export endpoints.
"""

import pytest
import os
from nids.storage.database import NidsDatabase
from nids.dashboard.app import create_dashboard_app


@pytest.fixture
def prod_client(tmp_path):
    db_file = str(tmp_path / "test_auth_prod.db")
    db = NidsDatabase(db_path=db_file)
    prod_config = {
        "system": {"environment": "production"},
        "security": {
            "admin_api_key": "test-admin-secret-key-12345",
            "viewer_api_key": "test-viewer-secret-key-67890",
        }
    }
    app = create_dashboard_app(db=db, config=prod_config)
    app.config["TESTING"] = True
    return app.test_client()


def test_production_unauthenticated_request_rejected(prod_client):
    # In production, unauthenticated request from remote must receive 401
    res = prod_client.get("/api/stats", environ_base={"REMOTE_ADDR": "192.168.1.50"})
    assert res.status_code == 401
    data = res.get_json()
    assert "Unauthorized" in data["error"]


def test_invalid_api_key_rejected(prod_client):
    res = prod_client.get(
        "/api/stats",
        headers={"X-API-Key": "completely-invalid-attacker-key"},
        environ_base={"REMOTE_ADDR": "192.168.1.50"}
    )
    assert res.status_code == 401
    data = res.get_json()
    assert "Unauthorized" in data["error"]


def test_viewer_role_access(prod_client):
    # Viewer can access /api/stats and /api/alerts
    headers = {"X-API-Key": "test-viewer-secret-key-67890"}
    res = prod_client.get("/api/stats", headers=headers, environ_base={"REMOTE_ADDR": "192.168.1.50"})
    assert res.status_code == 200

    # Viewer CANNOT access ADMIN endpoint /api/siem/export (must return 403 Forbidden)
    res_admin = prod_client.get("/api/siem/export", headers=headers, environ_base={"REMOTE_ADDR": "192.168.1.50"})
    assert res_admin.status_code == 403
    assert "Forbidden" in res_admin.get_json()["error"]


def test_admin_role_access(prod_client):
    # Admin can access /api/stats
    headers = {"X-API-Key": "test-admin-secret-key-12345"}
    res = prod_client.get("/api/stats", headers=headers, environ_base={"REMOTE_ADDR": "192.168.1.50"})
    assert res.status_code == 200

    # Admin is authorized for export (returns 404 if no log file yet, but NOT 401 or 403)
    res_export = prod_client.get("/api/siem/export", headers=headers, environ_base={"REMOTE_ADDR": "192.168.1.50"})
    assert res_export.status_code in [200, 404]
