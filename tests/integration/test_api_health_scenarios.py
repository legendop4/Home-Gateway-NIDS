"""
Integration Tests: REST API Health Endpoint Scenarios.
Verifies GET /api/health schema and status resolutions under UP, DEGRADED, DOWN, and ML_UNAVAILABLE states.
"""

import pytest
from nids.health import get_health_manager, HealthStatus, SystemHealthManager
from nids.storage.database import NidsDatabase
from nids.dashboard.app import create_dashboard_app


@pytest.fixture
def api_client(tmp_path):
    health_mgr = get_health_manager()
    health_mgr.reset()
    db_file = str(tmp_path / "test_api_health.db")
    db = NidsDatabase(db_path=db_file)
    app = create_dashboard_app(db=db)
    app.config["TESTING"] = True
    return app.test_client()


def test_api_health_all_up(api_client):
    health_mgr = get_health_manager()
    for comp in SystemHealthManager.CORE_COMPONENTS:
        health_mgr.heartbeat(comp)

    res = api_client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["overall_status"] == HealthStatus.UP.value
    assert len(data["components"]) == 8


def test_api_health_degraded_when_ml_unavailable(api_client):
    health_mgr = get_health_manager()
    health_mgr.update_status("transformer", HealthStatus.ML_UNAVAILABLE, message="PyTorch model missing")

    res = api_client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["overall_status"] == HealthStatus.DEGRADED.value
    assert data["components"]["transformer"]["status"] == HealthStatus.ML_UNAVAILABLE.value


def test_api_health_down_when_sqlite_fails(api_client):
    health_mgr = get_health_manager()
    health_mgr.update_status("sqlite", HealthStatus.DOWN, message="Database locked by another process")

    res = api_client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["overall_status"] == HealthStatus.DOWN.value
    assert data["components"]["sqlite"]["status"] == HealthStatus.DOWN.value
