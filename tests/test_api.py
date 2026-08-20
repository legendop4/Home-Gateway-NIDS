"""
Unit tests for Flask Dashboard API endpoints and schemas.
"""

import pytest
from nids.storage.database import NidsDatabase
from nids.storage.models import AlertRecord
from nids.feature_extraction.window_sequencer import WindowSequencer
from nids.dashboard.app import create_dashboard_app


@pytest.fixture
def client(tmp_path):
    db_path = str(tmp_path / "test_api.db")
    db = NidsDatabase(db_path=db_path)
    sequencer = WindowSequencer()

    # Prepopulate an alert
    db.insert_alert(AlertRecord(
        timestamp=1700000000.0,
        iso_timestamp="2026-08-19T12:00:00Z",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        attack_family="Reconnaissance / Fast Scan",
        detection_method="HYBRID",
        confidence_score=0.95,
        suricata_signature="ET SCAN Nmap",
        suricata_sid=2000001,
        ml_status="ACTIVE",
        details="Test alert",
    ))
    db.upsert_device("192.168.1.100", delta_packets=50, delta_bytes=2000)

    app = create_dashboard_app(db=db, sequencer=sequencer)
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_api_stats(client):
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_alerts"] == 1
    assert data["total_devices"] == 1


def test_api_alerts(client):
    res = client.get("/api/alerts")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] == 1
    assert data["alerts"][0]["src_ip"] == "192.168.1.100"
    assert data["alerts"][0]["detection_method"] == "HYBRID"


def test_api_devices(client):
    res = client.get("/api/devices")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] == 1
    assert data["devices"][0]["ip"] == "192.168.1.100"


def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert "overall_status" in data
    assert "components" in data
    assert "dashboard_api" in data["components"]
    assert "sqlite" in data["components"]



def test_api_sequence_endpoint(client):
    res = client.get("/api/sequence/192.168.1.100")
    assert res.status_code == 200
    data = res.get_json()
    assert data["src_ip"] == "192.168.1.100"
    assert len(data["sequence"]) == 10
