"""
Integration Tests: SQLite Database Failure Resilience.
Verifies that database write errors, locks, or corruption do not crash the packet capture / detection engine.
"""

import pytest
import sqlite3
from pathlib import Path

from nids.health import get_health_manager, HealthStatus
from nids.ml.transformer_model import TransformerInferenceEngine
from nids.fusion.decision_engine import DecisionEngine
from nids.feature_extraction.window_sequencer import WindowSequencer
from nids.storage.database import NidsDatabase
from nids.storage.exporter import SiemExporter
from nids.storage.models import AlertRecord
from nids.capture.eve_streamer import SuricataEvent


def test_database_write_failure_graceful_handling(tmp_path):
    health_mgr = get_health_manager()
    db_file = str(tmp_path / "test_db_locked.db")
    export_file = str(tmp_path / "siem_out.jsonl")

    db = NidsDatabase(db_path=db_file)
    exporter = SiemExporter(export_file_path=export_file)
    sequencer = WindowSequencer()
    ml_engine = TransformerInferenceEngine(weights_path="models/transformer_10x8.pt")

    decision_engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=ml_engine,
        sequencer=sequencer,
    )

    # Intentionally redirect DB path to an invalid directory to simulate disk failure
    db.db_path = Path("Z:/non_existent_drive/invalid_locked.db")

    event = SuricataEvent(
        timestamp=1700000000.0,
        iso_timestamp="2026-08-19T12:00:00Z",
        src_ip="192.168.10.150",
        dst_ip="192.168.10.1",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        event_type="alert",
        signature="ET SCAN Potential Nmap SYN Scan",
        signature_id=2000001,
        category="Attempted Information Leak",
        severity=2,
        raw_event={},
    )

    # Must NOT raise unhandled exception
    alert = decision_engine.handle_suricata_event(event)

    assert alert is not None
    exporter.flush()
    # Verify SIEM exporter still received alert even though DB write failed
    assert Path(export_file).exists()

    # Health manager must reflect SQLite error
    health = health_mgr.get_system_health()
    assert health["components"]["sqlite"]["error_count"] > 0
    assert health["components"]["sqlite"]["status"] == HealthStatus.DEGRADED.value
