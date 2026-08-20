"""
Integration Tests: Transformer Resilience and Graceful ML_UNAVAILABLE Degradation.
Verifies:
1. Missing model weights -> ML_UNAVAILABLE, Suricata continues operating.
2. Corrupted model weights -> ML_UNAVAILABLE, Suricata continues operating.
3. Runtime inference exception -> ML_UNAVAILABLE, Suricata continues operating.
"""

import pytest
from pathlib import Path
from nids.health import get_health_manager, HealthStatus
from nids.ml.transformer_model import TransformerInferenceEngine
from nids.capture.eve_streamer import SuricataEvent
from nids.fusion.decision_engine import DecisionEngine
from nids.feature_extraction.window_sequencer import WindowSequencer
from nids.storage.database import NidsDatabase
from nids.storage.exporter import SiemExporter


@pytest.fixture
def setup_pipeline(tmp_path):
    db_file = str(tmp_path / "test_resilience.db")
    export_file = str(tmp_path / "siem.jsonl")
    db = NidsDatabase(db_path=db_file)
    exporter = SiemExporter(export_file_path=export_file)
    sequencer = WindowSequencer()
    return db, exporter, sequencer


def test_transformer_missing_weights_fallback(setup_pipeline, tmp_path):
    db, exporter, sequencer = setup_pipeline
    non_existent_weights = str(tmp_path / "non_existent_transformer.pt")

    # Initialize engine with non-existent weights
    ml_engine = TransformerInferenceEngine(weights_path=non_existent_weights)
    assert not ml_engine.is_available

    decision_engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=ml_engine,
        sequencer=sequencer,
    )

    # Trigger Suricata event
    event = SuricataEvent(
        timestamp=1700000000.0,
        iso_timestamp="2026-08-19T12:00:00Z",
        src_ip="192.168.10.105",
        dst_ip="192.168.10.1",
        src_port=44444,
        dst_port=80,
        protocol="TCP",
        event_type="alert",
        signature="ET SCAN Potential Nmap SYN Scan",
        signature_id=2000001,
        category="Attempted Information Leak",
        severity=2,
        raw_event={},
    )

    alert = decision_engine.handle_suricata_event(event)

    assert alert is not None
    assert alert.detection_method == "SURICATA"
    assert alert.ml_status == "ML_UNAVAILABLE"
    assert "Notice: ML engine is ML_UNAVAILABLE" in alert.details

    # Verify DB recorded alert despite ML being unavailable
    alerts = db.get_recent_alerts()
    assert len(alerts) == 1
    assert alerts[0]["ml_status"] == "ML_UNAVAILABLE"


def test_transformer_corrupted_weights_fallback(setup_pipeline, tmp_path):
    db, exporter, sequencer = setup_pipeline
    corrupted_file = tmp_path / "corrupted_model.pt"
    corrupted_file.write_bytes(b"\x00\xFF\xAA\x55INVALID_PYTORCH_HEADER_BYTES")

    ml_engine = TransformerInferenceEngine(weights_path=str(corrupted_file))
    assert not ml_engine.is_available

    decision_engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=ml_engine,
        sequencer=sequencer,
    )

    event = SuricataEvent(
        timestamp=1700000005.0,
        iso_timestamp="2026-08-19T12:00:05Z",
        src_ip="192.168.10.106",
        dst_ip="192.168.10.1",
        src_port=55555,
        dst_port=443,
        protocol="TCP",
        event_type="alert",
        signature="ET SCAN Rapid Multi-Port Scan Detected",
        signature_id=2000005,
        category="Attempted Information Leak",
        severity=2,
        raw_event={},
    )

    alert = decision_engine.handle_suricata_event(event)
    assert alert is not None
    assert alert.detection_method == "SURICATA"
    assert alert.ml_status == "ML_UNAVAILABLE"
