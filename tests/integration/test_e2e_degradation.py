"""
End-to-End Degradation Integration Scenarios:
Scenario 1: Start -> Process Fast Scan -> Break Transformer -> Process Traffic -> Verify Suricata detects -> Verify Dashboard Health.
Scenario 2: Start -> Break Suricata -> Process Stealth Scan -> Verify Transformer detects -> Verify Dashboard Health.
"""

import pytest
from pathlib import Path

from nids.health import get_health_manager, HealthStatus
from nids.ml.transformer_model import TransformerInferenceEngine
from nids.fusion.decision_engine import DecisionEngine
from nids.feature_extraction.window_sequencer import WindowSequencer
from nids.feature_extraction.flow_tracker import FlowTracker
from nids.storage.database import NidsDatabase
from nids.storage.exporter import SiemExporter
from nids.capture.adapters import PcapCaptureAdapter
from nids.capture.suricata_evaluator import OfflineSuricataEngine
from nids.dashboard.app import create_dashboard_app


def test_scenario_1_transformer_breakage_suricata_survives(tmp_path):
    """
    E2E Scenario 1:
    1. Operational NIDS processes fast scan -> HYBRID alert.
    2. Transformer is broken/disabled -> ML_UNAVAILABLE.
    3. Traffic processed again -> Suricata continues detecting as SURICATA.
    4. Dashboard /api/health reflects ML_UNAVAILABLE while overall system remains DEGRADED (operational).
    """
    db_file = str(tmp_path / "e2e_scen1.db")
    export_file = str(tmp_path / "e2e_scen1_siem.jsonl")
    db = NidsDatabase(db_path=db_file)
    exporter = SiemExporter(export_file_path=export_file)
    sequencer = WindowSequencer()
    ml_engine = TransformerInferenceEngine(weights_path="models/transformer_10x8.pt")
    health_mgr = get_health_manager()
    health_mgr.reset()

    decision_engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=ml_engine,
        sequencer=sequencer,
        decision_threshold=0.70,
        alert_cooldown_sec=0.0,
    )

    app = create_dashboard_app(db=db, ml_engine=ml_engine, sequencer=sequencer)
    app.config["TESTING"] = True
    client = app.test_client()

    # 1. Process lab_fast_scan with working Transformer + Suricata
    pcap_path = "data/pcaps/lab_fast_scan.pcap"
    suricata_engine = OfflineSuricataEngine()
    suricata_alerts, _ = suricata_engine.evaluate_pcap(pcap_path)
    assert len(suricata_alerts) > 0

    first_alert = decision_engine.handle_suricata_event(suricata_alerts[0])
    assert first_alert is not None

    # 2. Break the Transformer
    ml_engine.is_available = False
    health_mgr.update_status("transformer", HealthStatus.ML_UNAVAILABLE, message="ML runtime failure")

    # 3. Process traffic again with broken Transformer
    second_alert = decision_engine.handle_suricata_event(suricata_alerts[0])
    assert second_alert is not None
    assert second_alert.detection_method == "SURICATA"
    assert second_alert.ml_status == "ML_UNAVAILABLE"

    # 4. Check dashboard /api/health
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["components"]["transformer"]["status"] == HealthStatus.ML_UNAVAILABLE.value
    assert data["overall_status"] == HealthStatus.DEGRADED.value


def test_scenario_2_suricata_breakage_transformer_survives(tmp_path):
    """
    E2E Scenario 2:
    1. Suricata is DOWN.
    2. Stealth scan traffic is processed through flow extraction & windowing.
    3. Transformer detects multi-window stealth reconnaissance as TRANSFORMER_RECON.
    4. Dashboard /api/health reflects SURICATA = DOWN while detection continues.
    """
    db_file = str(tmp_path / "e2e_scen2.db")
    export_file = str(tmp_path / "e2e_scen2_siem.jsonl")
    db = NidsDatabase(db_path=db_file)
    exporter = SiemExporter(export_file_path=export_file)
    sequencer = WindowSequencer()
    ml_engine = TransformerInferenceEngine(weights_path="models/transformer_10x8.pt")
    health_mgr = get_health_manager()
    health_mgr.reset()

    decision_engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=ml_engine,
        sequencer=sequencer,
        decision_threshold=0.70,
        alert_cooldown_sec=0.0,
    )

    app = create_dashboard_app(db=db, ml_engine=ml_engine, sequencer=sequencer)
    app.config["TESTING"] = True
    client = app.test_client()

    # 1. Break Suricata
    health_mgr.update_status("suricata", HealthStatus.DOWN, message="Suricata socket connection refused")

    # 2. Feed stealth scan sequence
    src_ip = "192.168.10.103"
    for _ in range(10):
        feature_dict = {
            "dst_port_count": 4.0,
            "dst_ip_count": 1.0,
            "syn_ratio": 0.85,
            "syn_ack_ratio": 8.0,
            "rst_ratio": 0.20,
            "packet_rate": 0.5,
            "byte_rate": 180.0,
            "flow_duration_mean": 0.1,
        }
        sequencer.feed_window_features(src_ip, feature_dict)

    # 3. Transformer evaluates and triggers alert
    alert = decision_engine.evaluate_periodic_ml(src_ip)
    assert alert is not None
    assert alert.detection_method == "TRANSFORMER_RECON"
    assert alert.confidence_score >= 0.70

    # 4. Check dashboard /api/health
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["components"]["suricata"]["status"] == HealthStatus.DOWN.value
