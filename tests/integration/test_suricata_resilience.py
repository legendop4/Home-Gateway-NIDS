"""
Integration Tests: Suricata Failure and Transformer Standalone Operation.
Verifies:
1. Suricata failure/absence allows Transformer to continue detecting slow scans.
2. Platform-specific Suricata process execution tests marked ENVIRONMENT_LIMITED on Windows.
"""

import pytest
import shutil
from pathlib import Path
import numpy as np

from nids.health import get_health_manager, HealthStatus
from nids.ml.transformer_model import TransformerInferenceEngine
from nids.fusion.decision_engine import DecisionEngine
from nids.feature_extraction.window_sequencer import WindowSequencer
from nids.storage.database import NidsDatabase
from nids.storage.exporter import SiemExporter


@pytest.fixture
def setup_pipeline(tmp_path):
    db_file = str(tmp_path / "test_suricata_res.db")
    export_file = str(tmp_path / "siem.jsonl")
    db = NidsDatabase(db_path=db_file)
    exporter = SiemExporter(export_file_path=export_file)
    sequencer = WindowSequencer()
    ml_engine = TransformerInferenceEngine(weights_path="models/transformer_10x8.pt")
    return db, exporter, sequencer, ml_engine


def test_suricata_down_transformer_standalone(setup_pipeline):
    """
    When Suricata is DOWN / no signatures arrive, Transformer catches slow/stealth scans independently.
    """
    db, exporter, sequencer, ml_engine = setup_pipeline
    health_mgr = get_health_manager()
    health_mgr.update_status("suricata", HealthStatus.DOWN, message="Suricata process stopped")

    decision_engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=ml_engine,
        sequencer=sequencer,
        decision_threshold=0.70,
        alert_cooldown_sec=0.0,
    )

    # Populate 10 windows with stealth scan features for 192.168.10.200
    src_ip = "192.168.10.200"
    for w in range(10):
        # 3 ports, high SYN ratio, uncompleted handshakes
        feature_dict = {
            "dst_port_count": 3.0,
            "dst_ip_count": 1.0,
            "syn_ratio": 0.90,
            "syn_ack_ratio": 6.0,
            "rst_ratio": 0.20,
            "packet_rate": 0.5,
            "byte_rate": 150.0,
            "flow_duration_mean": 0.1,
        }
        sequencer.feed_window_features(src_ip, feature_dict)

    # Run periodic evaluation (Suricata is DOWN, but Transformer runs)
    alert = decision_engine.evaluate_periodic_ml(src_ip)

    assert alert is not None
    assert alert.detection_method == "TRANSFORMER_RECON"
    assert alert.ml_status == "ACTIVE"
    assert alert.confidence_score >= 0.70

    # Verify overall health reflects Suricata being DOWN
    health = health_mgr.get_system_health()
    assert health["components"]["suricata"]["status"] == HealthStatus.DOWN.value


@pytest.mark.skipif(not shutil.which("suricata"), reason="ENVIRONMENT_LIMITED: Suricata binary not in PATH (Requires Linux / Pi environment)")
def test_live_suricata_process_execution(tmp_path):
    """
    Live Suricata process execution test (only executes on Linux / Pi where suricata binary is installed).
    """
    from nids.capture.suricata_evaluator import run_suricata_on_pcap
    pcap_file = "data/pcaps/lab_fast_scan.pcap"
    alerts = run_suricata_on_pcap(pcap_file)
    assert len(alerts) > 0
