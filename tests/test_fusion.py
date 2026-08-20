"""
Unit tests for DecisionEngine, Hybrid Fusion, and explicit ML_UNAVAILABLE states.
"""

import pytest
import numpy as np
from pathlib import Path

from nids.capture.eve_streamer import SuricataEvent
from nids.feature_extraction.flow_tracker import PacketSummary
from nids.feature_extraction.window_sequencer import WindowSequencer
from nids.ml.transformer_model import TransformerInferenceEngine
from nids.storage.database import NidsDatabase
from nids.storage.exporter import SiemExporter
from nids.fusion.decision_engine import DecisionEngine


class MockMLInferenceEngine:
    def __init__(self, score: float = 0.90, is_available: bool = True):
        self.score = score
        self.is_available = is_available

    def predict_score(self, sequence: np.ndarray, mask=None) -> float:
        if not self.is_available:
            raise RuntimeError("ML_UNAVAILABLE")
        return self.score


def test_fusion_hybrid_trigger(tmp_path):
    db = NidsDatabase(db_path=str(tmp_path / "test.db"))
    exporter = SiemExporter(export_file_path=str(tmp_path / "siem.jsonl"))
    sequencer = WindowSequencer()
    mock_ml = MockMLInferenceEngine(score=0.92, is_available=True)

    engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=mock_ml,
        sequencer=sequencer,
        decision_threshold=0.70,
        alert_cooldown_sec=0.0,
    )

    event = SuricataEvent(
        timestamp=100.0,
        iso_timestamp="2026-08-19T12:00:00Z",
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        src_port=40000,
        dst_port=80,
        protocol="TCP",
        event_type="alert",
        signature="ET SCAN Potential Nmap SYN Scan",
        signature_id=2000001,
        category="Recon",
        severity=2,
        raw_event={}
    )

    alert = engine.handle_suricata_event(event)
    assert alert is not None
    assert alert.detection_method == "HYBRID"
    assert alert.confidence_score == 0.92
    assert alert.ml_status == "ACTIVE"


def test_fusion_ml_unavailable(tmp_path):
    db = NidsDatabase(db_path=str(tmp_path / "test_unavail.db"))
    exporter = SiemExporter(export_file_path=str(tmp_path / "siem_unavail.jsonl"))
    sequencer = WindowSequencer()
    mock_ml = MockMLInferenceEngine(is_available=False)

    engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=mock_ml,
        sequencer=sequencer,
        decision_threshold=0.70,
        alert_cooldown_sec=0.0,
    )

    event = SuricataEvent(
        timestamp=100.0,
        iso_timestamp="2026-08-19T12:00:00Z",
        src_ip="192.168.1.60",
        dst_ip="10.0.0.1",
        src_port=40000,
        dst_port=80,
        protocol="TCP",
        event_type="alert",
        signature="ET SCAN Potential Nmap SYN Scan",
        signature_id=2000001,
        category="Recon",
        severity=2,
        raw_event={}
    )

    alert = engine.handle_suricata_event(event)
    assert alert is not None
    assert alert.detection_method == "SURICATA"
    assert alert.ml_status == "ML_UNAVAILABLE"
