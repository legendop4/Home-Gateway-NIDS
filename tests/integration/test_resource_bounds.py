"""
Integration Tests: Resource Bounds and In-Memory Limits.
Verifies hard caps and deterministic eviction for:
1. FlowTracker: max_active_flows
2. WindowSequencer: max_tracked_ips
3. DecisionEngine: max_pending_alerts
"""

import pytest
import time
from nids.feature_extraction.flow_tracker import FlowTracker, PacketSummary
from nids.feature_extraction.window_sequencer import WindowSequencer
from nids.fusion.decision_engine import DecisionEngine
from nids.capture.eve_streamer import SuricataEvent
from nids.storage.database import NidsDatabase
from nids.storage.exporter import SiemExporter
from nids.ml.transformer_model import TransformerInferenceEngine


def test_flow_tracker_max_active_flows_bound():
    # Set tight limit of 50 active flows
    tracker = FlowTracker(flow_timeout_sec=120.0, max_active_flows=50)

    # Ingest 150 unique flows
    for i in range(150):
        pkt = PacketSummary(
            timestamp=1700000000.0 + i,
            src_ip="192.168.1.100",
            dst_ip=f"10.0.0.{i % 254 + 1}",
            src_port=10000 + i,
            dst_port=80,
            protocol="TCP",
            length=64,
            is_syn=True,
        )
        tracker.process_packet(pkt)

    # Flow table must be strictly bounded at or below max_active_flows
    assert len(tracker.flows) <= 50
    assert len(tracker.flows) > 0


def test_window_sequencer_max_tracked_ips_bound():
    # Set tight limit of 20 tracked IPs
    sequencer = WindowSequencer(window_size_sec=60.0, sequence_length=10, max_tracked_ips=20)

    # Ingest packets across 80 unique source IPs
    for i in range(80):
        src_ip = f"172.16.0.{i+1}"
        pkt = PacketSummary(
            timestamp=1700000000.0 + (i * 5),
            src_ip=src_ip,
            dst_ip="10.0.0.1",
            src_port=20000,
            dst_port=443,
            protocol="TCP",
            length=100,
            is_syn=True,
        )
        sequencer.process_packet(pkt)

    # Active windows and window history must never exceed max_tracked_ips
    assert len(sequencer.active_windows) <= 20
    assert len(sequencer.window_history) <= 20


def test_decision_engine_max_pending_alerts_bound(tmp_path):
    db = NidsDatabase(db_path=str(tmp_path / "bounds.db"))
    exporter = SiemExporter(export_file_path=str(tmp_path / "bounds.jsonl"))
    sequencer = WindowSequencer()
    ml_engine = TransformerInferenceEngine(weights_path="models/transformer_10x8.pt")

    # Set tight cooldown cache limit of 30 IPs
    decision_engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=ml_engine,
        sequencer=sequencer,
        alert_cooldown_sec=10.0,
        max_pending_alerts=30,
    )

    # Trigger alerts from 100 distinct source IPs
    for i in range(100):
        event = SuricataEvent(
            timestamp=1700000000.0 + (i * 0.1),
            iso_timestamp="2026-08-19T12:00:00Z",
            src_ip=f"192.168.100.{i+1}",
            dst_ip="10.0.0.1",
            src_port=30000 + i,
            dst_port=80,
            protocol="TCP",
            event_type="alert",
            signature="ET SCAN Test Limit",
            signature_id=2000001,
            category="Scan",
            severity=2,
            raw_event={},
        )
        decision_engine.handle_suricata_event(event)

    # Cooldown tracking table must be strictly bounded at or below max_pending_alerts
    assert len(decision_engine._last_alert_time) <= 30
