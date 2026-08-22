"""
End-to-End Production Pipeline Integration Test using models/transformer_recon_unsw.pt.
Tests Benign traffic, Reconnaissance traffic, Suricata events, HYBRID fusion,
TRANSFORMER_RECON stealth detection, and Dashboard API exposure.
"""

from pathlib import Path
import json
import time
import numpy as np

from nids.feature_extraction.window_sequencer import WindowSequencer, WindowMetrics
from nids.feature_extraction.flow_tracker import PacketSummary, FlowTracker
from nids.ml.transformer_model import TransformerInferenceEngine
from nids.fusion.decision_engine import DecisionEngine
from nids.capture.eve_streamer import SuricataEvent
from nids.storage.database import NidsDatabase
from nids.storage.exporter import SiemExporter
from nids.dashboard.app import create_dashboard_app


def run_e2e_test():
    print("==================================================================")
    print("END-TO-END PIPELINE INTEGRATION TEST: models/transformer_recon_unsw.pt")
    print("==================================================================")

    # 1. Initialize Pipeline Components
    db_path = "data/e2e_test_nids.db"
    siem_path = "data/e2e_test_siem.jsonl"
    model_path = "models/transformer_recon_unsw.pt"

    for p in [Path(db_path), Path(siem_path)]:
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass

    db = NidsDatabase(db_path)
    exporter = SiemExporter(export_file_path=siem_path)
    sequencer = WindowSequencer(window_size_sec=60.0, sequence_length=10)

    print(f"\n[1] Loading TransformerInferenceEngine from {model_path}...")
    ml_engine = TransformerInferenceEngine(weights_path=model_path)
    print(f"    - Engine Available: {ml_engine.is_available}")
    print(f"    - Model Loaded: {ml_engine.model is not None}")
    assert ml_engine.is_available, "Failed to load UNSW model weights!"

    decision_engine = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=ml_engine,
        sequencer=sequencer,
        decision_threshold=0.70,
        alert_cooldown_sec=0.0,
        min_packets_for_ml=5,
    )

    # Load real sequences from held-out test split for ground truth validation
    test_npz = np.load("data/processed_unsw/test.npz")
    X_test, mask_test, y_test = test_npz["X"], test_npz["mask"], test_npz["y"]
    norm_idx = int(np.where(y_test == 0)[0][0])
    recon_idx = int(np.where(y_test == 1)[0][0])

    # -------------------------------------------------------------
    # 2. Test Case 1: Benign Web Browsing Traffic Sequence
    # -------------------------------------------------------------
    benign_ip = "192.168.1.105"
    print(f"\n[2] Feeding Benign Traffic Windows for {benign_ip}...")
    benign_seq_raw = X_test[norm_idx]
    for w in range(10):
        feat = benign_seq_raw[w]
        wm = WindowMetrics(
            src_ip=benign_ip,
            window_start=time.time() - (10 - w) * 60.0,
            window_end=time.time() - (9 - w) * 60.0,
            dst_ports={int(p) for p in range(max(1, int(feat[0])))},
            dst_ips={f"10.0.0.{i+1}" for i in range(max(1, int(feat[1])))},
            total_packets=max(10, int(feat[5] * 60.0)),
            total_bytes=int(feat[6] * 60.0),
            tcp_packets=max(10, int(feat[5] * 60.0)),
            syn_count=int(feat[2] * max(10, int(feat[5] * 60.0))),
            ack_count=max(1, int(feat[2] * max(10, int(feat[5] * 60.0)) / max(0.1, feat[3]))),
            rst_count=int(feat[4] * max(10, int(feat[5] * 60.0))),
            flow_durations=[float(feat[7])],
        )
        sequencer.feed_custom_window(benign_ip, wm)

    seq_benign, mask_benign = sequencer.get_sequence_tensor(benign_ip, include_active=True)
    score_benign = ml_engine.predict_score(seq_benign, mask_benign)
    print(f"    - Benign Tensor Shape: {seq_benign.shape}, Mask Shape: {mask_benign.shape}")
    print(f"    - Benign Anomaly Score: {score_benign:.4f} (Threshold: 0.70)")
    assert score_benign < 0.70, f"Expected score < 0.70, got {score_benign:.4f}"

    # Periodic ML should NOT trigger an alert on benign traffic
    alert_benign = decision_engine.evaluate_periodic_ml(benign_ip)
    print(f"    - Periodic ML Evaluation: {alert_benign}")
    assert alert_benign is None, "Benign traffic falsely triggered TRANSFORMER_RECON alert!"

    # Suricata signature on benign device with low ML score -> SURICATA only
    event_benign = SuricataEvent(
        timestamp=time.time(),
        iso_timestamp="2026-08-22T19:50:00Z",
        src_ip=benign_ip,
        dst_ip="192.168.1.1",
        src_port=51234,
        dst_port=80,
        protocol="TCP",
        event_type="alert",
        signature="SURICATA HTTP Generic Notice",
        signature_id=2000099,
        category="Generic Protocol Command",
        severity=3,
        raw_event={},
    )
    alert_suri_only = decision_engine.handle_suricata_event(event_benign)
    print(f"    - Suricata Hit on Benign Traffic Detection Method: {alert_suri_only.detection_method}")
    print(f"    - Confidence Score: {alert_suri_only.confidence_score}")
    assert alert_suri_only.detection_method == "SURICATA", f"Expected SURICATA, got {alert_suri_only.detection_method}"

    # -------------------------------------------------------------
    # 3. Test Case 2: Reconnaissance Traffic (Stealth Scan -> TRANSFORMER_RECON)
    # -------------------------------------------------------------
    recon_ip = "192.168.1.220"
    print(f"\n[3] Feeding Reconnaissance Scan Windows for {recon_ip}...")
    recon_seq_raw = X_test[recon_idx]
    for w in range(10):
        feat = recon_seq_raw[w]
        wm = WindowMetrics(
            src_ip=recon_ip,
            window_start=time.time() - (10 - w) * 60.0,
            window_end=time.time() - (9 - w) * 60.0,
            dst_ports={int(p) for p in range(max(1, int(feat[0])))},
            dst_ips={f"10.0.0.{i+1}" for i in range(max(1, int(feat[1])))},
            total_packets=max(10, int(feat[5] * 60.0)),
            total_bytes=int(feat[6] * 60.0),
            tcp_packets=max(10, int(feat[5] * 60.0)),
            syn_count=int(feat[2] * max(10, int(feat[5] * 60.0))),
            ack_count=max(1, int(feat[2] * max(10, int(feat[5] * 60.0)) / max(0.1, feat[3]))),
            rst_count=int(feat[4] * max(10, int(feat[5] * 60.0))),
            flow_durations=[float(feat[7])],
        )
        sequencer.feed_custom_window(recon_ip, wm)

    seq_recon, mask_recon = sequencer.get_sequence_tensor(recon_ip, include_active=True)
    score_recon = ml_engine.predict_score(seq_recon, mask_recon)
    print(f"    - Reconnaissance Anomaly Score: {score_recon:.4f} (Threshold: 0.70)")
    assert score_recon >= 0.70, f"Expected anomaly score >= 0.70, got {score_recon:.4f}"

    alert_stealth = decision_engine.evaluate_periodic_ml(recon_ip)
    print(f"    - Stealth Recon Detection Method: {alert_stealth.detection_method}")
    print(f"    - Attack Family: {alert_stealth.attack_family}")
    print(f"    - Confidence Score: {alert_stealth.confidence_score}")
    assert alert_stealth.detection_method == "TRANSFORMER_RECON"

    # -------------------------------------------------------------
    # 4. Test Case 3: Hybrid Detection (Suricata Event + High ML Score -> HYBRID)
    # -------------------------------------------------------------
    hybrid_ip = "192.168.1.250"
    print(f"\n[4] Testing Hybrid Decision Fusion for {hybrid_ip}...")
    for w in range(10):
        feat = recon_seq_raw[w]
        wm = WindowMetrics(
            src_ip=hybrid_ip,
            window_start=time.time() - (10 - w) * 60.0,
            window_end=time.time() - (9 - w) * 60.0,
            dst_ports={int(p) for p in range(max(1, int(feat[0])))},
            dst_ips={f"10.0.0.{i+1}" for i in range(max(1, int(feat[1])))},
            total_packets=max(10, int(feat[5] * 60.0)),
            total_bytes=int(feat[6] * 60.0),
            tcp_packets=max(10, int(feat[5] * 60.0)),
            syn_count=int(feat[2] * max(10, int(feat[5] * 60.0))),
            ack_count=max(1, int(feat[2] * max(10, int(feat[5] * 60.0)) / max(0.1, feat[3]))),
            rst_count=int(feat[4] * max(10, int(feat[5] * 60.0))),
            flow_durations=[float(feat[7])],
        )
        sequencer.feed_custom_window(hybrid_ip, wm)

    event_recon = SuricataEvent(
        timestamp=time.time(),
        iso_timestamp="2026-08-22T19:55:00Z",
        src_ip=hybrid_ip,
        dst_ip="192.168.1.1",
        src_port=49882,
        dst_port=445,
        protocol="TCP",
        event_type="alert",
        signature="ET SCAN Potential Nmap SYN Scan",
        signature_id=2000001,
        category="Attempted Information Leak",
        severity=1,
        raw_event={},
    )

    alert_hybrid = decision_engine.handle_suricata_event(event_recon)
    print(f"    - Hybrid Event Detection Method: {alert_hybrid.detection_method}")
    print(f"    - Suricata Signature: {alert_hybrid.suricata_signature}")
    print(f"    - Confidence Score: {alert_hybrid.confidence_score}")
    print(f"    - Alert Details: {alert_hybrid.details}")
    assert alert_hybrid.detection_method == "HYBRID"

    # -------------------------------------------------------------
    # 5. Test Case 4: Dashboard API Exposure Verification
    # -------------------------------------------------------------
    print("\n[5] Testing Dashboard Flask API Exposure...")
    app = create_dashboard_app(db=db, ml_engine=ml_engine, sequencer=sequencer)
    client = app.test_client()

    res_stats = client.get("/api/stats")
    stats_data = json.loads(res_stats.data)
    print(f"    - /api/stats Status: {res_stats.status_code}, ML Status: {stats_data.get('ml_status')}")
    assert res_stats.status_code == 200
    assert stats_data.get("ml_status") == "ACTIVE"

    res_alerts = client.get("/api/alerts")
    alerts_data = json.loads(res_alerts.data)
    alert_methods = [a["detection_method"] for a in alerts_data.get("alerts", [])]
    print(f"    - /api/alerts Status: {res_alerts.status_code}, Alert Count: {alerts_data.get('count')}")
    print(f"    - Exposed Detection Methods: {alert_methods}")
    assert res_alerts.status_code == 200
    assert "HYBRID" in alert_methods
    assert "TRANSFORMER_RECON" in alert_methods
    assert "SURICATA" in alert_methods

    res_metrics = client.get("/api/metrics")
    metrics_data = json.loads(res_metrics.data)
    print(f"    - /api/metrics Status: {res_metrics.status_code}, Count: {metrics_data.get('count')}")
    assert res_metrics.status_code == 200

    print("\n==================================================================")
    print("ALL END-TO-END PIPELINE TESTS PASSED SUCCESSFULLY!")
    print("==================================================================")

    # Cleanup temp test files
    for p in [Path(db_path), Path(siem_path)]:
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass


if __name__ == "__main__":
    run_e2e_test()
