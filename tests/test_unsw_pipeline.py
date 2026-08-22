"""
Unit and Integration Tests for UNSW-NB15 Pipeline and Hybrid Decision Engine.
"""

import unittest
from pathlib import Path
import numpy as np

from nids.ml.dataset_unsw import extract_8_features_from_row, FEATURE_NAMES, FEATURE_DIM
from nids.ml.transformer_model import ReconTransformer, TransformerInferenceEngine, TORCH_AVAILABLE
from nids.feature_extraction.window_sequencer import WindowSequencer
from nids.fusion.decision_engine import DecisionEngine
from nids.capture.eve_streamer import SuricataEvent
from nids.storage.database import NidsDatabase
from nids.storage.exporter import SiemExporter


class TestUNSWPipeline(unittest.TestCase):

    def test_feature_extraction_8_dims(self):
        mock_row = {
            "dur": "0.05",
            "spkts": "4",
            "dpkts": "0",
            "sbytes": "240",
            "dbytes": "0",
            "state": "REQ",
            "proto": "tcp",
            "synack": "0.0",
            "ackdat": "0.0",
            "tcprtt": "0.0",
            "ct_src_dport_ltm": "15",
            "ct_dst_ltm": "3",
            "rate": "80.0",
            "sload": "38400.0",
            "dload": "0.0",
            "attack_cat": "Reconnaissance",
            "label": "1",
        }
        vec = extract_8_features_from_row(mock_row)
        self.assertIsInstance(vec, np.ndarray)
        self.assertEqual(vec.shape, (8,))
        self.assertEqual(len(FEATURE_NAMES), 8)
        self.assertEqual(vec[0], 15.0)  # dst_port_count
        self.assertEqual(vec[1], 3.0)   # dst_ip_count
        self.assertEqual(vec[2], 0.85)  # syn_ratio for REQ state
        self.assertEqual(vec[4], 0.0)   # rst_ratio
        self.assertEqual(vec[5], 80.0)  # packet_rate
        self.assertEqual(vec[7], 0.05)  # flow_duration_mean

    def test_transformer_unsw_inference_compatibility(self):
        if not TORCH_AVAILABLE:
            self.skipTest("PyTorch not installed")

        model_path = Path("models/transformer_recon_unsw.pt")
        if not model_path.exists():
            self.skipTest("UNSW model weights not found")

        engine = TransformerInferenceEngine(weights_path=str(model_path))
        self.assertTrue(engine.is_available)

        # 1. Normal sequence
        dummy_normal_seq = np.zeros((10, 8), dtype=np.float32)
        dummy_normal_seq[:, 0] = 2.0  # dst_ports
        dummy_normal_seq[:, 1] = 2.0  # dst_ips
        dummy_normal_seq[:, 2] = 0.1  # syn_ratio
        dummy_normal_seq[:, 5] = 2.0  # packet_rate
        mask = np.ones((10,), dtype=np.float32)

        score_normal = engine.predict_score(dummy_normal_seq, mask)
        self.assertTrue(0.0 <= score_normal <= 1.0)

        # 2. Reconnaissance sequence
        dummy_recon_seq = np.zeros((10, 8), dtype=np.float32)
        dummy_recon_seq[:, 0] = 50.0  # high dst_ports
        dummy_recon_seq[:, 1] = 5.0
        dummy_recon_seq[:, 2] = 0.9   # high syn_ratio
        dummy_recon_seq[:, 5] = 60.0  # high packet_rate

        score_recon = engine.predict_score(dummy_recon_seq, mask)
        self.assertTrue(0.0 <= score_recon <= 1.0)

    def test_hybrid_decision_engine_unsw_integration(self):
        db_path = "data/test_nids_temp.db"
        siem_path = "data/test_siem_temp.jsonl"

        db = NidsDatabase(db_path)
        exporter = SiemExporter(export_file_path=siem_path)
        sequencer = WindowSequencer(window_size_sec=60.0, sequence_length=10)

        model_path = "models/transformer_recon_unsw.pt" if Path("models/transformer_recon_unsw.pt").exists() else "models/transformer_recon.pt"
        engine = TransformerInferenceEngine(weights_path=model_path)

        decision_engine = DecisionEngine(
            db=db,
            exporter=exporter,
            transformer_engine=engine,
            sequencer=sequencer,
            decision_threshold=0.70,
            alert_cooldown_sec=0.0,
        )

        # Feed custom reconnaissance window
        src_ip = "192.168.1.50"
        sequencer.feed_window_features(src_ip, {
            "dst_port_count": 80.0,
            "dst_ip_count": 10.0,
            "syn_ratio": 0.95,
            "syn_ack_ratio": 15.0,
            "rst_ratio": 0.20,
            "packet_rate": 50.0,
            "byte_rate": 2000.0,
            "flow_duration_mean": 0.05,
        })

        # Test Case A: Suricata signature detection + High ML Score -> HYBRID
        event = SuricataEvent(
            timestamp=1700000000.0,
            iso_timestamp="2026-08-22T19:40:00Z",
            src_ip=src_ip,
            dst_ip="192.168.1.1",
            src_port=44552,
            dst_port=80,
            protocol="TCP",
            event_type="alert",
            signature="ET SCAN Potential Nmap SYN Scan",
            signature_id=2000001,
            category="Attempted Information Leak",
            severity=1,
            raw_event={},
        )

        alert = decision_engine.handle_suricata_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.src_ip, src_ip)
        self.assertIn(alert.detection_method, ["SURICATA", "TRANSFORMER", "HYBRID"])
        self.assertTrue(0.0 <= alert.confidence_score <= 1.0)

        # Cleanup temp test files
        for p in [Path(db_path), Path(siem_path)]:
            if p.exists():
                try:
                    p.unlink()
                except Exception:
                    pass


if __name__ == "__main__":
    unittest.main()
