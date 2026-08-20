"""
Main Entrypoint and Orchestrator for Home-Gateway NIDS.
Supports Training, Evaluation, PCAP Replay, Live Sniffing, and Web Dashboard.
"""

from pathlib import Path
import argparse
import sys
import threading
import time

from nids.config import load_config
from nids.capture.adapters import PcapCaptureAdapter, ScapyCaptureAdapter
from nids.capture.eve_streamer import SuricataEveStreamer
from nids.feature_extraction.flow_tracker import FlowTracker, PacketSummary
from nids.feature_extraction.window_sequencer import WindowSequencer
from nids.ml.transformer_model import TransformerInferenceEngine
from nids.storage.database import NidsDatabase
from nids.storage.exporter import SiemExporter
from nids.fusion.decision_engine import DecisionEngine
from nids.dashboard.app import create_dashboard_app


def start_pipeline(config_path: str, mode: str, pcap_file: str = None, port: int = 5000):
    config = load_config(config_path)
    print("=" * 65)
    print("        HOME-GATEWAY NIDS: HYBRID RECONNAISSANCE GATEWAY")
    print(f"        Mode: {mode.upper()} | Port: {port}")
    print("=" * 65)

    # 1. Initialize Storage & Exporters
    db = NidsDatabase(db_path=config["system"]["db_path"])
    exporter = SiemExporter(export_file_path=config["system"]["siem_export_path"])

    # 2. Initialize Sequencer & ML Engine
    sequencer = WindowSequencer(
        window_size_sec=config["feature_extraction"]["window_size_sec"],
        sequence_length=config["feature_extraction"]["sequence_length"],
    )
    flow_tracker = FlowTracker()

    ml_weights = config["ml"]["model_weights_path"]
    ml_engine = TransformerInferenceEngine(weights_path=ml_weights, device=config["ml"]["device"])
    if ml_engine.is_available:
        print(f"[+] Sequence Transformer loaded from {ml_weights}")
    else:
        print(f"[-] Sequence Transformer NOT loaded (Weights missing or offline). Status: ML_UNAVAILABLE")

    # 3. Initialize Fusion Engine
    fusion = DecisionEngine(
        db=db,
        exporter=exporter,
        transformer_engine=ml_engine,
        sequencer=sequencer,
        decision_threshold=config["ml"]["decision_threshold"],
        alert_cooldown_sec=config["fusion"]["alert_cooldown_sec"],
    )

    # 4. Ingestion Callbacks
    def packet_callback(packet: PacketSummary):
        # Update devices table
        db.upsert_device(packet.src_ip, delta_packets=1, delta_bytes=packet.length)
        # Update flow tracker
        flow = flow_tracker.process_packet(packet)
        # Ingest into window sequencer
        closed_win = sequencer.process_packet(packet, flow_duration=flow.duration)
        if closed_win:
            # Trigger periodic ML sequence evaluation on completed window
            fusion.evaluate_periodic_ml(closed_win.src_ip)

    # 5. Start Suricata Streamer
    if config["suricata"]["enabled"]:
        eve_path = config["suricata"]["eve_path"]
        streamer = SuricataEveStreamer(
            eve_path=eve_path,
            recon_keywords=config["suricata"]["recon_signature_keywords"],
            poll_interval_sec=config["suricata"]["poll_interval_sec"],
        )
        streamer.start(callback=fusion.handle_suricata_event)
        print(f"[+] Suricata EVE streamer active on {eve_path}")

    # 6. Start Capture Source
    if mode == "live":
        iface = config["capture"]["interface"]
        print(f"[+] Starting live capture adapter on {iface}...")
        capture_adapter = ScapyCaptureAdapter(interface=iface, bpf_filter=config["capture"]["bpf_filter"])
        capture_thread = threading.Thread(target=capture_adapter.start, args=(packet_callback,), daemon=True)
        capture_thread.start()
    elif mode == "pcap":
        file_to_replay = pcap_file or config["capture"]["pcap_file"]
        if not file_to_replay or not Path(file_to_replay).exists():
            print(f"[-] PCAP file not found: {file_to_replay}. Please specify with --pcap-file.")
        else:
            print(f"[+] Replaying PCAP file: {file_to_replay}...")
            capture_adapter = PcapCaptureAdapter(file_to_replay)
            capture_thread = threading.Thread(target=capture_adapter.start, args=(packet_callback,), daemon=True)
            capture_thread.start()

    # 7. Start Web Dashboard
    app = create_dashboard_app(db=db, ml_engine=ml_engine, sequencer=sequencer, config=config)
    print(f"\n[+] Home-Gateway NIDS Dashboard available at: http://localhost:{port}")
    app.run(host=config["dashboard"]["host"], port=port, debug=False)


def main():
    parser = argparse.ArgumentParser(description="Home-Gateway NIDS Command Line Orchestrator")
    parser.add_argument("--config", type=str, default="config/config.yaml", help="Path to config file")
    parser.add_argument("--mode", type=str, choices=["live", "pcap", "dashboard"], default="dashboard", help="Operating mode")
    parser.add_argument("--pcap-file", type=str, default=None, help="PCAP file to replay in pcap mode")
    parser.add_argument("--port", type=int, default=5000, help="Web dashboard port")
    parser.add_argument("--train", action="store_true", help="Train Transformer and Baseline models")
    parser.add_argument("--evaluate", action="store_true", help="Run evaluation harness on synthetic & PCAP data")
    parser.add_argument("--gen-pcaps", action="store_true", help="Generate synthetic lab PCAP files")
    args = parser.parse_args()

    if args.gen_pcaps:
        from scripts.generate_lab_pcap import generate_pcaps
        generate_pcaps()
        return

    if args.train:
        from nids.ml.train import train_models
        train_models()
        return

    if args.evaluate:
        from nids.ml.evaluate import evaluate_all
        evaluate_all()
        return

    start_pipeline(config_path=args.config, mode=args.mode, pcap_file=args.pcap_file, port=args.port)


if __name__ == "__main__":
    main()
