"""
Configuration loader and validator for Home-Gateway NIDS.
"""

import os
from pathlib import Path
from typing import Any, Dict
import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "system": {
        "environment": "development",
        "log_level": "INFO",
        "db_path": "data/nids.db",
        "siem_export_path": "data/siem_alerts.jsonl",
        "syslog_facility": "LOG_LOCAL6",
    },
    "capture": {
        "adapter": "pcap",
        "interface": "wlan0",
        "bpf_filter": "ip",
        "pcap_file": None,
    },
    "suricata": {
        "enabled": True,
        "eve_path": "data/eve.json",
        "poll_interval_sec": 0.5,
        "recon_signature_keywords": [
            "SCAN", "Portscan", "Nmap", "Reconnaissance",
            "SSH Scan", "SYN Scan", "FIN Scan", "NULL Scan", "XMAS Scan"
        ],
    },
    "feature_extraction": {
        "window_size_sec": 60,
        "sequence_length": 10,
        "features": [
            "dst_port_count", "dst_ip_count", "syn_ratio",
            "syn_ack_ratio", "rst_ratio", "packet_rate",
            "byte_rate", "flow_duration_mean"
        ],
    },
    "ml": {
        "enabled": True,
        "model_type": "transformer",
        "model_weights_path": "models/transformer_recon.pt",
        "decision_threshold": 0.70,
        "device": "cpu",
        "d_model": 32,
        "nhead": 4,
        "num_layers": 2,
        "dim_feedforward": 64,
        "dropout": 0.1,
    },
    "fusion": {
        "alert_cooldown_sec": 120,
        "min_packets_for_ml": 10,
    },
    "dashboard": {
        "host": "0.0.0.0",
        "port": 5000,
        "debug": False,
    },
}


def deep_merge(source: Dict[str, Any], destination: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge source dictionary into destination dictionary."""
    for key, value in source.items():
        if isinstance(value, dict) and key in destination and isinstance(destination[key], dict):
            destination[key] = deep_merge(value, destination[key])
        else:
            destination[key] = value
    return destination


def load_config(config_path: str = "config/config.yaml") -> Dict[str, Any]:
    """
    Load configuration from YAML file and merge with defaults.
    Ensures data directories exist.
    """
    config = dict(DEFAULT_CONFIG)
    path = Path(config_path)

    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            user_cfg = yaml.safe_load(f) or {}
            config = deep_merge(user_cfg, config)

    # Ensure required parent directories exist
    db_path = Path(config["system"]["db_path"])
    db_path.parent.mkdir(parents=True, exist_ok=True)

    siem_path = Path(config["system"]["siem_export_path"])
    siem_path.parent.mkdir(parents=True, exist_ok=True)

    model_path = Path(config["ml"]["model_weights_path"])
    model_path.parent.mkdir(parents=True, exist_ok=True)

    return config
