"""
Dataset Generation, Session-Level Splitting, and Persistent Storage for Home-Gateway NIDS.
Generates realistic overlapping behavioral distributions with temporal variation and noise.
Includes short-lived HTTP/API flows in benign data, stochastic low-rate evasion recon,
and independently generated evasion stress testing splits.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import numpy as np
import hashlib


FEATURE_NAMES = [
    "dst_port_count",
    "dst_ip_count",
    "syn_ratio",
    "syn_ack_ratio",
    "rst_ratio",
    "packet_rate",
    "byte_rate",
    "flow_duration_mean",
]
FEATURE_DIM = len(FEATURE_NAMES)


def generate_session_sequence(
    session_id: str,
    session_type: str,
    sequence_length: int = 10,
    rng: Optional[np.random.RandomState] = None,
) -> Tuple[np.ndarray, np.ndarray, float, str]:
    """
    Generates a temporal sequence (sequence_length x 8) for a distinct network session.
    """
    if rng is None:
        rng = np.random.RandomState()

    seq = np.zeros((sequence_length, FEATURE_DIM), dtype=np.float32)
    mask = np.ones((sequence_length,), dtype=np.float32)

    # Validity length (number of active historical windows)
    if session_type.startswith("stealth") or "evasion" in session_type:
        valid_len = rng.randint(max(4, sequence_length - 4), sequence_length + 1)
    else:
        valid_len = rng.randint(3, sequence_length + 1)

    start_t = sequence_length - valid_len
    mask[:start_t] = 0.0

    label = 0.0

    # -------------------------------------------------------------
    # BENIGN SESSION PROFILES
    # -------------------------------------------------------------
    if session_type == "benign_browse":
        label = 0.0
        for t in range(start_t, sequence_length):
            dst_ports = max(1.0, rng.normal(3.5, 1.5))
            dst_ips = max(1.0, rng.normal(2.0, 0.8))
            syn_ratio = np.clip(rng.normal(0.12, 0.05), 0.02, 0.32)
            syn_ack = np.clip(rng.normal(0.14, 0.06), 0.02, 0.35)
            rst_ratio = np.clip(rng.exponential(0.01), 0.0, 0.05)
            pkt_rate = max(0.1, rng.normal(8.0, 5.0))
            byte_rate = max(100.0, rng.normal(8000.0, 6000.0))
            # Log-normal flow duration covering short (0.3s) and long (20s) connections
            mean_dur = float(np.clip(np.exp(rng.normal(1.8, 0.8)), 0.2, 35.0))
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    elif session_type == "benign_short_flows":
        # Realistic short HTTP/DNS/API request-response lifecycles (mean_dur 0.1s - 1.5s)
        # Prevents false positives on lab PCAPs where connections terminate quickly
        label = 0.0
        for t in range(start_t, sequence_length):
            dst_ports = max(1.0, rng.normal(2.0, 0.8))
            dst_ips = max(1.0, rng.normal(2.5, 1.0))
            syn_ratio = np.clip(rng.normal(0.10, 0.04), 0.02, 0.22)
            syn_ack = np.clip(rng.normal(0.11, 0.04), 0.02, 0.25)
            rst_ratio = np.clip(rng.exponential(0.005), 0.0, 0.03)
            pkt_rate = max(0.05, rng.normal(0.8, 0.4))
            byte_rate = max(30.0, rng.normal(120.0, 60.0))
            mean_dur = float(np.clip(rng.uniform(0.15, 1.2), 0.05, 2.0))
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    elif session_type == "benign_heavy":
        # Multi-tab browsing, developer packages, video streaming
        label = 0.0
        for t in range(start_t, sequence_length):
            dst_ports = max(3.0, rng.normal(10.0, 4.0))  # High port diversity
            dst_ips = max(1.0, rng.normal(5.0, 2.0))
            syn_ratio = np.clip(rng.normal(0.09, 0.04), 0.01, 0.24)
            syn_ack = np.clip(rng.normal(0.10, 0.04), 0.01, 0.26)
            rst_ratio = np.clip(rng.exponential(0.015), 0.0, 0.05)
            pkt_rate = max(5.0, rng.normal(40.0, 18.0))
            byte_rate = max(2000.0, rng.normal(90000.0, 45000.0))
            mean_dur = max(1.0, rng.normal(20.0, 10.0))
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    elif session_type == "benign_idle":
        label = 0.0
        for t in range(start_t, sequence_length):
            dst_ports = float(rng.choice([0, 1, 2], p=[0.4, 0.5, 0.1]))
            dst_ips = max(1.0, dst_ports)
            syn_ratio = 0.08 if dst_ports > 0 else 0.0
            syn_ack = 0.08 if dst_ports > 0 else 0.0
            rst_ratio = 0.0
            pkt_rate = max(0.01, rng.uniform(0.02, 0.5))
            byte_rate = max(10.0, rng.uniform(40.0, 300.0))
            mean_dur = max(0.05, rng.uniform(0.2, 2.0))
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    # -------------------------------------------------------------
    # RECONNAISSANCE PROFILES (Standard Training / Validation / Test)
    # -------------------------------------------------------------
    elif session_type == "fast_scan":
        label = 1.0
        scan_start_t = rng.randint(max(start_t, sequence_length - 3), sequence_length)
        for t in range(start_t, sequence_length):
            if t >= scan_start_t:
                dst_ports = max(15.0, rng.normal(55.0, 20.0))
                dst_ips = max(1.0, rng.normal(2.0, 1.0))
                syn_ratio = np.clip(rng.normal(0.88, 0.06), 0.70, 1.0)
                syn_ack = np.clip(rng.normal(12.0, 6.0), 3.0, 45.0)
                rst_ratio = np.clip(rng.normal(0.25, 0.10), 0.05, 0.65)
                pkt_rate = max(10.0, rng.normal(40.0, 18.0))
                byte_rate = max(400.0, rng.normal(2800.0, 1400.0))
                mean_dur = max(0.001, rng.uniform(0.01, 0.25))
            else:
                dst_ports = max(1.0, rng.normal(2.0, 1.0))
                dst_ips = 1.0
                syn_ratio = 0.10
                syn_ack = 0.10
                rst_ratio = 0.01
                pkt_rate = 2.0
                byte_rate = 1000.0
                mean_dur = 4.0
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    elif session_type == "stealth_scan":
        label = 1.0
        for t in range(start_t, sequence_length):
            dst_ports = max(1.0, rng.normal(3.2, 1.2))
            dst_ips = 1.0
            syn_ratio = np.clip(rng.normal(0.80, 0.08), 0.58, 0.98)
            syn_ack = np.clip(rng.normal(5.0, 2.5), 1.8, 22.0)
            rst_ratio = np.clip(rng.normal(0.18, 0.09), 0.02, 0.45)
            pkt_rate = max(0.05, rng.normal(0.5, 0.25))
            byte_rate = max(25.0, rng.normal(140.0, 70.0))
            mean_dur = max(0.01, rng.uniform(0.05, 0.5))
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    elif session_type == "randomized_scan":
        label = 1.0
        for t in range(start_t, sequence_length):
            dst_ports = max(2.0, rng.normal(5.0, 2.0))
            dst_ips = max(2.0, rng.normal(3.5, 1.2))
            syn_ratio = np.clip(rng.normal(0.78, 0.09), 0.52, 0.98)
            syn_ack = np.clip(rng.normal(4.5, 2.0), 1.5, 18.0)
            rst_ratio = np.clip(rng.normal(0.15, 0.07), 0.02, 0.35)
            pkt_rate = max(0.1, rng.normal(1.0, 0.5))
            byte_rate = max(40.0, rng.normal(260.0, 120.0))
            mean_dur = max(0.01, rng.uniform(0.05, 0.6))
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    # -------------------------------------------------------------
    # EVASION STRESS TEST PROFILES (Strictly Unseen Distributions)
    # -------------------------------------------------------------
    elif session_type == "evasion_recon_stochastic":
        # Attacker probes with stochastic Poisson/geometric intervals and variable jitter
        label = 1.0
        # Randomly choose active probe windows (probability 0.4 to 0.7 per window)
        probe_prob = rng.uniform(0.35, 0.65)
        for t in range(start_t, sequence_length):
            if rng.rand() < probe_prob:
                # Active stealth probe window
                dst_ports = max(1.0, rng.normal(2.2, 1.0))
                dst_ips = 1.0 if rng.rand() > 0.3 else 2.0
                syn_ratio = np.clip(rng.normal(0.72, 0.12), 0.48, 0.95)
                syn_ack = max(1.5, rng.exponential(3.0))
                rst_ratio = np.clip(rng.uniform(0.05, 0.35), 0.01, 0.50)
                pkt_rate = max(0.02, rng.uniform(0.03, 0.8))
                byte_rate = max(20.0, rng.uniform(40.0, 300.0))
                mean_dur = max(0.02, rng.uniform(0.04, 0.8))
            else:
                # Stochastic background browsing / idle in non-probe window
                dst_ports = max(1.0, rng.normal(2.5, 1.0))
                dst_ips = 1.0
                syn_ratio = np.clip(rng.normal(0.11, 0.04), 0.02, 0.25)
                syn_ack = np.clip(rng.normal(0.12, 0.05), 0.02, 0.28)
                rst_ratio = 0.01
                pkt_rate = max(0.1, rng.normal(2.5, 1.2))
                byte_rate = max(100.0, rng.normal(1800.0, 900.0))
                mean_dur = max(0.2, rng.normal(6.0, 3.0))
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    elif session_type == "evasion_recon_low_syn":
        # Low SYN-ratio decoy probes (attacker intersperses established connections to lower syn_ratio)
        label = 1.0
        for t in range(start_t, sequence_length):
            dst_ports = max(2.0, rng.normal(4.0, 1.5))
            dst_ips = max(1.0, rng.normal(2.0, 0.8))
            # SYN ratio depressed into ambiguous 0.40 - 0.65 zone!
            syn_ratio = np.clip(rng.normal(0.52, 0.08), 0.35, 0.68)
            syn_ack = np.clip(rng.normal(2.2, 1.0), 1.1, 8.0)
            rst_ratio = np.clip(rng.uniform(0.05, 0.25), 0.01, 0.40)
            pkt_rate = max(0.2, rng.normal(1.5, 0.8))
            byte_rate = max(80.0, rng.normal(500.0, 250.0))
            mean_dur = max(0.05, rng.uniform(0.1, 1.5))
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    elif session_type == "hard_benign_dev_burst":
        # Developer tool / microservice polling / rapid API queries: high port diversity, short durations, but valid ACKs
        label = 0.0
        for t in range(start_t, sequence_length):
            dst_ports = max(8.0, rng.normal(22.0, 7.0))  # High ports
            dst_ips = max(2.0, rng.normal(5.0, 2.0))
            syn_ratio = np.clip(rng.normal(0.26, 0.07), 0.12, 0.45)  # Moderate SYN ratio
            syn_ack = np.clip(rng.normal(0.28, 0.08), 0.12, 0.50)
            rst_ratio = np.clip(rng.exponential(0.02), 0.0, 0.08)
            pkt_rate = max(8.0, rng.normal(35.0, 15.0))
            byte_rate = max(2000.0, rng.normal(35000.0, 18000.0))
            mean_dur = float(np.clip(rng.uniform(0.2, 1.8), 0.05, 3.0))  # Short flows
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    elif session_type == "hard_benign_intermittent":
        # Intermittent smart home / IoT device bursts
        label = 0.0
        for t in range(start_t, sequence_length):
            if rng.rand() < 0.5:
                dst_ports = max(1.0, rng.normal(3.0, 1.0))
                dst_ips = 1.0
                syn_ratio = np.clip(rng.normal(0.15, 0.06), 0.03, 0.30)
                syn_ack = np.clip(rng.normal(0.16, 0.06), 0.03, 0.32)
                rst_ratio = 0.01
                pkt_rate = max(0.1, rng.normal(1.2, 0.6))
                byte_rate = max(50.0, rng.normal(400.0, 200.0))
                mean_dur = max(0.1, rng.uniform(0.2, 1.5))
            else:
                dst_ports = 0.0
                dst_ips = 0.0
                syn_ratio = 0.0
                syn_ack = 0.0
                rst_ratio = 0.0
                pkt_rate = 0.0
                byte_rate = 0.0
                mean_dur = 0.0
            seq[t] = [dst_ports, dst_ips, syn_ratio, syn_ack, rst_ratio, pkt_rate, byte_rate, mean_dur]

    return seq, mask, label, session_id


def build_and_save_persistent_datasets(
    output_dir: str = "data/processed",
    seed: int = 42,
) -> Dict[str, Dict[str, Any]]:
    """
    Constructs persistent session-isolated dataset splits:
    1. train.npz
    2. val.npz
    3. test.npz
    4. evasion_stress_test.npz (independently parameterized)
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    rng = np.random.RandomState(seed)

    splits_config = {
        "train": {
            "benign_browse": 700,
            "benign_short_flows": 500,
            "benign_heavy": 300,
            "benign_idle": 300,
            "fast_scan": 600,
            "stealth_scan": 600,
            "randomized_scan": 300,
        },
        "val": {
            "benign_browse": 150,
            "benign_short_flows": 120,
            "benign_heavy": 80,
            "benign_idle": 80,
            "fast_scan": 150,
            "stealth_scan": 150,
            "randomized_scan": 80,
        },
        "test": {
            "benign_browse": 220,
            "benign_short_flows": 180,
            "benign_heavy": 100,
            "benign_idle": 100,
            "fast_scan": 200,
            "stealth_scan": 200,
            "randomized_scan": 100,
        },
        "evasion_stress_test": {
            "hard_benign_dev_burst": 200,
            "hard_benign_intermittent": 200,
            "evasion_recon_stochastic": 250,
            "evasion_recon_low_syn": 150,
        }
    }

    results = {}

    for split_name, counts in splits_config.items():
        X_list, mask_list, y_list, sess_list = [], [], [], []
        session_counter = 0

        for stype, num in counts.items():
            for i in range(num):
                # Generate opaque session ID without encoding class labels into string
                h = hashlib.sha256(f"{split_name}_{stype}_{session_counter}_{i}".encode()).hexdigest()[:12]
                sess_id = f"sess_{h}"
                session_counter += 1
                seq, mask, label, sid = generate_session_sequence(sess_id, stype, sequence_length=10, rng=rng)
                X_list.append(seq)
                mask_list.append(mask)
                y_list.append(label)
                sess_list.append(sid)

        X_arr = np.array(X_list, dtype=np.float32)
        mask_arr = np.array(mask_list, dtype=np.float32)
        y_arr = np.array(y_list, dtype=np.float32)
        sess_arr = np.array(sess_list)

        # Shuffle deterministically within split
        idx = rng.permutation(len(y_arr))
        X_arr, mask_arr, y_arr, sess_arr = X_arr[idx], mask_arr[idx], y_arr[idx], sess_arr[idx]

        save_file = out_path / f"{split_name}.npz"
        np.savez_compressed(
            save_file,
            X=X_arr,
            mask=mask_arr,
            y=y_arr,
            session_ids=sess_arr,
        )
        print(f"[+] Saved persistent dataset {save_file}: N = {len(y_arr)} (Positives: {int(y_arr.sum())}, Negatives: {int(len(y_arr) - y_arr.sum())})")
        results[split_name] = {
            "path": str(save_file),
            "total_samples": len(y_arr),
            "positive_samples": int(y_arr.sum()),
            "negative_samples": int(len(y_arr) - y_arr.sum()),
        }

    return results


def load_persistent_split(split_name: str, data_dir: str = "data/processed") -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Load pre-saved split."""
    file_path = Path(data_dir) / f"{split_name}.npz"
    if not file_path.exists():
        build_and_save_persistent_datasets(output_dir=data_dir)
    data = np.load(file_path, allow_pickle=True)
    return data["X"], data["mask"], data["y"], data["session_ids"]


try:
    import torch
    from torch.utils.data import Dataset

    class ReconDataset(Dataset):
        """PyTorch Dataset wrapper."""
        def __init__(self, X: np.ndarray, mask: np.ndarray, y: np.ndarray):
            self.X = torch.tensor(X, dtype=torch.float32)
            self.mask = torch.tensor(mask, dtype=torch.float32)
            self.y = torch.tensor(y, dtype=torch.float32).unsqueeze(-1)

        def __len__(self) -> int:
            return len(self.y)

        def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
            return self.X[idx], self.mask[idx], self.y[idx]

except ImportError:
    ReconDataset = None  # type: ignore
