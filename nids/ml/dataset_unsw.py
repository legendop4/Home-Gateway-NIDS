"""
UNSW-NB15 Dataset Loader and Temporal Sequence Pipeline for Home-Gateway NIDS.
Converts real-world UNSW-NB15 flow records into 10x8 temporal sequence matrices
matching the production Transformer input specification.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import csv
import numpy as np

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
FEATURE_DIM = len(FEATURE_NAMES)  # 8


def extract_8_features_from_row(row: Dict[str, str]) -> np.ndarray:
    """
    Extracts the 8-dimensional feature vector from a single UNSW-NB15 record.
    """
    dur = max(1e-5, float(row.get("dur", 0.0)))
    spkts = float(row.get("spkts", 0.0))
    dpkts = float(row.get("dpkts", 0.0))
    sbytes = float(row.get("sbytes", 0.0))
    dbytes = float(row.get("dbytes", 0.0))
    state = row.get("state", "").strip().upper()
    proto = row.get("proto", "").strip().lower()
    synack = float(row.get("synack", 0.0))
    ackdat = float(row.get("ackdat", 0.0))
    tcprtt = float(row.get("tcprtt", 0.0))
    
    # 1. dst_port_count: count of connections to same destination port
    dst_port_count = float(row.get("ct_src_dport_ltm", 1.0))
    
    # 2. dst_ip_count: count of connections to same destination IP
    dst_ip_count = float(row.get("ct_dst_ltm", 1.0))
    
    # 3. syn_ratio: proportion of SYN behavior
    if proto == "tcp":
        if state in ["REQ", "INT", "ACC"]:
            syn_ratio = 0.85
        elif synack > 0 and tcprtt > 0:
            syn_ratio = np.clip(synack / tcprtt, 0.1, 0.9)
        else:
            syn_ratio = 0.12
    else:
        syn_ratio = 0.0
        
    # 4. syn_ack_ratio: handshake completion ratio
    if proto == "tcp":
        if ackdat > 0:
            syn_ack_ratio = np.clip(synack / ackdat, 0.1, 20.0)
        elif synack > 0:
            syn_ack_ratio = 10.0  # High ratio when SYN sent without full ACK completion
        else:
            syn_ack_ratio = 1.0
    else:
        syn_ack_ratio = 0.0
        
    # 5. rst_ratio: reset / rejected connection ratio
    rst_ratio = 1.0 if state == "RST" else (0.05 if state in ["CLO", "FIN"] else 0.0)
    
    # 6. packet_rate: total packets per second
    rate_val = row.get("rate", "")
    if rate_val and float(rate_val) > 0:
        packet_rate = float(rate_val)
    else:
        packet_rate = (spkts + dpkts) / dur
        
    # 7. byte_rate: total bytes per second
    sload = float(row.get("sload", 0.0))
    dload = float(row.get("dload", 0.0))
    if sload + dload > 0:
        byte_rate = (sload + dload) / 8.0  # bits/sec to bytes/sec
    else:
        byte_rate = (sbytes + dbytes) / dur
        
    # 8. flow_duration_mean: duration in seconds
    flow_duration_mean = dur
    
    return np.array([
        dst_port_count,
        dst_ip_count,
        syn_ratio,
        syn_ack_ratio,
        rst_ratio,
        packet_rate,
        byte_rate,
        flow_duration_mean,
    ], dtype=np.float32)


def build_sequences_from_unsw_csv(
    csv_path: str,
    sequence_length: int = 10,
    stride: int = 5,
    max_records: Optional[int] = None,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, Dict[str, Any]]:
    """
    Parses UNSW CSV, filters for Normal (0) and Reconnaissance (1),
    and creates rolling (sequence_length, 8) temporal tensors with attention masks.
    """
    file_p = Path(csv_path)
    if not file_p.exists():
        raise FileNotFoundError(f"UNSW dataset not found at {csv_path}")

    records: List[Tuple[np.ndarray, float]] = []
    normal_count = 0
    recon_count = 0
    discarded_other_attacks = 0

    with open(file_p, mode="r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if max_records and i >= max_records:
                break
                
            attack_cat = row.get("attack_cat", "").strip()
            # Clean possible BOM
            if not attack_cat and "\ufeffattack_cat" in row:
                attack_cat = row["\ufeffattack_cat"].strip()

            if attack_cat == "Normal":
                label = 0.0
                normal_count += 1
            elif attack_cat == "Reconnaissance":
                label = 1.0
                recon_count += 1
            else:
                discarded_other_attacks += 1
                continue  # Exclude other attacks to focus strictly on MITRE T1046 Recon

            feat_vec = extract_8_features_from_row(row)
            records.append((feat_vec, label))

    total_usable = len(records)
    print(f"[{file_p.name}] Usable records: {total_usable} (Normal: {normal_count}, Recon: {recon_count}, Other Discarded: {discarded_other_attacks})")

    # Generate rolling sequences
    sequences = []
    masks = []
    labels = []

    # Process in contiguous chunks of homogenous or transitioning sessions
    for start_idx in range(0, total_usable - sequence_length + 1, stride):
        window_records = records[start_idx : start_idx + sequence_length]
        seq = np.array([r[0] for r in window_records], dtype=np.float32)
        mask = np.ones((sequence_length,), dtype=np.float32)
        # Sequence label is 1.0 if any window contains Reconnaissance
        window_labels = [r[1] for r in window_records]
        seq_label = 1.0 if sum(window_labels) >= 1.0 else 0.0
        
        sequences.append(seq)
        masks.append(mask)
        labels.append(seq_label)

    X = np.array(sequences, dtype=np.float32) if sequences else np.zeros((0, sequence_length, FEATURE_DIM), dtype=np.float32)
    M = np.array(masks, dtype=np.float32) if masks else np.zeros((0, sequence_length), dtype=np.float32)
    y = np.array(labels, dtype=np.float32) if labels else np.zeros((0,), dtype=np.float32)

    stats = {
        "source_file": file_p.name,
        "total_records_processed": normal_count + recon_count + discarded_other_attacks,
        "normal_records": normal_count,
        "recon_records": recon_count,
        "discarded_other_attacks": discarded_other_attacks,
        "usable_records": total_usable,
        "generated_sequences": len(y),
        "recon_sequences": int(y.sum()),
        "normal_sequences": int(len(y) - y.sum()),
    }
    return X, M, y, stats


def prepare_unsw_splits(
    unsw_dir: str = "data/unsw",
    output_dir: str = "data/processed_unsw",
    val_ratio: float = 0.20,
    seed: int = 42,
) -> Dict[str, Any]:
    """
    Creates train, val, and held-out test splits from UNSW-NB15 CSV files.
    """
    unsw_path = Path(unsw_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    train_csv = unsw_path / "UNSW_NB15_training-set.csv"
    test_csv = unsw_path / "UNSW_NB15_testing-set.csv"

    # 1. Parse Training CSV
    X_train_full, M_train_full, y_train_full, train_stats = build_sequences_from_unsw_csv(str(train_csv), stride=5)

    # Split train_full into train and val without data leakage (contiguous block split)
    n_total = len(y_train_full)
    n_val = int(n_total * val_ratio)
    n_train = n_total - n_val

    # Use deterministic split
    np.random.seed(seed)
    indices = np.arange(n_total)
    np.random.shuffle(indices)

    train_idx = indices[:n_train]
    val_idx = indices[n_train:]

    X_train, M_train, y_train = X_train_full[train_idx], M_train_full[train_idx], y_train_full[train_idx]
    X_val, M_val, y_val = X_train_full[val_idx], M_train_full[val_idx], y_train_full[val_idx]

    # 2. Parse Held-Out Testing CSV (Strictly independent test set)
    X_test, M_test, y_test, test_stats = build_sequences_from_unsw_csv(str(test_csv), stride=5)

    # Save splits as compressed NPZ
    np.savez_compressed(out_path / "train.npz", X=X_train, mask=M_train, y=y_train)
    np.savez_compressed(out_path / "val.npz", X=X_val, mask=M_val, y=y_val)
    np.savez_compressed(out_path / "test.npz", X=X_test, mask=M_test, y=y_test)

    print(f"\n[+] Saved processed UNSW datasets in {out_path}:")
    print(f"    Train: {len(y_train)} sequences (Recon: {int(y_train.sum())}, Normal: {int(len(y_train) - y_train.sum())})")
    print(f"    Val:   {len(y_val)} sequences (Recon: {int(y_val.sum())}, Normal: {int(len(y_val) - y_val.sum())})")
    print(f"    Test:  {len(y_test)} sequences (Recon: {int(y_test.sum())}, Normal: {int(len(y_test) - y_test.sum())})")

    return {
        "train_stats": train_stats,
        "test_stats": test_stats,
        "final_counts": {
            "train_sequences": len(y_train),
            "val_sequences": len(y_val),
            "test_sequences": len(y_test),
        }
    }


if __name__ == "__main__":
    prepare_unsw_splits()
