"""
Scientifically Defensible Evaluation and Ablation Benchmark for Home-Gateway NIDS.
Measures:
1. Primary Benchmark on Persistent Held-Out Synthetic Test Set (test.npz)
   - Heuristic Rule Baseline
   - Logistic Regression
   - Transformer 1x8 (Single-Window)
   - Transformer 5x8 (Five-Window)
   - Transformer 10x8 (Ten-Window Full Sequence)
2. Validated Temporal Context Ablation (Independently Trained 1x8 vs 5x8 vs 10x8)
3. Feature Ablation (SYN-Ratio Only vs Non-Temporal All vs Full 10x8)
4. Independent Evasion Stress Test (evasion_stress_test.npz)
5. Lab PCAP Packet Replay Evaluation (Explicitly identifies REAL_SURICATA vs OFFLINE_RULE_ENGINE)
6. Probability Calibration Metrics (Brier Score & ECE)
7. Empirical Latency Profiling (wall clock, p50, p95, sample counts)
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json
import time
import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import joblib

try:
    import torch
    from .transformer_model import ReconTransformer, TransformerInferenceEngine, compute_calibration_metrics
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from .dataset import load_persistent_split
from .baseline_detector import BaselineReconDetector, HeuristicReconDetector
from .pcap_parser import parse_pcap_to_sequences
from ..capture.suricata_evaluator import (
    OfflineSuricataEngine,
    run_suricata_on_pcap,
    get_suricata_execution_mode,
    SURICATA_MODE_REAL,
    SURICATA_MODE_OFFLINE,
)


def measure_latency_distribution(
    predict_fn,
    samples: List[Tuple[np.ndarray, Optional[np.ndarray]]],
    n_warmup: int = 50,
    n_runs: int = 1000,
) -> Dict[str, float]:
    """
    Measures high-resolution inference latency with statistical percentiles.
    """
    n_samples = len(samples)
    if n_samples == 0:
        return {"sample_count": 0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0}

    # Warm-up
    for i in range(min(n_warmup, n_samples)):
        s, m = samples[i % n_samples]
        _ = predict_fn(s, m)

    latencies_ns = []
    for i in range(n_runs):
        s, m = samples[i % n_samples]
        t0 = time.perf_counter_ns()
        _ = predict_fn(s, m)
        t1 = time.perf_counter_ns()
        latencies_ns.append(t1 - t0)

    latencies_ms = np.array(latencies_ns) / 1e6
    return {
        "sample_count": n_runs,
        "mean_ms": float(round(float(np.mean(latencies_ms)), 4)),
        "p50_ms": float(round(float(np.percentile(latencies_ms, 50)), 4)),
        "p95_ms": float(round(float(np.percentile(latencies_ms, 95)), 4)),
    }


def compute_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_probs: Optional[np.ndarray] = None,
    latency_dict: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    y_true = np.array(y_true, dtype=int).flatten()
    y_pred = np.array(y_pred, dtype=int).flatten()

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = fp / (fp + tn + 1e-6)
    acc = (tp + tn) / (tp + tn + fp + fn + 1e-6)

    res: Dict[str, Any] = {
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "accuracy": float(round(acc, 4)),
        "precision": float(round(precision, 4)),
        "recall": float(round(recall, 4)),
        "f1_score": float(round(f1, 4)),
        "false_positive_rate": float(round(fpr, 4)),
    }

    if latency_dict is not None:
        res["sample_count"] = latency_dict.get("sample_count", 0)
        res["latency_mean_ms"] = latency_dict.get("mean_ms", 0.0)
        res["latency_p50_ms"] = latency_dict.get("p50_ms", 0.0)
        res["latency_p95_ms"] = latency_dict.get("p95_ms", 0.0)

    if y_probs is not None:
        cal = compute_calibration_metrics(y_probs, y_true)
        res["brier_score"] = cal["brier_score"]
        res["expected_calibration_error"] = cal["expected_calibration_error"]

    return res


def evaluate_all(
    models_dir: str = "models",
    threshold: float = 0.70,
    data_dir: str = "data/processed",
    pcap_dir: str = "data/pcaps",
    output_report_path: str = "data/evaluation_report.json",
) -> Dict[str, Any]:
    """
    Executes full multi-dimensional evaluation suite with strict separation of synthetic vs PCAP benchmarks.
    """
    print("=" * 90)
    print("        HOME-GATEWAY NIDS: RECONNAISSANCE SCIENTIFIC BENCHMARK")
    print("=" * 90)

    m_dir = Path(models_dir)

    # 1. Load persistent held-out test split (test.npz)
    X_test, mask_test, y_test, sess_test = load_persistent_split("test", data_dir=data_dir)
    print(f"\n[+] Loaded Persistent Held-Out Test Set (test.npz): N = {len(y_test)} (Recon: {int(y_test.sum())}, Benign: {int(len(y_test)-y_test.sum())})")

    suricata_mode = get_suricata_execution_mode()
    print(f"[+] Suricata Engine Available: {suricata_mode}")

    results: Dict[str, Any] = {
        "meta": {
            "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "decision_threshold": threshold,
            "suricata_execution_mode": suricata_mode,
            "test_samples_total": len(y_test),
            "test_recon_samples": int(y_test.sum()),
            "test_benign_samples": int(len(y_test) - y_test.sum()),
        },
        "synthetic_benchmark": {},
        "temporal_ablation": {},
        "feature_ablation": {},
        "evasion_stress_test": {},
        "lab_pcap_evaluation": {},
    }

    # -------------------------------------------------------------
    # 1. Heuristic Rule Baseline (Evaluated on Sequence Features)
    # -------------------------------------------------------------
    heuristic = HeuristicReconDetector()
    h_samples = [(X_test[i], mask_test[i]) for i in range(len(X_test))]
    h_lat = measure_latency_distribution(lambda s, m: heuristic.score_sequence(s, m), h_samples, n_runs=1000)
    h_probs = [heuristic.score_sequence(X_test[i], mask_test[i]) for i in range(len(X_test))]
    h_preds = [1 if s >= threshold else 0 for s in h_probs]
    results["synthetic_benchmark"]["Heuristic_Rule_Detector"] = compute_metrics(y_test, np.array(h_preds), np.array(h_probs), h_lat)

    # -------------------------------------------------------------
    # 2. Baseline Logistic Regression (Trained on 10x8 flattened)
    # -------------------------------------------------------------
    baseline_file = m_dir / "baseline_model.joblib"
    if baseline_file.exists():
        baseline: BaselineReconDetector = joblib.load(str(baseline_file))
        b_samples = [(X_test[i:i+1], None) for i in range(len(X_test))]
        b_lat = measure_latency_distribution(lambda s, _: baseline.predict_proba(s), b_samples, n_runs=2000)
        b_probs = baseline.predict_proba(X_test)
        b_preds = (b_probs >= threshold).astype(int)
        results["synthetic_benchmark"]["Baseline_Logistic_Regression"] = compute_metrics(y_test, b_preds, b_probs, b_lat)
    else:
        results["synthetic_benchmark"]["Baseline_Logistic_Regression"] = {"status": "CHECKPOINT_MISSING"}

    # -------------------------------------------------------------
    # 3. Model A: Independently Trained Single-Window Model (1x8)
    # -------------------------------------------------------------
    engine_1w = TransformerInferenceEngine(weights_path=str(m_dir / "transformer_1x8.pt"))
    if engine_1w.is_available:
        X_test_1w = X_test[:, -1:, :]
        mask_test_1w = mask_test[:, -1:]
        samples_1w = [(X_test_1w[i], mask_test_1w[i]) for i in range(len(X_test))]
        lat_1w = measure_latency_distribution(lambda s, m: engine_1w.predict_score(s, m, calibrate=True), samples_1w, n_runs=1000)
        probs_1w = [engine_1w.predict_score(X_test_1w[i], mask_test_1w[i], calibrate=True) for i in range(len(X_test))]
        preds_1w = [1 if s >= threshold else 0 for s in probs_1w]
        res_1w = compute_metrics(y_test, np.array(preds_1w), np.array(probs_1w), lat_1w)
        results["temporal_ablation"]["Transformer_1x8_SingleWindow"] = res_1w
        results["synthetic_benchmark"]["Transformer_1x8"] = res_1w

    # -------------------------------------------------------------
    # 4. Model B: Independently Trained 5-Window Model (5x8)
    # -------------------------------------------------------------
    engine_5w = TransformerInferenceEngine(weights_path=str(m_dir / "transformer_5x8.pt"))
    if engine_5w.is_available:
        X_test_5w = X_test[:, -5:, :]
        mask_test_5w = mask_test[:, -5:]
        samples_5w = [(X_test_5w[i], mask_test_5w[i]) for i in range(len(X_test))]
        lat_5w = measure_latency_distribution(lambda s, m: engine_5w.predict_score(s, m, calibrate=True), samples_5w, n_runs=1000)
        probs_5w = [engine_5w.predict_score(X_test_5w[i], mask_test_5w[i], calibrate=True) for i in range(len(X_test))]
        preds_5w = [1 if s >= threshold else 0 for s in probs_5w]
        res_5w = compute_metrics(y_test, np.array(preds_5w), np.array(probs_5w), lat_5w)
        results["temporal_ablation"]["Transformer_5x8_FiveWindow"] = res_5w
        results["synthetic_benchmark"]["Transformer_5x8"] = res_5w

    # -------------------------------------------------------------
    # 5. Model C: Independently Trained 10-Window Sequence Transformer (10x8)
    # -------------------------------------------------------------
    engine_10w = TransformerInferenceEngine(weights_path=str(m_dir / "transformer_10x8.pt"))
    if engine_10w.is_available:
        samples_10w = [(X_test[i], mask_test[i]) for i in range(len(X_test))]
        lat_10w = measure_latency_distribution(lambda s, m: engine_10w.predict_score(s, m, calibrate=True), samples_10w, n_runs=1000)
        probs_10w = [engine_10w.predict_score(X_test[i], mask_test[i], calibrate=True) for i in range(len(X_test))]
        preds_10w = [1 if s >= threshold else 0 for s in probs_10w]
        res_10w = compute_metrics(y_test, np.array(preds_10w), np.array(probs_10w), lat_10w)
        results["temporal_ablation"]["Transformer_10x8_TenWindow"] = res_10w
        results["synthetic_benchmark"]["Transformer_10x8"] = res_10w

    # -------------------------------------------------------------
    # 6. Feature Ablation (SYN-Ratio Only vs Non-Temporal All vs Full 10x8)
    # -------------------------------------------------------------
    if engine_10w.is_available:
        X_test_syn_only = np.zeros_like(X_test)
        X_test_syn_only[:, :, 2] = X_test[:, :, 2]  # Feature 2 = syn_ratio
        probs_syn = [engine_10w.predict_score(X_test_syn_only[i], mask_test[i], calibrate=True) for i in range(len(X_test))]
        preds_syn = [1 if s >= threshold else 0 for s in probs_syn]
        results["feature_ablation"]["SYN_Ratio_Only"] = compute_metrics(y_test, np.array(preds_syn), np.array(probs_syn))
        results["feature_ablation"]["Non_Temporal_All_Features (1x8)"] = results["temporal_ablation"].get("Transformer_1x8_SingleWindow", {})
        results["feature_ablation"]["Full_10x8_Temporal_Sequence"] = results["temporal_ablation"].get("Transformer_10x8_TenWindow", {})

    # -------------------------------------------------------------
    # 7. Independent Evasion Stress Test (evasion_stress_test.npz)
    # -------------------------------------------------------------
    print("\n--- Running Independent Evasion Stress Test (evasion_stress_test.npz) ---")
    try:
        X_ev, mask_ev, y_ev, sess_ev = load_persistent_split("evasion_stress_test", data_dir=data_dir)
        print(f"[+] Loaded Evasion Stress Test: N = {len(y_ev)} (Pos: {int(y_ev.sum())}, Neg: {int(len(y_ev)-y_ev.sum())})")

        # Baseline on Evasion
        if baseline_file.exists():
            ev_b_probs = baseline.predict_proba(X_ev)
            ev_b_preds = (ev_b_probs >= threshold).astype(int)
            results["evasion_stress_test"]["Baseline_Logistic_Regression"] = compute_metrics(y_ev, ev_b_preds, ev_b_probs)

        # 1x8 on Evasion
        if engine_1w.is_available:
            X_ev_1w = X_ev[:, -1:, :]
            mask_ev_1w = mask_ev[:, -1:]
            ev_1w_probs = [engine_1w.predict_score(X_ev_1w[i], mask_ev_1w[i], calibrate=True) for i in range(len(X_ev))]
            ev_1w_preds = [1 if s >= threshold else 0 for s in ev_1w_probs]
            results["evasion_stress_test"]["Transformer_1x8"] = compute_metrics(y_ev, np.array(ev_1w_preds), np.array(ev_1w_probs))

        # 5x8 on Evasion
        if engine_5w.is_available:
            X_ev_5w = X_ev[:, -5:, :]
            mask_ev_5w = mask_ev[:, -5:]
            ev_5w_probs = [engine_5w.predict_score(X_ev_5w[i], mask_ev_5w[i], calibrate=True) for i in range(len(X_ev))]
            ev_5w_preds = [1 if s >= threshold else 0 for s in ev_5w_probs]
            results["evasion_stress_test"]["Transformer_5x8"] = compute_metrics(y_ev, np.array(ev_5w_preds), np.array(ev_5w_probs))

        # 10x8 on Evasion
        if engine_10w.is_available:
            ev_10w_probs = [engine_10w.predict_score(X_ev[i], mask_ev[i], calibrate=True) for i in range(len(X_ev))]
            ev_10w_preds = [1 if s >= threshold else 0 for s in ev_10w_probs]
            results["evasion_stress_test"]["Transformer_10x8"] = compute_metrics(y_ev, np.array(ev_10w_preds), np.array(ev_10w_probs))

    except Exception as e:
        print(f"[-] Evasion stress test error: {e}")

    # -------------------------------------------------------------
    # 8. Lab PCAP Captures Evaluation (Actual Packet-Level Stream Processing)
    # -------------------------------------------------------------
    print(f"\n--- Running Lab PCAP Evaluation ({suricata_mode}) ---")
    pcap_dir_path = Path(pcap_dir)
    pcap_ground_truth = {
        "lab_benign.pcap": 0,
        "lab_fast_scan.pcap": 1,
        "lab_stealth_scan.pcap": 1,
    }

    pcap_y_true = []
    pcap_suricata_preds = []
    pcap_tf_preds = []
    pcap_hybrid_preds = []
    pcap_details = {}
    pcap_latencies = []

    if pcap_dir_path.exists():
        for pcap_name, gt_label in pcap_ground_truth.items():
            pcap_file = pcap_dir_path / pcap_name
            if not pcap_file.exists():
                continue

            # Run deterministic engine on packet stream
            suricata_alerts, mode_used, suricata_lat = run_suricata_on_pcap(str(pcap_file))
            suricata_detected = int(len(suricata_alerts) > 0)
            if "mean_ms" in suricata_lat and suricata_lat["mean_ms"] > 0:
                pcap_latencies.append(suricata_lat["mean_ms"])

            # Run sequence extraction and Transformer on same PCAP
            seqs_by_ip = parse_pcap_to_sequences(str(pcap_file))
            tf_detected = 0
            max_tf_score = 0.0
            for ip, seq_list in seqs_by_ip.items():
                for seq, mask in seq_list:
                    if engine_10w.is_available:
                        score = engine_10w.predict_score(seq, mask, calibrate=True)
                        max_tf_score = max(max_tf_score, score)
                        if score >= threshold:
                            tf_detected = 1

            hybrid_detected = int(suricata_detected or tf_detected)

            pcap_y_true.append(gt_label)
            pcap_suricata_preds.append(suricata_detected)
            pcap_tf_preds.append(tf_detected)
            pcap_hybrid_preds.append(hybrid_detected)

            pcap_details[pcap_name] = {
                "ground_truth": "RECON" if gt_label == 1 else "BENIGN",
                "engine_mode": mode_used,
                "suricata_alert_count": len(suricata_alerts),
                "suricata_detected": bool(suricata_detected),
                "suricata_latency": suricata_lat,
                "transformer_max_score": round(max_tf_score, 4),
                "transformer_detected": bool(tf_detected),
                "hybrid_detected": bool(hybrid_detected),
                "suricata_signatures_triggered": list(set(a.signature for a in suricata_alerts)),
            }

    if pcap_y_true:
        pcap_lat_summary = {
            "sample_count": len(pcap_latencies),
            "mean_ms": float(round(float(np.mean(pcap_latencies)), 4)) if pcap_latencies else 0.0,
            "p50_ms": float(round(float(np.median(pcap_latencies)), 4)) if pcap_latencies else 0.0,
            "p95_ms": float(round(float(np.percentile(pcap_latencies, 95)), 4)) if pcap_latencies else 0.0,
        }
        results["lab_pcap_evaluation"] = {
            "engine_mode": suricata_mode,
            "per_file_breakdown": pcap_details,
            "suricata_pcap_metrics": compute_metrics(np.array(pcap_y_true), np.array(pcap_suricata_preds), latency_dict=pcap_lat_summary),
            "transformer_pcap_metrics": compute_metrics(np.array(pcap_y_true), np.array(pcap_tf_preds)),
            "hybrid_pcap_metrics": compute_metrics(np.array(pcap_y_true), np.array(pcap_hybrid_preds)),
        }

    # -------------------------------------------------------------
    # PRINT SUMMARY TABLES
    # -------------------------------------------------------------
    print("\n" + "=" * 105)
    print("                      CONTROLLED SYNTHETIC BENCHMARK (Held-Out test.npz)")
    print("=" * 105)
    print("{:<35} | {:<7} | {:<7} | {:<7} | {:<7} | {:<7} | {:<7} | {:<12}".format(
        "Detection Strategy", "Prec", "Recall", "F1", "FPR", "Brier", "ECE", "Latency(mean)"
    ))
    print("-" * 105)
    for model_name, m in results["synthetic_benchmark"].items():
        if "f1_score" in m:
            brier_str = f"{m.get('brier_score', 0):.4f}" if "brier_score" in m else "N/A"
            ece_str = f"{m.get('expected_calibration_error', 0):.4f}" if "expected_calibration_error" in m else "N/A"
            lat_str = f"{m.get('latency_mean_ms', 0):.4f} ms" if "latency_mean_ms" in m else "N/A"
            print("{:<35} | {:<7.4f} | {:<7.4f} | {:<7.4f} | {:<7.4f} | {:<7} | {:<7} | {:<12}".format(
                model_name, m["precision"], m["recall"], m["f1_score"], m["false_positive_rate"], brier_str, ece_str, lat_str
            ))

    print("\n" + "=" * 105)
    print("                               TEMPORAL ABLATION (test.npz)")
    print("=" * 105)
    print("{:<35} | {:<7} | {:<7} | {:<7} | {:<7} | {:<12}".format(
        "Model Variant", "Prec", "Recall", "F1", "FPR", "Latency(mean)"
    ))
    print("-" * 105)
    for model_name, m in results["temporal_ablation"].items():
        lat_str = f"{m.get('latency_mean_ms', 0):.4f} ms" if "latency_mean_ms" in m else "N/A"
        print("{:<35} | {:<7.4f} | {:<7.4f} | {:<7.4f} | {:<7.4f} | {:<12}".format(
            model_name, m["precision"], m["recall"], m["f1_score"], m["false_positive_rate"], lat_str
        ))

    print("\n" + "=" * 105)
    print("                        INDEPENDENT EVASION STRESS TEST (evasion_stress_test.npz)")
    print("=" * 105)
    print("{:<35} | {:<7} | {:<7} | {:<7} | {:<7}".format(
        "Model Variant", "Prec", "Recall", "F1", "FPR"
    ))
    print("-" * 105)
    for model_name, m in results["evasion_stress_test"].items():
        if "f1_score" in m:
            print("{:<35} | {:<7.4f} | {:<7.4f} | {:<7.4f} | {:<7.4f}".format(
                model_name, m["precision"], m["recall"], m["f1_score"], m["false_positive_rate"]
            ))

    print("\n" + "=" * 105)
    print(f"                               LAB PCAP EVALUATION ({suricata_mode})")
    print("=" * 105)
    for pcap_name, info in results.get("lab_pcap_evaluation", {}).get("per_file_breakdown", {}).items():
        print(f"  * {pcap_name} ({info['ground_truth']}):")
        print(f"      - {info['engine_mode']}: Detected = {info['suricata_detected']} (Alerts: {info['suricata_alert_count']})")
        print(f"      - Transformer (10x8): Detected = {info['transformer_detected']} (Max Score: {info['transformer_max_score']})")
        print(f"      - Hybrid Fusion: Detected = {info['hybrid_detected']}")

    # Save to report path
    out_p = Path(output_report_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with open(out_p, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Full evaluation report saved to {out_p.resolve()}")

    return results


if __name__ == "__main__":
    evaluate_all()
