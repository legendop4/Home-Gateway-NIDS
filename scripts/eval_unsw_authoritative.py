"""
Independent Authoritative Evaluation Script for models/transformer_recon_unsw.pt
Evaluates strictly on held-out test.npz without modifying model or dataset.
"""

from pathlib import Path
import hashlib
import json
import numpy as np
import torch
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score, precision_recall_curve, auc

from nids.ml.transformer_model import ReconTransformer, compute_calibration_metrics


def compute_sha256(file_path: Path) -> str:
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


def evaluate_authoritative():
    model_path = Path("models/transformer_recon_unsw.pt")
    test_path = Path("data/processed_unsw/test.npz")
    train_path = Path("data/processed_unsw/train.npz")

    if not model_path.exists():
        raise FileNotFoundError(f"Model not found at {model_path}")
    if not test_path.exists():
        raise FileNotFoundError(f"Test dataset not found at {test_path}")

    model_hash = compute_sha256(model_path)
    test_hash = compute_sha256(test_path)
    train_hash = compute_sha256(train_path)

    # 1. Load Data
    train_npz = np.load(train_path)
    test_npz = np.load(test_path)

    X_train = train_npz["X"]
    X_test, mask_test, y_test = test_npz["X"], test_npz["mask"], test_npz["y"]

    # In production, features from WindowSequencer are passed directly to ReconTransformer
    X_test_input = X_test

    # 2. Load Model
    device = torch.device("cpu")
    state_dict = torch.load(model_path, map_location=device, weights_only=True)
    
    model = ReconTransformer(
        feature_dim=8,
        sequence_length=10,
        d_model=32,
        nhead=4,
        num_layers=2,
    ).to(device)
    model.load_state_dict(state_dict)
    model.eval()

    cal_temperature = float(model.temperature_scaler.temperature.item())

    # 3. Run Inference
    with torch.no_grad():
        x_tensor = torch.tensor(X_test_input, dtype=torch.float32, device=device)
        mask_tensor = torch.tensor(mask_test, dtype=torch.float32, device=device)
        probs = model(x_tensor, mask_tensor, calibrate=True).cpu().numpy().flatten()
        raw_probs = model(x_tensor, mask_tensor, calibrate=False).cpu().numpy().flatten()

    y_true = y_test.flatten().astype(int)

    # Evaluate at multiple decision thresholds
    thresholds = [0.50, 0.70]
    results_by_thresh = {}

    roc_auc = float(roc_auc_score(y_true, probs))
    p_curve, r_curve, _ = precision_recall_curve(y_true, probs)
    pr_auc = float(auc(r_curve, p_curve))
    cal_metrics = compute_calibration_metrics(probs, y_true)

    for th in thresholds:
        y_pred = (probs >= th).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
        prec = float(precision_score(y_true, y_pred, zero_division=0))
        rec = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))
        acc = float((tp + tn) / len(y_true))
        fpr = float(fp / (fp + tn + 1e-6))

        results_by_thresh[f"threshold_{th:.2f}"] = {
            "threshold": th,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "confusion_matrix": {
                "true_negatives": int(tn),
                "false_positives": int(fp),
                "false_negatives": int(fn),
                "true_positives": int(tp),
            }
        }

    report = {
        "model_path": str(model_path),
        "model_sha256": model_hash,
        "test_dataset_path": str(test_path),
        "test_dataset_sha256": test_hash,
        "train_dataset_sha256": train_hash,
        "total_test_sequences": len(y_true),
        "recon_class_count": int(np.sum(y_true == 1)),
        "normal_class_count": int(np.sum(y_true == 0)),
        "calibration_temperature": cal_temperature,
        "brier_score": cal_metrics["brier_score"],
        "expected_calibration_error": cal_metrics["expected_calibration_error"],
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "evaluations": results_by_thresh,
    }

    print("==========================================================")
    print("AUTHORITATIVE RE-EVALUATION REPORT")
    print("==========================================================")
    print(json.dumps(report, indent=2))
    
    with open("data/authoritative_unsw_evaluation_report.json", "w") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    evaluate_authoritative()
