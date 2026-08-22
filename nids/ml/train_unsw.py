"""
Training and Evaluation Pipeline for Transformer on UNSW-NB15 Dataset.
Trains ReconTransformer on UNSW-NB15 10x8 sequences and outputs models/transformer_recon_unsw.pt.
Preserves existing synthetic models completely intact.
"""

from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import json

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader
    from .transformer_model import ReconTransformer, compute_calibration_metrics
    from .dataset import ReconDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

from .dataset_unsw import prepare_unsw_splits


def train_unsw_transformer(
    data_dir: str = "data/processed_unsw",
    output_model_path: str = "models/transformer_recon_unsw.pt",
    epochs: int = 25,
    batch_size: int = 128,
    lr: float = 1e-3,
    d_model: int = 32,
    num_layers: int = 2,
    seed: int = 42,
) -> Dict[str, Any]:
    if not TORCH_AVAILABLE:
        raise RuntimeError("PyTorch is not available.")

    torch.manual_seed(seed)
    np.random.seed(seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n--- Training UNSW-NB15 Transformer on {device} ---")

    data_path = Path(data_dir)
    train_npz = np.load(data_path / "train.npz")
    val_npz = np.load(data_path / "val.npz")
    test_npz = np.load(data_path / "test.npz")

    X_train, mask_train, y_train = train_npz["X"], train_npz["mask"], train_npz["y"]
    X_val, mask_val, y_val = val_npz["X"], val_npz["mask"], val_npz["y"]
    X_test, mask_test, y_test = test_npz["X"], test_npz["mask"], test_npz["y"]

    print(f"Train samples: {len(y_train)} (Pos: {int(y_train.sum())}, Neg: {int(len(y_train)-y_train.sum())})")
    print(f"Val samples:   {len(y_val)} (Pos: {int(y_val.sum())}, Neg: {int(len(y_val)-y_val.sum())})")
    print(f"Test samples:  {len(y_test)} (Pos: {int(y_test.sum())}, Neg: {int(len(y_test)-y_test.sum())})")

    train_ds = ReconDataset(X_train, mask_train, y_train)
    val_ds = ReconDataset(X_val, mask_val, y_val)
    test_ds = ReconDataset(X_test, mask_test, y_test)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_ds, batch_size=batch_size, shuffle=False)

    model = ReconTransformer(
        feature_dim=8,
        sequence_length=10,
        d_model=d_model,
        nhead=4,
        num_layers=num_layers,
    ).to(device)

    # Class weighting to handle imbalance
    pos_weight = torch.tensor([(len(y_train) - y_train.sum()) / max(1.0, y_train.sum())], device=device)
    criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_val_loss = float("inf")
    save_file = Path(output_model_path)
    save_file.parent.mkdir(parents=True, exist_ok=True)

    for epoch in range(1, epochs + 1):
        model.train()
        train_loss = 0.0
        for bx, bm, by in train_loader:
            bx, bm, by = bx.to(device), bm.to(device), by.to(device)
            optimizer.zero_grad()
            logits = model.forward_logits(bx, bm)
            loss = criterion(logits, by)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * len(by)

        train_loss /= len(train_ds)
        scheduler.step()

        # Validation
        model.eval()
        val_loss = 0.0
        correct = 0
        with torch.no_grad():
            for bx, bm, by in val_loader:
                bx, bm, by = bx.to(device), bm.to(device), by.to(device)
                logits = model.forward_logits(bx, bm)
                loss = criterion(logits, by)
                val_loss += loss.item() * len(by)
                preds = (torch.sigmoid(logits) >= 0.5).float()
                correct += (preds == by).sum().item()

        val_loss /= len(val_ds)
        val_acc = correct / len(val_ds)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), str(save_file))

        if epoch % 5 == 0 or epoch == epochs:
            print(f"[UNSW Transformer] Epoch {epoch:02d}/{epochs:02d} - Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}")

    # Load best weights before temperature calibration
    model.load_state_dict(torch.load(str(save_file), map_location=device, weights_only=True))

    # Temperature Calibration on validation set
    cal_temp = model.calibrate_temperature(val_loader, device=device)
    torch.save(model.state_dict(), str(save_file))
    print(f"[+] Saved calibrated UNSW model to {save_file} (T={cal_temp:.4f})")

    # Evaluation on Held-Out Test Set
    from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix, roc_auc_score, precision_recall_curve, auc

    model.eval()
    test_probs = []
    with torch.no_grad():
        for bx, bm, _ in test_loader:
            bx, bm = bx.to(device), bm.to(device)
            probs = model(bx, bm, calibrate=True).cpu().numpy()
            test_probs.append(probs)
            
    test_probs = np.vstack(test_probs).flatten()
    y_test_flat = y_test.flatten().astype(int)
    y_pred_binary = (test_probs >= 0.5).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test_flat, y_pred_binary, labels=[0, 1]).ravel()
    prec = float(precision_score(y_test_flat, y_pred_binary, zero_division=0))
    rec = float(recall_score(y_test_flat, y_pred_binary, zero_division=0))
    f1 = float(f1_score(y_test_flat, y_pred_binary, zero_division=0))
    acc = float((tp + tn) / len(y_test_flat))
    fpr = float(fp / (fp + tn + 1e-6))
    
    try:
        roc_auc = float(roc_auc_score(y_test_flat, test_probs))
        p_curve, r_curve, _ = precision_recall_curve(y_test_flat, test_probs)
        pr_auc = float(auc(r_curve, p_curve))
    except Exception:
        roc_auc = 0.0
        pr_auc = 0.0

    cal_metrics = compute_calibration_metrics(test_probs, y_test_flat)

    eval_results = {
        "dataset": "UNSW-NB15 Held-Out Test Set",
        "sample_count": len(y_test_flat),
        "recon_samples": int(y_test.sum()),
        "normal_samples": int(len(y_test) - y_test.sum()),
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
        "brier_score": cal_metrics["brier_score"],
        "expected_calibration_error": cal_metrics["expected_calibration_error"],
        "calibrated_temperature": float(cal_temp),
    }

    print("\n==========================================")
    print("UNSW-NB15 HELD-OUT TEST EVALUATION RESULTS")
    print("==========================================")
    for k, v in eval_results.items():
        print(f"  {k}: {v}")

    with open("data/unsw_evaluation_report.json", "w") as f:
        json.dump(eval_results, f, indent=2)

    return eval_results


if __name__ == "__main__":
    train_unsw_transformer()
