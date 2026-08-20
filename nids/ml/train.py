"""
Training pipeline for Home-Gateway NIDS.
Independently trains:
1. Baseline Logistic Regression
2. Single-Window Transformer Model (1x8)
3. 5-Window Sequence Transformer (5x8)
4. 10-Window Sequence Transformer (10x8)
Performs independent validation-set temperature calibration for every neural model.
"""

from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
import joblib

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

from .dataset import build_and_save_persistent_datasets, load_persistent_split
from .baseline_detector import BaselineReconDetector


def train_single_transformer(
    seq_len: int,
    X_tr: np.ndarray,
    mask_tr: np.ndarray,
    y_tr: np.ndarray,
    X_v: np.ndarray,
    mask_v: np.ndarray,
    y_v: np.ndarray,
    epochs: int = 30,
    batch_size: int = 64,
    lr: float = 1e-3,
    d_model: int = 32,
    num_layers: int = 2,
    device: torch.device = torch.device("cpu"),
    save_path: str = "models/transformer_model.pt",
) -> Tuple[ReconTransformer, Dict[str, Any]]:
    """
    Independently trains and calibrates a ReconTransformer of specified sequence length.
    """
    print(f"\n--- Training Independent Transformer ({seq_len}x8) ---")
    # Slice to sequence length (most recent seq_len windows)
    X_train_slice = X_tr[:, -seq_len:, :]
    mask_train_slice = mask_tr[:, -seq_len:]
    X_val_slice = X_v[:, -seq_len:, :]
    mask_val_slice = mask_v[:, -seq_len:]

    train_ds = ReconDataset(X_train_slice, mask_train_slice, y_tr)
    val_ds = ReconDataset(X_val_slice, mask_val_slice, y_v)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)

    model = ReconTransformer(
        feature_dim=8,
        sequence_length=seq_len,
        d_model=d_model,
        nhead=4 if d_model >= 4 else 1,
        num_layers=num_layers,
    ).to(device)

    criterion = nn.BCEWithLogitsLoss()
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)

    best_val_loss = float("inf")
    save_file = Path(save_path)
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

        if epoch % 10 == 0 or epoch == epochs:
            print(f"[{seq_len}x8] Epoch {epoch:02d}/{epochs:02d} - Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f}")

    # Load best checkpoint before calibration
    model.load_state_dict(torch.load(str(save_file), map_location=device, weights_only=True))

    # Independent Temperature Calibration on Validation Slice
    cal_temp = model.calibrate_temperature(val_loader, device=device)
    torch.save(model.state_dict(), str(save_file))
    print(f"[+] Saved calibrated {seq_len}x8 model to {save_file} (T={cal_temp:.4f})")

    # Metrics on validation
    model.eval()
    val_probs_cal = []
    with torch.no_grad():
        for bx, bm, _ in val_loader:
            bx, bm = bx.to(device), bm.to(device)
            val_probs_cal.append(model(bx, bm, calibrate=True).cpu().numpy())
    val_probs_cal = np.vstack(val_probs_cal)
    cal_metrics = compute_calibration_metrics(val_probs_cal, y_v)

    return model, {
        "val_loss": float(best_val_loss),
        "val_acc": float(val_acc),
        "temperature": float(cal_temp),
        "val_brier": cal_metrics["brier_score"],
        "val_ece": cal_metrics["expected_calibration_error"],
    }


def train_models(
    epochs: int = 30,
    batch_size: int = 64,
    lr: float = 1e-3,
    data_dir: str = "data/processed",
    output_dir: str = "models",
    seed: int = 42,
) -> Dict[str, Any]:
    """
    Executes full training pass for baseline and all 3 independent temporal models.
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # 1. Load persistent datasets
    print("Loading persistent datasets from", data_dir)
    build_and_save_persistent_datasets(output_dir=data_dir, seed=seed)
    X_train, mask_train, y_train, _ = load_persistent_split("train", data_dir=data_dir)
    X_val, mask_val, y_val, _ = load_persistent_split("val", data_dir=data_dir)

    print(f"Dataset summary: Train N={len(y_train)} (Pos: {int(y_train.sum())}, Neg: {int(len(y_train)-y_train.sum())})")
    print(f"                 Val   N={len(y_val)} (Pos: {int(y_val.sum())}, Neg: {int(len(y_val)-y_val.sum())})")

    # 2. Train Baseline Logistic Regression
    print("\n--- Training Baseline Logistic Regression ---")
    baseline = BaselineReconDetector()
    baseline.fit(X_train, y_train)
    baseline_val_probs = baseline.predict_proba(X_val)
    baseline_cal = compute_calibration_metrics(baseline_val_probs, y_val)
    baseline_path = out_path / "baseline_model.joblib"
    joblib.dump(baseline, str(baseline_path))
    print(f"[+] Baseline saved to {baseline_path} (Val Brier: {baseline_cal['brier_score']:.4f}, ECE: {baseline_cal['expected_calibration_error']:.4f})")

    results: Dict[str, Any] = {
        "baseline_val_brier": baseline_cal["brier_score"],
        "baseline_val_ece": baseline_cal["expected_calibration_error"],
    }

    if TORCH_AVAILABLE:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Training device: {device}")

        # Model A: Single-Window (1x8)
        _, res_1w = train_single_transformer(
            seq_len=1, X_tr=X_train, mask_tr=mask_train, y_tr=y_train,
            X_v=X_val, mask_v=mask_val, y_v=y_val,
            epochs=epochs, batch_size=batch_size, lr=lr, d_model=32, num_layers=1,
            device=device, save_path=str(out_path / "transformer_1x8.pt")
        )
        results["transformer_1x8"] = res_1w

        # Model B: 5-Window (5x8)
        _, res_5w = train_single_transformer(
            seq_len=5, X_tr=X_train, mask_tr=mask_train, y_tr=y_train,
            X_v=X_val, mask_v=mask_val, y_v=y_val,
            epochs=epochs, batch_size=batch_size, lr=lr, d_model=32, num_layers=2,
            device=device, save_path=str(out_path / "transformer_5x8.pt")
        )
        results["transformer_5x8"] = res_5w

        # Model C: 10-Window (10x8)
        _, res_10w = train_single_transformer(
            seq_len=10, X_tr=X_train, mask_tr=mask_train, y_tr=y_train,
            X_v=X_val, mask_v=mask_val, y_v=y_val,
            epochs=epochs, batch_size=batch_size, lr=lr, d_model=32, num_layers=2,
            device=device, save_path=str(out_path / "transformer_10x8.pt")
        )
        results["transformer_10x8"] = res_10w

        # Copy 10x8 as standard transformer_recon.pt for downstream compatibility
        import shutil
        shutil.copyfile(str(out_path / "transformer_10x8.pt"), str(out_path / "transformer_recon.pt"))
        print(f"[+] Canonical transformer_recon.pt updated from transformer_10x8.pt")

    return results


if __name__ == "__main__":
    train_models()
