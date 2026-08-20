"""
Lightweight Sequence Transformer for Network Reconnaissance Detection.
Input shape: (batch_size, 10, 8) representing 10 consecutive 60-second flow-feature windows.
Includes mask-aware positional encoding, proper attention padding masks, and probability calibration.
"""

from typing import Optional, Tuple, Dict, Any
from pathlib import Path
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    nn = object  # type: ignore


if TORCH_AVAILABLE:
    class PositionalEncoding(nn.Module):
        """Learnable positional embeddings with zero-mask gating."""
        def __init__(self, sequence_length: int = 10, d_model: int = 32):
            super().__init__()
            self.pos_embedding = nn.Embedding(sequence_length, d_model)

        def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
            # x shape: (B, T, D)
            seq_len = x.size(1)
            positions = torch.arange(seq_len, device=x.device).unsqueeze(0).expand(x.size(0), -1)
            pos_emb = self.pos_embedding(positions)

            if mask is not None:
                # Zero-out positional embeddings on padded time-steps
                pos_emb = pos_emb * mask.unsqueeze(-1)

            return x + pos_emb


    class TemperatureScaler(nn.Module):
        """
        Post-hoc probability calibration via Platt / Temperature scaling.
        Optimizes a single temperature parameter T > 0 on a held-out validation set.
        """
        def __init__(self):
            super().__init__()
            self.temperature = nn.Parameter(torch.ones(1) * 1.0)

        def forward(self, logits: torch.Tensor) -> torch.Tensor:
            return logits / torch.clamp(self.temperature, min=1e-3)


    class ReconTransformer(nn.Module):
        """
        2-Layer Lightweight Transformer Encoder for 10x60s Reconnaissance Detection.
        Strictly preserves zero-padding masks across projection, attention, and pooling.
        """

        def __init__(
            self,
            feature_dim: int = 8,
            sequence_length: int = 10,
            d_model: int = 32,
            nhead: int = 4,
            num_layers: int = 2,
            dim_feedforward: int = 64,
            dropout: float = 0.1,
        ):
            super().__init__()
            self.feature_dim = feature_dim
            self.sequence_length = sequence_length
            self.d_model = d_model

            # 1. Feature Projection
            self.input_projection = nn.Linear(feature_dim, d_model, bias=False)  # bias=False avoids non-zero padding values

            # 2. Masked Positional Encoding
            self.pos_encoder = PositionalEncoding(sequence_length=sequence_length, d_model=d_model)
            self.input_norm = nn.LayerNorm(d_model)
            self.dropout = nn.Dropout(dropout)

            # 3. Transformer Encoder Layers
            encoder_layer = nn.TransformerEncoderLayer(
                d_model=d_model,
                nhead=nhead,
                dim_feedforward=dim_feedforward,
                dropout=dropout,
                batch_first=True,
                activation="gelu",
            )
            self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

            # 4. Classification Head
            self.classifier = nn.Sequential(
                nn.LayerNorm(d_model),
                nn.Linear(d_model, 16),
                nn.GELU(),
                nn.Dropout(dropout),
                nn.Linear(16, 1),
            )

            # 5. Temperature Scaler for Calibration
            self.temperature_scaler = TemperatureScaler()

        def forward_logits(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None) -> torch.Tensor:
            """Outputs raw uncalibrated logits."""
            if mask is not None:
                x = x * mask.unsqueeze(-1)

            h = self.input_projection(x)
            h = self.pos_encoder(h, mask=mask)
            h = self.input_norm(h)
            h = self.dropout(h)

            src_key_padding_mask = None
            if mask is not None:
                src_key_padding_mask = (mask == 0.0)

            encoded = self.transformer_encoder(h, src_key_padding_mask=src_key_padding_mask)

            # Masked Mean Pooling
            if mask is not None:
                expanded_mask = mask.unsqueeze(-1)
                encoded = encoded * expanded_mask
                sum_encoded = torch.sum(encoded, dim=1)
                valid_counts = torch.clamp(torch.sum(expanded_mask, dim=1), min=1.0)
                pooled = sum_encoded / valid_counts
            else:
                pooled = torch.mean(encoded, dim=1)

            logits = self.classifier(pooled)
            return logits

        def forward(self, x: torch.Tensor, mask: Optional[torch.Tensor] = None, calibrate: bool = True) -> torch.Tensor:
            """
            x: shape (B, 10, 8)
            mask: shape (B, 10)
            Returns:
                calibrated probabilities: shape (B, 1) in [0.0, 1.0]
            """
            logits = self.forward_logits(x, mask)
            if calibrate:
                scaled_logits = self.temperature_scaler(logits)
                return torch.sigmoid(scaled_logits)
            return torch.sigmoid(logits)

        def calibrate_temperature(self, val_loader, device: torch.device) -> float:
            """Optimize temperature parameter on held-out validation set using NLL loss."""
            self.eval()
            logits_list = []
            labels_list = []

            with torch.no_grad():
                for batch_x, batch_mask, batch_y in val_loader:
                    batch_x = batch_x.to(device)
                    batch_mask = batch_mask.to(device)
                    logits = self.forward_logits(batch_x, batch_mask)
                    logits_list.append(logits.cpu())
                    labels_list.append(batch_y)

            logits_all = torch.cat(logits_list).to(device)
            labels_all = torch.cat(labels_list).to(device)

            criterion = nn.BCEWithLogitsLoss()
            optimizer = torch.optim.LBFGS([self.temperature_scaler.temperature], lr=0.01, max_iter=50)

            def eval_loss():
                optimizer.zero_grad()
                scaled = self.temperature_scaler(logits_all)
                loss = criterion(scaled, labels_all)
                loss.backward()
                return loss

            optimizer.step(eval_loss)
            temp = float(self.temperature_scaler.temperature.item())
            print(f"[+] Model Temperature calibrated on validation set: T = {temp:.4f}")
            return temp

else:
    class ReconTransformer:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise RuntimeError("PyTorch is not installed. Transformer model is unavailable.")


def compute_calibration_metrics(probs: np.ndarray, labels: np.ndarray, num_bins: int = 10) -> Dict[str, float]:
    """
    Computes Brier Score and Expected Calibration Error (ECE).
    """
    probs = np.clip(probs.flatten(), 1e-7, 1.0 - 1e-7)
    labels = labels.flatten()

    # 1. Brier Score
    brier_score = float(np.mean((probs - labels) ** 2))

    # 2. Expected Calibration Error (ECE)
    bin_boundaries = np.linspace(0.0, 1.0, num_bins + 1)
    ece = 0.0
    total_samples = len(probs)

    for i in range(num_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        in_bin = (probs >= bin_lower) & (probs < bin_upper if i < num_bins - 1 else probs <= bin_upper)
        bin_size = np.sum(in_bin)

        if bin_size > 0:
            bin_acc = np.mean(labels[in_bin])
            bin_conf = np.mean(probs[in_bin])
            ece += (bin_size / total_samples) * np.abs(bin_acc - bin_conf)

    return {
        "brier_score": float(round(brier_score, 4)),
        "expected_calibration_error": float(round(ece, 4)),
    }


class TransformerInferenceEngine:
    """
    Wraps ReconTransformer for safe inference, handling weight loading,
    proper mask validation, and error reporting.
    """

    def __init__(self, weights_path: str = "models/transformer_recon.pt", device: str = "cpu"):
        self.weights_path = Path(weights_path)
        self.device = device
        self.model: Optional[ReconTransformer] = None
        self.is_available = False
        self._load_model()

    def _load_model(self) -> None:
        if not TORCH_AVAILABLE:
            self.is_available = False
            return

        if not self.weights_path.exists():
            self.is_available = False
            return

        try:
            state_dict = torch.load(self.weights_path, map_location=self.device, weights_only=True)
            # Auto-detect sequence length from pos_embedding
            if "pos_encoder.pos_embedding.weight" in state_dict:
                seq_len = state_dict["pos_encoder.pos_embedding.weight"].shape[0]
            else:
                seq_len = 10

            # Auto-detect number of layers
            layer_keys = [k for k in state_dict.keys() if "transformer_encoder.layers." in k]
            layer_indices = {int(k.split(".")[2]) for k in layer_keys}
            num_layers = max(layer_indices) + 1 if layer_indices else 2

            self.model = ReconTransformer(sequence_length=seq_len, num_layers=num_layers)
            self.model.load_state_dict(state_dict)
            self.model.to(self.device)
            self.model.eval()
            self.is_available = True
        except Exception as e:
            print(f"[TransformerInferenceEngine] Failed to load model weights from {self.weights_path}: {e}")
            self.is_available = False

    def predict_score(self, sequence: np.ndarray, mask: Optional[np.ndarray] = None, calibrate: bool = True) -> float:
        """
        Runs inference on a single 10x8 sequence.
        Returns:
            calibrated probability score in [0.0, 1.0]
        Raises:
            RuntimeError if ML is unavailable.
        """
        if not self.is_available or self.model is None:
            raise RuntimeError("ML_UNAVAILABLE")

        if sequence.ndim == 2:
            sequence = np.expand_dims(sequence, axis=0)  # (1, 10, 8)
        if mask is not None and mask.ndim == 1:
            mask = np.expand_dims(mask, axis=0)  # (1, 10)

        with torch.no_grad():
            x_tensor = torch.tensor(sequence, dtype=torch.float32, device=self.device)
            mask_tensor = torch.tensor(mask, dtype=torch.float32, device=self.device) if mask is not None else None
            prob = self.model(x_tensor, mask_tensor, calibrate=calibrate)
            return float(prob.squeeze().item())
