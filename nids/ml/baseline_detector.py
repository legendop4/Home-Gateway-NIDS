"""
Baseline Detection Models: Heuristic Rule-based Detector & Logistic Regression Benchmark.
Used to evaluate whether the Transformer adds measurable value over non-deep learning methods.
"""

from typing import Dict, Optional, Tuple
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler


class HeuristicReconDetector:
    """
    Statistical heuristic detector based on known port-scanning signatures:
    - High unique destination ports contacted within sliding windows
    - High SYN-to-ACK ratio (unanswered SYN packets)
    - Low connection duration
    """

    def __init__(
        self,
        port_threshold_fast: float = 20.0,
        port_threshold_stealth: float = 8.0,
        syn_ratio_threshold: float = 0.80,
    ):
        self.port_threshold_fast = port_threshold_fast
        self.port_threshold_stealth = port_threshold_stealth
        self.syn_ratio_threshold = syn_ratio_threshold

    def score_sequence(self, sequence: np.ndarray, mask: Optional[np.ndarray] = None) -> float:
        """
        Input:
            sequence: array of shape (10, 8) or (B, 10, 8)
            mask: array of shape (10,) or (B, 10)
        Returns:
            score: calibrated probability float in [0.0, 1.0]
        """
        if sequence.ndim == 3:
            return np.array([self.score_sequence(seq, m if mask is not None else None) for seq, m in zip(sequence, mask if mask is not None else [None]*len(sequence))])

        if mask is not None and np.sum(mask) == 0:
            return 0.0

        valid_steps = sequence[mask > 0] if mask is not None else sequence
        if len(valid_steps) == 0:
            return 0.0

        # Feature indices:
        # 0: dst_port_count, 1: dst_ip_count, 2: syn_ratio, 3: syn_ack_ratio,
        # 4: rst_ratio, 5: packet_rate, 6: byte_rate, 7: flow_duration_mean
        dst_ports = valid_steps[:, 0]
        syn_ratios = valid_steps[:, 2]
        syn_ack_ratios = valid_steps[:, 3]
        durations = valid_steps[:, 7]

        max_ports = np.max(dst_ports)
        sum_ports = np.sum(dst_ports)
        mean_syn_ratio = np.mean(syn_ratios)
        mean_syn_ack = np.mean(syn_ack_ratios)

        # Fast scan check
        fast_score = min(1.0, max_ports / (self.port_threshold_fast + 1e-5)) * min(1.0, mean_syn_ratio / self.syn_ratio_threshold)

        # Stealth scan check (spread across multiple windows)
        num_windows_with_probes = np.sum(dst_ports >= 2.0)
        stealth_score = 0.0
        if num_windows_with_probes >= 3 and sum_ports >= self.port_threshold_stealth:
            stealth_score = min(1.0, (sum_ports / 15.0) * (num_windows_with_probes / 5.0) * min(1.0, mean_syn_ratio / 0.70))

        final_score = float(max(fast_score, stealth_score))
        return np.clip(final_score, 0.0, 1.0)


class BaselineReconDetector:
    """
    Supervised Logistic Regression baseline for binary recon detection.
    Flattens the 10x8 sequence into an 80-d vector.
    """

    def __init__(self):
        self.scaler = StandardScaler()
        self.model = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BaselineReconDetector":
        """
        X: shape (N, 10, 8)
        y: shape (N,)
        """
        N = X.shape[0]
        X_flat = X.reshape(N, -1)
        X_scaled = self.scaler.fit_transform(X_flat)
        self.model.fit(X_scaled, y)
        self.is_fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Returns probabilities of reconnaissance: shape (N,) or float if single sample.
        """
        if not self.is_fitted:
            raise RuntimeError("Baseline model is not fitted yet.")

        single = False
        if X.ndim == 2:  # (10, 8)
            X = np.expand_dims(X, axis=0)
            single = True

        N = X.shape[0]
        X_flat = X.reshape(N, -1)
        X_scaled = self.scaler.transform(X_flat)
        probs = self.model.predict_proba(X_scaled)[:, 1]

        return float(probs[0]) if single else probs

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        probs = self.predict_proba(X)
        return (probs >= threshold).astype(int)
