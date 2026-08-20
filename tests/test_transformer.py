"""
Unit tests for ReconTransformer model architecture, forward pass, tensor shapes, and masking.
"""

import pytest
import numpy as np
import torch

from nids.ml.transformer_model import ReconTransformer, TransformerInferenceEngine


def test_transformer_forward_pass_shape():
    model = ReconTransformer(feature_dim=8, sequence_length=10, d_model=32, nhead=4, num_layers=2)
    model.eval()

    batch_size = 4
    x = torch.randn(batch_size, 10, 8)
    mask = torch.ones(batch_size, 10)
    # Mask out first 4 steps for batch 0
    mask[0, :4] = 0.0

    with torch.no_grad():
        out = model(x, mask)

    assert out.shape == (batch_size, 1)
    # Ensure outputs are valid probabilities in [0.0, 1.0]
    assert (out >= 0.0).all() and (out <= 1.0).all()


def test_inference_engine_ml_unavailable(tmp_path):
    # Pass a non-existent weights file
    fake_path = tmp_path / "non_existent.pt"
    engine = TransformerInferenceEngine(weights_path=str(fake_path))
    assert engine.is_available is False

    seq = np.zeros((10, 8), dtype=np.float32)
    with pytest.raises(RuntimeError, match="ML_UNAVAILABLE"):
        engine.predict_score(seq)
