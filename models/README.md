# Model Weights & Metadata

This directory stores trained model checkpoints for the **Home-Gateway NIDS** reconnaissance detection pipeline.

## Model Files
- `transformer_recon.pt`: PyTorch weights for the 2-layer Sequence Transformer Encoder (10 × 60s windows $\rightarrow$ calibrated reconnaissance probability).
- `baseline_model.joblib`: Scikit-Learn Logistic Regression benchmark weights.

## Model Architecture Specifications
- **Input Dimension**: $T=10$ windows, $D=8$ behavioral features (`(batch_size, 10, 8)`).
- **Projection**: Linear $8 \rightarrow 32$ with learnable positional embeddings.
- **Encoder**: 2 Layers, 4 Attention Heads, $d_{\text{ff}}=64$, GELU activations, Dropout $0.10$.
- **Pooling**: Mask-aware sequence mean pooling across valid time steps.
- **Output**: Sigmoid calibrated probability $P(\text{Reconnaissance} \mid X_{1:10}) \in [0.0, 1.0]$.
