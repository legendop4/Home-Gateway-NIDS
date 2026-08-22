# Home-Gateway NIDS: Network Reconnaissance Detection Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Framework: PyTorch](https://img.shields.io/badge/PyTorch-2.0+-ee4c2c.svg)](https://pytorch.org/)
[![Status: Research Prototype](https://img.shields.io/badge/Status-Research_Prototype-brightgreen.svg)]()

A research-prototype **Hybrid Network Intrusion Detection System (NIDS)** tailored for enterprise and smart-home gateway environments. The platform combines deterministic signature matching (Suricata / offline rules) with a **10-step Sequence Transformer Encoder** to detect fast, slow, and stealth network reconnaissance (**MITRE ATT&CK T1046**).

---

## 1. System Architecture

```text
                      +------------------------------------------+
                      |   Network Traffic (AP / Ethernet / PCAP) |
                      +------------------------------------------+
                                           |
                   +-----------------------+-----------------------+
                   |                                               |
                   v                                               v
        +----------------------+                       +-----------------------+
        |   Suricata / Offline |                       | Flow Feature          |
        |   Rule Engine        |                       | Extractor & Windowing |
        +----------------------+                       +-----------------------+
                   |                                               |
                   | (EVE JSON / Alerts)                           | (10 x 60s Sequences)
                   v                                               v
        +----------------------+                       +-----------------------+
        | Deterministic Alert  |                       | Sequence Transformer  |
        | Stream Ingestion     |                       | Calibrated Classifier |
        +----------------------+                       +-----------------------+
                   \                                               /
                    \                                             /
                     v                                           v
                   +-----------------------------------------------+
                   |           Hybrid Decision Fusion Engine       |
                   |   (SURICATA | TRANSFORMER_RECON | HYBRID)     |
                   +-----------------------------------------------+
                                           |
                   +-----------------------+-----------------------+
                   |                                               |
                   v                                               v
        +----------------------+                       +-----------------------+
        |  SQLite Storage WAL  |                       | Bounded SIEM Exporter |
        | (Alerts, Devices)    |                       | (ECS JSONL / CEF)     |
        +----------------------+                       +-----------------------+
                   |
                   v
        +----------------------+
        | Flask Web Dashboard  |
        | (RBAC & CSP Hardened)|
        +----------------------+
```

---

## 2. Threat Model: Network Reconnaissance (MITRE ATT&CK T1046)

The system focuses strictly on **Network Service Discovery & Reconnaissance**:

| Attack Variant | Technical Characteristics | Primary Detection Mechanism |
| :--- | :--- | :--- |
| **Fast TCP SYN Scan** | High packet rate ($>20$ pkts/s), rapid port cycling, high uncompleted SYN ratio. | Deterministic signature match (e.g. `sid:2000001`) + Transformer score $\rightarrow$ **HYBRID** alert. |
| **Slow / Stealth Scan** | Low packet rate ($<1$ pkt/s), probes spread across 5–10 minutes evading single-packet thresholds. | 10-window Sequence Transformer temporal correlation $\rightarrow$ **TRANSFORMER_RECON** alert. |
| **Randomized Port Sweep** | Random non-sequential port probes distributed across multiple destination hosts. | Multi-window port & IP diversity feature accumulation. |
| **FIN / NULL / XMAS Scans** | Abnormal TCP flags without valid connection handshakes. | TCP flag matching + behavioral ratio metrics. |

---

## 3. Dual-Dataset Experimental Methodology

The platform uses a two-tier evaluation strategy:

1. **Real-World UNSW-NB15 Benchmark (Primary ML Training & Evaluation)**:
   Real network traffic flows evaluated on held-out test splits to demonstrate generalizability on genuine flow distributions.
2. **Controlled Synthetic Dataset (Stress & Evasion Testing)**:
   Stochastic Poisson probing intervals and temporal window ablations ($1 \times 8$ vs $5 \times 8$ vs $10 \times 8$) for reproducible edge-case benchmarking.

### 8 Flow Features Extracted per 60-Second Window:
1. `dst_port_count`: Distinct destination ports targeted
2. `dst_ip_count`: Unique target destination IPs
3. `syn_ratio`: Proportion of TCP SYN packets
4. `syn_ack_ratio`: TCP SYN-to-SYN/ACK connection completion ratio
5. `rst_ratio`: Proportion of TCP RST packets received
6. `packet_rate`: Average packet transmission speed (pkts/s)
7. `byte_rate`: Average throughput in bytes per second (Bps)
8. `flow_duration_mean`: Mean active flow lifetime (seconds)

---

## 4. Empirical Evaluation Results

### A. Real-World UNSW-NB15 Benchmark (Held-Out Test Set, N = 8,098 Sequences)
Evaluated on `data/processed_unsw/test.npz` with temperature-calibrated model [`models/transformer_recon_unsw.pt`](models/transformer_recon_unsw.pt):

| Metric | Standard Threshold (0.50) | Gateway Decision Threshold (0.70) | Operational Significance |
| :--- | :---: | :---: | :--- |
| **Accuracy** | 83.39% | **94.53%** | Sequence classification accuracy on real flows |
| **Precision** | 34.30% | **61.48%** | Higher threshold eliminates 67.5% of false positives |
| **Recall / Sensitivity** | **99.72%** (701 / 703) | **99.00%** (696 / 703) | Exceptional capture of real reconnaissance attacks |
| **F1-Score** | 51.04% | **75.86%** | Balanced precision/recall at operating threshold |
| **False Positive Rate (FPR)** | 18.16% | **5.90%** | Mitigated downstream by Suricata hybrid fusion |
| **ROC-AUC** | **0.9961** | **0.9961** | Strong separability on real-world flow features |
| **PR-AUC** | **0.9772** | **0.9772** | High precision-recall curve integral under class imbalance |
| **Confusion Matrix** | `TN=6052, FP=1343, FN=2, TP=701` | `TN=6959, FP=436, FN=7, TP=696` | Only 7 missed attacks out of 703 test sequences |
| **Brier Score / ECE** | `0.1123` / `0.2072` | `0.1123` / `0.2072` | Well-calibrated probability error ($T = 1.0016$) |

### B. Controlled Synthetic Benchmark (Held-Out `test.npz`, N = 1,100 Sessions)

| Detection Strategy | Precision | Recall | F1-Score | FPR | Brier Score | ECE | Latency (Mean / p95) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Rule Baseline** | 0.8743 | 0.9040 | 0.8889 | 0.1083 | 0.0947 | 0.1152 | 0.11 ms / 0.14 ms |
| **Logistic Regression** | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0.0010 | 0.36 ms / 0.60 ms |
| **Transformer 1×8 (Single-Window)** | 0.9901 | 1.0000 | 0.9950 | 0.0083 | 0.0046 | 0.0057 | 2.33 ms / 2.63 ms |
| **Transformer 5×8 (5-Window)** | 0.9960 | 0.9980 | 0.9970 | 0.0033 | 0.0015 | 0.0027 | 3.66 ms / 4.22 ms |
| **Transformer 10×8 (10-Window)** | **1.0000** | **0.9680** | **0.9837** | **0.0000** | **0.0095** | **0.0125** | **3.18 ms / 4.08 ms** |

### C. Independent Evasion Stress Test (`evasion_stress_test.npz`, N = 800 Sessions)

Stress tests temporal sequence tracking on stochastic Poisson probing intervals ($30\text{s} - 90\text{s}$ per probe):

| Model Variant | Input Dimension | Precision | Recall | F1-Score | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Baseline Logistic Regression** | $10 \times 8$ (Flattened) | 1.0000 | 0.7000 | 0.8235 | 0.0000 |
| **Transformer 1×8** | $1 \times 8$ (Single Window) | 0.9455 | 0.6500 | 0.7704 | 0.0375 |
| **Transformer 5×8** | $5 \times 8$ (5 Windows) | 0.9376 | 0.9775 | 0.9572 | 0.0650 |
| **Transformer 10×8** | $10 \times 8$ (10 Windows) | **0.9925** | **0.9900** | **0.9912** | **0.0075** |

### D. Lab PCAP Packet Replay Evaluation

| Packet Capture | Ground Truth | Suricata / Offline Rules | Transformer Score | Hybrid Decision |
| :--- | :---: | :---: | :---: | :---: |
| **`lab_benign.pcap`** | BENIGN | 0 alerts | 0.0040 (TN) | **BENIGN** |
| **`lab_fast_scan.pcap`** | RECON | 8 alerts (`sid:2000001`) | 0.9993 (TP) | **HYBRID ALERT** |
| **`lab_stealth_scan.pcap`** | RECON | 0 alerts (Evaded threshold) | 0.9993 (TP) | **TRANSFORMER_RECON** |

---

## 5. Security & Reliability Architecture

- **Centralized Health Manager**: Watchdog daemon monitoring 8 subsystems with status states (`UP`, `DEGRADED`, `DOWN`, `ML_UNAVAILABLE`).
- **Bounded In-Memory Structures**: Hard caps on flow tables (50k), IP sequence buffers (10k), cooldown cache (5k), and SIEM export queue (5k).
- **API Security**: Constant-time token verification (`hmac.compare_digest`), dual roles (`VIEWER` / `ADMIN`), strict IP and pagination validation, OWASP security headers, and safe error masking.
- **Production Secret Management**: Enforced environment variable secrets (`NIDS_ADMIN_API_KEY`, `NIDS_VIEWER_API_KEY`).
- **End-to-End Test Suite**: Complete unit, integration, and security test coverage.

---

## 6. Quick Start & Execution

### Setup Environment
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

### Run Evaluation Suite
```bash
# Synthetic baseline evaluation & ablation benchmarks
python run.py --evaluate

# UNSW-NB15 model evaluation
python -m scripts.eval_unsw_authoritative

# End-to-End Pipeline Integration Test
python -m scripts.test_e2e_unsw_pipeline
```

### Start Gateway Dashboard & Detection Server
```bash
# Replay lab stealth scan PCAP
python run.py --mode pcap --pcap-file data/pcaps/lab_stealth_scan.pcap

# Open dashboard in browser
# http://127.0.0.1:5000
```

### Run Full Test Suite
```bash
python -m unittest discover -s tests -p "test_*.py"
```
