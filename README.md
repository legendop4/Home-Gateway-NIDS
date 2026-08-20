# Home-Gateway NIDS: Network Reconnaissance Detection Platform

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Framework: PyTorch](https://img.shields.io/badge/PyTorch-2.0+-ee4c2c.svg)](https://pytorch.org/)
[![Status: Research Prototype](https://img.shields.io/badge/Status-Research_Prototype-brightgreen.svg)]()

A research-prototype **Hybrid Intrusion Detection System (NIDS)** for gateway environments, implementing enterprise-oriented detection engineering and software hardening practices. It combines deterministic signature inspection with a calibrated **10 × 60-second Sequence Transformer Encoder** to detect fast, slow, and stealth network reconnaissance (MITRE ATT&CK T1046).

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

The detection scope is strictly **Network Reconnaissance**:

| Attack Variant | Technical Characteristics | Primary Detection Mechanism |
| :--- | :--- | :--- |
| **Fast TCP SYN Scan** | High packet rate ($>20$ pkts/sec), rapid port cycling ($>30$ ports/min), high uncompleted SYN ratio. | Deterministic signature match (e.g. `sid:2000001`) + Transformer score $\rightarrow$ **HYBRID** alert. |
| **Slow / Stealth Scan** | Low packet rate ($<1$ pkt/sec), probes spread across 5–10 minutes, evading single-packet thresholds. | 10-window Sequence Transformer temporal correlation $\rightarrow$ **TRANSFORMER_RECON** alert. |
| **Randomized Port Sweep** | Random non-sequential port probes distributed across multiple destination hosts. | Multi-window port & IP diversity feature accumulation. |
| **FIN / NULL / XMAS Scans** | Abnormal TCP flags without valid connection handshakes. | TCP flag matching + behavioral ratio metrics. |

---

## 3. Dataset Composition & Session-Level Split Isolation

All synthetic data is partitioned by **opaque Session ID** (`sess_xxxxxxxxxxxx`) and stored persistently in `data/processed/`:

| Split File | Total Sessions | Benign Sessions | Recon Sessions | Session Composition |
| :--- | :---: | :---: | :---: | :--- |
| **`train.npz`** | **3,300** | 1,800 | 1,500 | Benign (Browse: 700, Short HTTP: 500, Heavy: 300, Idle: 300), Recon (Fast: 600, Stealth: 600, Random: 300) |
| **`val.npz`** | **810** | 430 | 380 | Benign (Browse: 150, Short HTTP: 120, Heavy: 80, Idle: 80), Recon (Fast: 150, Stealth: 150, Random: 80) |
| **`test.npz`** | **1,100** | 600 | 500 | Benign (Browse: 220, Short HTTP: 180, Heavy: 100, Idle: 100), Recon (Fast: 200, Stealth: 200, Random: 100) |
| **`evasion_stress_test.npz`** | **800** | 400 | 400 | Hard Benign (Dev burst: 200, Intermittent IoT: 200), Evasion Recon (Stochastic Poisson: 250, Low-SYN Decoy: 150) |

---

## 4. Empirical Evaluation & Ablation Results

Evaluated via `python run.py --evaluate` on frozen persistent splits (`data/evaluation_report.json`):

### A. Controlled Synthetic Benchmark (Held-Out `test.npz`, N = 1,100)

Evaluates machine learning and heuristic models directly on the normalized sequence feature representations:

| Detection Strategy | Precision | Recall | F1-Score | FPR | Brier Score | ECE | Inference Latency (Mean / p95) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Heuristic Rule Detector** | 0.8743 | 0.9040 | 0.8889 | 0.1083 | 0.0947 | 0.1152 | 0.1124 ms / 0.1361 ms |
| **Baseline Logistic Regression** | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | 0.0010 | 0.3619 ms / 0.6042 ms |
| **Transformer 1×8 (Single-Window)** | 0.9901 | 1.0000 | 0.9950 | 0.0083 | 0.0046 | 0.0057 | 2.3284 ms / 2.6349 ms |
| **Transformer 5×8 (5-Window)** | 0.9960 | 0.9980 | 0.9970 | 0.0033 | 0.0015 | 0.0027 | 3.6627 ms / 4.2207 ms |
| **Transformer 10×8 (10-Window)** | 1.0000 | 0.9680 | 0.9837 | 0.0000 | 0.0095 | 0.0125 | 3.1825 ms / 4.0754 ms |

### B. Independent Evasion Stress Test (`evasion_stress_test.npz`, N = 800)

Stress tests temporal robustness on stochastic Poisson probing intervals ($30\text{s} - 90\text{s}$ per probe) that evade single-window detectors:

| Model Variant | Input Dimension | Precision | Recall | F1-Score | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Baseline Logistic Regression** | $10 \times 8$ (Flattened) | 1.0000 | 0.7000 | 0.8235 | 0.0000 |
| **Transformer 1×8** | $1 \times 8$ (Single Window) | 0.9455 | 0.6500 | 0.7704 | 0.0375 |
| **Transformer 5×8** | $5 \times 8$ (5 Windows) | 0.9376 | 0.9775 | 0.9572 | 0.0650 |
| **Transformer 10×8** | $10 \times 8$ (10 Windows) | **0.9925** | **0.9900** | **0.9912** | **0.0075** |

### C. Lab PCAP Packet Replay Evaluation

Evaluated against genuine offline packet captures:

| Packet Capture | Ground Truth | OFFLINE_RULE_ENGINE / Suricata | Transformer (10×8) | Hybrid Decision |
| :--- | :---: | :---: | :---: | :---: |
| **`lab_benign.pcap`** | BENIGN | 0 alerts (Passed) | Max Score: 0.0040 (TN) | **BENIGN** |
| **`lab_fast_scan.pcap`** | RECON | 8 alerts (`sid:2000001`, `sid:2000006`) | Max Score: 0.9993 (TP) | **HYBRID ALERT** |
| **`lab_stealth_scan.pcap`** | RECON | 0 alerts (Evaded threshold) | Max Score: 0.9993 (TP) | **TRANSFORMER_RECON** |

---

## 5. Security & Reliability Architecture

- **Centralized Health Manager**: Watchdog daemon monitoring 8 subsystems with status states (`UP`, `DEGRADED`, `DOWN`, `ML_UNAVAILABLE`).
- **Bounded In-Memory Structures**: Hard caps on flow tables (50k), IP sequence buffers (10k), cooldown cache (5k), and SIEM export queue (5k).
- **API Security**: Constant-time token verification (`hmac.compare_digest`), dual roles (`VIEWER` / `ADMIN`), strict IP and pagination validation, OWASP security headers, and safe production error masking.
- **Production Secret Management**: Enforced environment variable secrets (`NIDS_ADMIN_API_KEY`, `NIDS_VIEWER_API_KEY`).
- **Automated Test Coverage**: 56 unit, integration, and security tests passing.

---

## 6. Quick Start & Execution

### Setup Environment
```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux:
source .venv/bin/activate

pip install -r requirements.lock
```

### Run Evaluation Suite
```bash
python run.py --evaluate
```

### Start Local Dashboard & Detection Server
```bash
python run.py --mode pcap --pcap-file data/pcaps/lab_stealth_scan.pcap
# Open http://127.0.0.1:5000 in your browser
```

### Run Full Test Suite
```bash
python -m pytest tests
```
