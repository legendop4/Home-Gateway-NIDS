# UNSW-NB15 Integration & Feature Mapping Analysis

## 1. Executive Summary & Purpose
This document provides the technical analysis, feature mapping, temporal representation assessment, and integration roadmap for incorporating the real-world **UNSW-NB15** benchmark dataset into the **Home-Gateway NIDS** platform.

The primary research question is:
> *"Can the temporal Sequence Transformer Encoder detect reconnaissance behaviour (MITRE ATT&CK T1046) when trained on real-world network traffic features while preserving the existing 10 × 60s temporal architecture and Hybrid Decision Engine?"*

---

## 2. Dataset Files & Characteristics

| File Name | Purpose / Contents | Attributes & Schema |
| :--- | :--- | :--- |
| `UNSW_NB15_training-set.csv` | Training + Validation partition (82,332 or 175,341 records) | 45 features + `attack_cat` + `label` (Stripped IP/ports/timestamps) |
| `UNSW_NB15_testing-set.csv` | Final Held-Out Test partition (175,341 or 82,332 records) | 45 features + `attack_cat` + `label` (Stripped IP/ports/timestamps) |
| `NUSW-NB15_features(in).csv` | Feature dictionary (49 features) | Feature name, data type, description |
| `Raw UNSW PCAPs / Raw CSVs 1-4` | Full packet capture / Raw flow traces with 5-tuples and Unix timestamps | Full `srcip`, `dstip`, `sport`, `dsport`, `stime`, `ltime` |

### Attack Selection (Binary Focus)
- **Normal / Benign**: `label = 0`, `attack_cat = 'Normal'`
- **Reconnaissance**: `label = 1`, `attack_cat = 'Reconnaissance'`
- *Other attack categories* (DoS, Exploits, Fuzzers, Generic, Analysis, Backdoor, Shellcode, Worms) are segregated to maintain focus on **Reconnaissance Detection (MITRE ATT&CK T1046)**.

---

## 3. Exact Feature Mapping: Gateway NIDS vs. UNSW-NB15

The Home-Gateway NIDS Transformer operates on a $(10 \times 8)$ tensor representing 10 sliding 60-second windows across 8 behavioral features:

| Our Feature | UNSW-NB15 Column(s) | Derivation Logic | Direct / Derived / Proxy | Confidence |
| :--- | :--- | :--- | :---: | :---: |
| **`dst_port_count`** | `ct_src_dport_ltm` (or `dsport` in raw) | `ct_src_dport_ltm` represents connection count to the same destination port in 100 connections. | **B (Derived / Proxy)** | Medium-High |
| **`dst_ip_count`** | `ct_dst_ltm` / `ct_dst_src_ltm` | `ct_dst_ltm` counts connections to same destination IP in 100 connections. | **B (Derived / Proxy)** | Medium-High |
| **`syn_ratio`** | `state`, `synack`, `tcprtt`, `proto` | In curated CSV, packet-level TCP flag counts are not stored. Derived via connection state (`state in ['ACC', 'CON', 'REQ']`) and handshake latency (`synack > 0`). | **C (Approximate Proxy)** | Medium |
| **`syn_ack_ratio`** | `synack`, `ackdat`, `state` | Handshake timing components ($tcprtt = synack + ackdat$) indicate handshake completion. | **C (Approximate Proxy)** | Medium |
| **`rst_ratio`** | `state` (`state == 'RST'`) | Evaluated via flow termination status (`state == 'RST'`). | **B (Derived Proxy)** | Medium-High |
| **`packet_rate`** | `rate` / `(spkts + dpkts) / dur` | Direct flow packet rate: $(spkts + dpkts) / \max(dur, 0.001)$. | **A (Directly Available)** | High |
| **`byte_rate`** | `sload` + `dload` / `(sbytes + dbytes) / dur` | Direct flow throughput in bytes/second: $(sbytes + dbytes) / \max(dur, 0.001)$. | **A (Directly Available)** | High |
| **`flow_duration_mean`** | `dur` | Direct record flow duration in seconds. | **A (Directly Available)** | High |

---

## 4. Temporal Representation & Windowing Feasibility

### Production Gateway Pipeline
```text
Raw Packets → PacketSummary → FlowTracker → WindowSequencer (60s sliding buckets) → 10x8 Tensor
```

### UNSW-NB15 Curated CSV vs. Raw PCAP Distinction
1. **Curated CSV (`training-set.csv` / `testing-set.csv`)**:
   - Authors removed `srcip`, `dstip`, `stime`, `ltime` to prevent ML models from memorizing IP subnets.
   - Sequential grouping can be constructed using sequential row windows or flow clusters, but does not represent physical wall-clock 60-second time intervals.
2. **Raw UNSW PCAP Captures / Raw CSVs (`UNSW-NB15_1..4.csv`)**:
   - Contain genuine epoch timestamps (`stime`, `ltime`) and source IPs (`srcip`).
   - Feed directly into our existing `nids/ml/pcap_parser.py` and `WindowSequencer` without any architectural modification.

---

## 5. Role of Datasets in Research Setup

| Dataset | Role in Research Setup |
| :--- | :--- |
| **Real UNSW-NB15** | **Primary ML Training & Evaluation Source** for academic validity and real network flow benchmarks. |
| **Synthetic Dataset** | **Controlled Stress Testing & Reproducibility** (evasion stress tests, stochastic Poisson jitter, controlled temporal ablations). |
| **Lab PCAP Replay** | **End-to-End Pipeline Integration** (validates Suricata + Transformer + DecisionEngine fusion). |
## 6. Authoritative Empirical Evaluation Results (models/transformer_recon_unsw.pt)

Evaluated strictly on the held-out `test.npz` (derived from `UNSW_NB15_testing-set.csv`, $N = 8,098$ sequences):
- **Model Checkpoint SHA-256**: `8cb52fbd6cbd56b87a12d77922ce30d22df5778cbdf09de893813a92f6e64ed7`
- **Test Dataset SHA-256**: `0b70af2e0ce1633b9469ee8c20a5fd71f43dd2e0351d3c0fc1b6c55339a0f638`
- **Class Breakdown**: Normal = 7,395, Reconnaissance = 703
- **Global Discrimination**: **ROC-AUC = 0.9961**, **PR-AUC = 0.9772**, **Brier Score = 0.1123**, **ECE = 0.2072**
- **Calibrated Temperature ($T$)**: **1.0016**

### Performance Across Decision Thresholds

| Metric | Standard Threshold (0.50) | Gateway Decision Threshold (0.70) | Operational Significance |
| :--- | :---: | :---: | :--- |
| **Accuracy** | 83.39% | **94.53%** | Sequence classification accuracy. |
| **Precision** | 34.30% | **61.48%** | Higher threshold eliminates 67.5% of false positives. |
| **Recall / Sensitivity** | 99.72% (701 / 703) | **99.00% (696 / 703)** | Exceptional attack capture rate (only 7 missed scans). |
| **F1-Score** | 51.04% | **75.86%** | Balanced precision/recall at operating point. |
| **False Positive Rate (FPR)** | 18.16% | **5.90%** | Reduced to manageable rate for gateway alerts. |
| **Confusion Matrix** | `TN=6052, FP=1343, FN=2, TP=701` | `TN=6959, FP=436, FN=7, TP=696` | Downstream Suricata fusion further mitigates FPs. |

---

## 7. Critical Scientific Verification: Sequence Construction Methodology

### Method Classification: Constructed 10-Flow Sequences (Method B)
Because the curated `UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` stripped original packet timestamps (`stime`, `ltime`) and source IP addresses (`srcip`) to prevent static memorization, sequences generated from these CSV files represent **constructed 10-flow rolling sequences**, NOT genuine 60-second source-IP temporal windows.

- **What is validated**: Demonstrates that the Transformer architecture learns non-linear feature correlations across consecutive flow transactions.
- **What requires raw PCAP replay**: Genuine wall-clock 60-second temporal window aggregation per Source IP (tested via `lab_fast_scan.pcap` / `lab_stealth_scan.pcap` through `FlowTracker` and `WindowSequencer`).
