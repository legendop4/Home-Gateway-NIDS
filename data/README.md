# Data & Telemetry Directory

This directory contains runtime databases, SIEM export streams, reproducible lab PCAPs, and scientific evaluation benchmarks for Home-Gateway NIDS.

## Directory Structure & Artifacts

### 1. Runtime Telemetry & Databases
* **`nids.db`**: SQLite database in WAL (Write-Ahead Logging) mode storing:
  - `alerts`: Intrusion alerts categorized by detection method (`SURICATA`, `TRANSFORMER_RECON`, `HYBRID`).
  - `devices`: Connected gateway hosts on the `192.168.10.X` subnet, packet counters, and risk profiles.
  - `flow_metrics`: 8-feature rolling window metrics for real-time frontend charts.
* **`siem_alerts.jsonl`**: Real-time event log streamed in Splunk / Elastic Common Schema (ECS) format for SIEM ingestion.

### 2. Lab Replay Captures (`pcaps/`)
* **`lab_benign.pcap`**: Baseline normal web browsing traffic (HTTP/HTTPS/DNS). Result: 0 alerts, Transformer anomaly score 0.0040.
* **`lab_fast_scan.pcap`**: Aggressive TCP SYN port scan across multiple ports. Result: Suricata `sid:2000001` match + Transformer score 0.9993 $\rightarrow$ **`HYBRID` Alert**.
* **`lab_stealth_scan.pcap`**: Low-and-slow reconnaissance probe using Poisson jitter to evade count thresholds. Result: Suricata 0 alerts + Transformer score 0.9993 $\rightarrow$ **`TRANSFORMER_RECON` Alert**.

### 3. Scientific Benchmark Reports
* **`authoritative_unsw_evaluation_report.json`**: Official evaluation of `models/transformer_recon_unsw.pt` on held-out UNSW-NB15 test sequences ($N = 8,098$). Verified metrics:
  - Accuracy: **94.53%** (at operating threshold 0.70)
  - Recall / Sensitivity: **99.00%** (696 / 703 true attacks detected)
  - ROC-AUC: **0.9961**
  - PR-AUC: **0.9772**
* **`evaluation_report.json`**: Latency, ECE calibration, and temporal ablation metrics comparing $1 \times 8$, $5 \times 8$, and $10 \times 8$ Sequence Transformers against heuristic and linear baselines.
