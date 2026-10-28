"""
Suricata & Deterministic Rule Evaluation Subsystem.
Explicitly distinguishes:
- REAL_SURICATA (Live binary execution via CLI)
- OFFLINE_RULE_ENGINE (Rule-compatible Python inspection matching recon.rules)
Measures genuine wall clock latency, p50, and p95 without hardcoded estimates.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import subprocess
import shutil
import json
import time
import re
import numpy as np
import scapy.all as scapy_all

from .eve_streamer import SuricataEvent, SuricataEveStreamer
from .adapters import scapy_pkt_to_summary


SURICATA_MODE_REAL = "REAL_SURICATA"
SURICATA_MODE_OFFLINE = "OFFLINE_RULE_ENGINE"


@dataclass
class SignatureRule:
    sid: int
    msg: str
    flags: str  # "S", "F", "0", "FPU", etc.
    threshold_count: int = 1
    threshold_seconds: float = 60.0


class OfflineSuricataEngine:
    """
    Offline deterministic rule evaluator parsing and enforcing recon.rules.
    Explicitly labeled as OFFLINE_RULE_ENGINE to distinguish from real Suricata binary.
    """

    def __init__(self, rules_path: str = "config/rules/recon.rules", max_tracked_entries: int = 5000):
        self.rules_path = Path(rules_path)
        self.max_tracked_entries = max_tracked_entries
        self.rules: List[SignatureRule] = self._load_rules()
        # Map: (sid, src_ip) -> list of matching packet timestamps
        self.threshold_tracker: Dict[Tuple[int, str], List[float]] = {}

    def _load_rules(self) -> List[SignatureRule]:
        rules = []
        if self.rules_path.exists():
            with open(self.rules_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    
                    # Regex extraction of Suricata rule parameters
                    sid_match = re.search(r"sid:(\d+);", line)
                    msg_match = re.search(r'msg:"([^"]+)";', line)
                    flags_match = re.search(r"flags:([A-Z0-9,]+);", line)
                    thresh_match = re.search(r"count\s+(\d+),\s+seconds\s+(\d+)", line)

                    if sid_match and msg_match:
                        sid = int(sid_match.group(1))
                        msg = msg_match.group(1)
                        flags = flags_match.group(1) if flags_match else "S"
                        count = int(thresh_match.group(1)) if thresh_match else 1
                        secs = float(thresh_match.group(2)) if thresh_match else 60.0

                        rules.append(SignatureRule(
                            sid=sid,
                            msg=msg,
                            flags=flags,
                            threshold_count=count,
                            threshold_seconds=secs,
                        ))

        if not rules:
            # Fallback default rules if file is missing
            rules = [
                SignatureRule(sid=2000001, msg="ET SCAN Potential Nmap SYN Scan", flags="S", threshold_count=20, threshold_seconds=5.0),
                SignatureRule(sid=2000002, msg="ET SCAN Nmap FIN Scan", flags="F", threshold_count=1, threshold_seconds=60.0),
                SignatureRule(sid=2000003, msg="ET SCAN Nmap NULL Scan", flags="0", threshold_count=1, threshold_seconds=60.0),
                SignatureRule(sid=2000004, msg="ET SCAN Nmap XMAS Scan", flags="FPU", threshold_count=1, threshold_seconds=60.0),
                SignatureRule(sid=2000005, msg="ET SCAN Rapid Multi-Port Scan Detected", flags="S", threshold_count=50, threshold_seconds=10.0),
                SignatureRule(sid=2000006, msg="ET SCAN Stealth Port Scan Probe", flags="S", threshold_count=15, threshold_seconds=60.0),
            ]
        return rules

    def _prune_tracker(self, now: float) -> None:
        """Evicts expired tracking state and bounds table size."""
        if len(self.threshold_tracker) > self.max_tracked_entries:
            expired = [k for k, v in self.threshold_tracker.items() if not v or (now - v[-1]) > 120.0]
            for k in expired:
                del self.threshold_tracker[k]
            if len(self.threshold_tracker) > self.max_tracked_entries:
                # Force drop oldest 10%
                for k in list(self.threshold_tracker.keys())[:int(self.max_tracked_entries * 0.10)]:
                    del self.threshold_tracker[k]

    def evaluate_summary(self, summary: PacketSummary) -> List[SuricataEvent]:
        if not summary or summary.protocol != "TCP":
            return []

        matched_events = []
        ts = summary.timestamp
        src_ip = summary.src_ip

        self._prune_tracker(ts)

        for rule in self.rules:
            flag_match = False
            if rule.flags == "S" and summary.is_syn and not summary.is_ack:
                flag_match = True
            elif rule.flags == "F" and summary.is_fin and not summary.is_syn and not summary.is_ack:
                flag_match = True
            elif rule.flags == "0" and summary.raw_flags == 0:
                flag_match = True
            elif "FPU" in rule.flags and (summary.raw_flags & 0x29) == 0x29:  # FIN + PSH + URG
                flag_match = True

            if flag_match:
                key = (rule.sid, src_ip)
                if key not in self.threshold_tracker:
                    self.threshold_tracker[key] = []

                # Slide threshold window
                self.threshold_tracker[key] = [t for t in self.threshold_tracker[key] if (ts - t) <= rule.threshold_seconds]
                self.threshold_tracker[key].append(ts)

                if len(self.threshold_tracker[key]) >= rule.threshold_count:
                    event = SuricataEvent(
                        timestamp=ts,
                        iso_timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
                        src_ip=src_ip,
                        dst_ip=summary.dst_ip,
                        src_port=summary.src_port,
                        dst_port=summary.dst_port,
                        protocol="TCP",
                        event_type="alert",
                        signature=rule.msg,
                        signature_id=rule.sid,
                        category="Attempted Information Leak",
                        severity=2,
                        raw_event={}
                    )
                    matched_events.append(event)
                    self.threshold_tracker[key] = []

        return matched_events

    def evaluate_packet(self, pkt) -> List[SuricataEvent]:
        summary = scapy_pkt_to_summary(pkt)
        return self.evaluate_summary(summary) if summary else []

    def evaluate_pcap(self, pcap_path: str) -> Tuple[List[SuricataEvent], Dict[str, float]]:
        """Processes entire PCAP and returns alerts alongside measured execution latency."""
        alerts = []
        packet_latencies_ns = []
        try:
            reader = scapy_all.PcapReader(pcap_path)
            for pkt in reader:
                t0 = time.perf_counter_ns()
                evs = self.evaluate_packet(pkt)
                t1 = time.perf_counter_ns()
                packet_latencies_ns.append(t1 - t0)
                alerts.extend(evs)
            reader.close()
        except Exception as e:
            print(f"[OfflineSuricataEngine] Error reading {pcap_path}: {e}")

        if packet_latencies_ns:
            lat_arr = np.array(packet_latencies_ns) / 1e6
            lat_dict = {
                "sample_count": len(lat_arr),
                "mean_ms": float(round(float(np.mean(lat_arr)), 4)),
                "p50_ms": float(round(float(np.percentile(lat_arr, 50)), 4)),
                "p95_ms": float(round(float(np.percentile(lat_arr, 95)), 4)),
            }
        else:
            lat_dict = {"sample_count": 0, "mean_ms": 0.0, "p50_ms": 0.0, "p95_ms": 0.0}

        return alerts, lat_dict


def get_suricata_execution_mode() -> str:
    """Returns REAL_SURICATA if binary is in PATH, else OFFLINE_RULE_ENGINE."""
    return SURICATA_MODE_REAL if shutil.which("suricata") else SURICATA_MODE_OFFLINE


def run_suricata_on_pcap(
    pcap_path: str,
    rules_path: str = "config/rules/recon.rules"
) -> Tuple[List[SuricataEvent], str, Dict[str, float]]:
    """
    Executes actual Suricata binary if available, or OfflineSuricataEngine fallback.
    Returns (alerts, execution_mode, latency_dict).
    """
    suricata_bin = shutil.which("suricata")
    if suricata_bin:
        import tempfile
        temp_dir = tempfile.mkdtemp(prefix="suricata_eval_")
        t_start = time.perf_counter_ns()
        try:
            cmd = [
                suricata_bin,
                "-r", pcap_path,
                "-l", temp_dir,
                "-S", rules_path,
                "--runmode", "single",
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            t_end = time.perf_counter_ns()
            wall_ms = (t_end - t_start) / 1e6
            eve_file = Path(temp_dir) / "eve.json"
            if eve_file.exists():
                streamer = SuricataEveStreamer(eve_path=str(eve_file))
                alerts = []
                with open(eve_file, "r", encoding="utf-8") as f:
                    for line in f:
                        ev = streamer.parse_event(line)
                        if ev:
                            alerts.append(ev)
                lat_dict = {
                    "sample_count": 1,
                    "wall_clock_ms": float(round(wall_ms, 2)),
                    "mean_ms": float(round(wall_ms, 2)),
                    "p50_ms": float(round(wall_ms, 2)),
                    "p95_ms": float(round(wall_ms, 2)),
                }
                return alerts, SURICATA_MODE_REAL, lat_dict
        except Exception as e:
            print(f"[Suricata] Subprocess execution failed ({e}). Falling back to OFFLINE_RULE_ENGINE.")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    # Use offline deterministic engine
    engine = OfflineSuricataEngine(rules_path=rules_path)
    alerts, lat_dict = engine.evaluate_pcap(pcap_path)
    return alerts, SURICATA_MODE_OFFLINE, lat_dict
