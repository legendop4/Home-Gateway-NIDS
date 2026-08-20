"""
Database Models & Schemas for Home-Gateway NIDS.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Optional, Any
import time


@dataclass
class AlertRecord:
    timestamp: float
    iso_timestamp: str
    src_ip: str
    dst_ip: str
    attack_family: str  # "Reconnaissance / Fast Scan", "Reconnaissance / Stealth Scan"
    detection_method: str  # "SURICATA", "TRANSFORMER", "HYBRID"
    confidence_score: float  # Calibrated model score or 1.0 for signature
    suricata_signature: Optional[str] = None
    suricata_sid: Optional[int] = None
    ml_status: str = "ACTIVE"  # "ACTIVE", "ML_UNAVAILABLE"
    details: Optional[str] = None
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DeviceRecord:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    first_seen: float = 0.0
    last_seen: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    risk_level: str = "LOW"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    alert_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FlowMetricRecord:
    timestamp: float
    src_ip: str
    dst_port_count: float
    dst_ip_count: float
    syn_ratio: float
    syn_ack_ratio: float
    rst_ratio: float
    packet_rate: float
    byte_rate: float
    flow_duration_mean: float
    anomaly_score: float
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SystemLogRecord:
    timestamp: float
    level: str
    component: str
    message: str
    id: Optional[int] = None
