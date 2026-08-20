"""
SQLite Database manager with WAL mode, indexing, connection management,
and resilient error boundary integration with SystemHealthManager.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import sqlite3
import threading
import time

from .models import AlertRecord, DeviceRecord, FlowMetricRecord
from ..health import get_health_manager, HealthStatus


class NidsDatabase:
    """Thread-safe, resilient SQLite database manager for Home-Gateway NIDS."""

    def __init__(self, db_path: str = "data/nids.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        health_mgr = get_health_manager()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    # Alerts table
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS alerts (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp REAL NOT NULL,
                            iso_timestamp TEXT NOT NULL,
                            src_ip TEXT NOT NULL,
                            dst_ip TEXT NOT NULL,
                            attack_family TEXT NOT NULL,
                            detection_method TEXT NOT NULL,
                            confidence_score REAL NOT NULL,
                            suricata_signature TEXT,
                            suricata_sid INTEGER,
                            ml_status TEXT NOT NULL DEFAULT 'ACTIVE',
                            details TEXT
                        );
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp DESC);")
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip);")

                    # Devices table
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS devices (
                            ip TEXT PRIMARY KEY,
                            mac TEXT,
                            hostname TEXT,
                            first_seen REAL NOT NULL,
                            last_seen REAL NOT NULL,
                            total_packets INTEGER DEFAULT 0,
                            total_bytes INTEGER DEFAULT 0,
                            risk_level TEXT DEFAULT 'LOW',
                            alert_count INTEGER DEFAULT 0
                        );
                    """)

                    # Flow metrics table
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS flow_metrics (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp REAL NOT NULL,
                            src_ip TEXT NOT NULL,
                            dst_port_count REAL NOT NULL,
                            dst_ip_count REAL NOT NULL,
                            syn_ratio REAL NOT NULL,
                            syn_ack_ratio REAL NOT NULL,
                            rst_ratio REAL NOT NULL,
                            packet_rate REAL NOT NULL,
                            byte_rate REAL NOT NULL,
                            flow_duration_mean REAL NOT NULL,
                            anomaly_score REAL NOT NULL
                        );
                    """)
                    conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_ts ON flow_metrics(timestamp DESC);")

                    # System logs table
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS system_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp REAL NOT NULL,
                            level TEXT NOT NULL,
                            component TEXT NOT NULL,
                            message TEXT NOT NULL
                        );
                    """)
                    conn.commit()
                    health_mgr.heartbeat("sqlite", {"db_path": str(self.db_path)})
            except Exception as e:
                health_mgr.update_status("sqlite", HealthStatus.DOWN, message=f"SQLite initialization failed: {e}")
                raise

    def insert_alert(self, alert: AlertRecord) -> int:
        health_mgr = get_health_manager()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("""
                        INSERT INTO alerts (
                            timestamp, iso_timestamp, src_ip, dst_ip, attack_family,
                            detection_method, confidence_score, suricata_signature,
                            suricata_sid, ml_status, details
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        alert.timestamp, alert.iso_timestamp, alert.src_ip, alert.dst_ip,
                        alert.attack_family, alert.detection_method, alert.confidence_score,
                        alert.suricata_signature, alert.suricata_sid, alert.ml_status, alert.details
                    ))
                    alert_id = cursor.lastrowid

                    # Update device risk level
                    conn.execute("""
                        UPDATE devices
                        SET alert_count = alert_count + 1,
                            risk_level = CASE
                                WHEN alert_count >= 3 THEN 'CRITICAL'
                                WHEN alert_count >= 1 THEN 'HIGH'
                                ELSE 'MEDIUM'
                            END
                        WHERE ip = ?
                    """, (alert.src_ip,))
                    conn.commit()
                    health_mgr.heartbeat("sqlite")
                    return alert_id
            except Exception as e:
                health_mgr.record_error("sqlite", f"Failed to insert alert: {e}", degrade=True)
                return -1

    def get_recent_alerts(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        health_mgr = get_health_manager()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("""
                        SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ? OFFSET ?
                    """, (limit, offset))
                    rows = [dict(row) for row in cursor.fetchall()]
                    health_mgr.heartbeat("sqlite")
                    return rows
            except Exception as e:
                health_mgr.record_error("sqlite", f"Failed to read alerts: {e}", degrade=True)
                return []

    def upsert_device(self, ip: str, mac: Optional[str] = None, hostname: Optional[str] = None, delta_packets: int = 0, delta_bytes: int = 0) -> None:
        health_mgr = get_health_manager()
        now = time.time()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute("""
                        INSERT INTO devices (ip, mac, hostname, first_seen, last_seen, total_packets, total_bytes)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(ip) DO UPDATE SET
                            mac = COALESCE(excluded.mac, devices.mac),
                            hostname = COALESCE(excluded.hostname, devices.hostname),
                            last_seen = excluded.last_seen,
                            total_packets = devices.total_packets + excluded.total_packets,
                            total_bytes = devices.total_bytes + excluded.total_bytes
                    """, (ip, mac, hostname, now, now, delta_packets, delta_bytes))
                    conn.commit()
                    health_mgr.heartbeat("sqlite")
            except Exception as e:
                health_mgr.record_error("sqlite", f"Failed to upsert device: {e}", degrade=True)

    def get_all_devices(self) -> List[Dict[str, Any]]:
        health_mgr = get_health_manager()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC")
                    rows = [dict(row) for row in cursor.fetchall()]
                    health_mgr.heartbeat("sqlite")
                    return rows
            except Exception as e:
                health_mgr.record_error("sqlite", f"Failed to read devices: {e}", degrade=True)
                return []

    def insert_metric(self, metric: FlowMetricRecord) -> None:
        health_mgr = get_health_manager()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    conn.execute("""
                        INSERT INTO flow_metrics (
                            timestamp, src_ip, dst_port_count, dst_ip_count,
                            syn_ratio, syn_ack_ratio, rst_ratio, packet_rate,
                            byte_rate, flow_duration_mean, anomaly_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        metric.timestamp, metric.src_ip, metric.dst_port_count,
                        metric.dst_ip_count, metric.syn_ratio, metric.syn_ack_ratio,
                        metric.rst_ratio, metric.packet_rate, metric.byte_rate,
                        metric.flow_duration_mean, metric.anomaly_score
                    ))
                    conn.commit()
                    health_mgr.heartbeat("sqlite")
            except Exception as e:
                health_mgr.record_error("sqlite", f"Failed to insert flow metric: {e}", degrade=True)

    def get_recent_metrics(self, limit: int = 60) -> List[Dict[str, Any]]:
        health_mgr = get_health_manager()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.execute("""
                        SELECT * FROM flow_metrics ORDER BY timestamp DESC LIMIT ?
                    """, (limit,))
                    rows = cursor.fetchall()
                    health_mgr.heartbeat("sqlite")
                    return [dict(row) for row in reversed(rows)]
            except Exception as e:
                health_mgr.record_error("sqlite", f"Failed to read metrics: {e}", degrade=True)
                return []

    def get_stats_summary(self) -> Dict[str, Any]:
        health_mgr = get_health_manager()
        with self._lock:
            try:
                with self._get_connection() as conn:
                    total_alerts = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
                    high_risk = conn.execute("SELECT COUNT(*) as c FROM devices WHERE risk_level IN ('HIGH', 'CRITICAL')").fetchone()["c"]
                    total_devices = conn.execute("SELECT COUNT(*) as c FROM devices").fetchone()["c"]

                    # Alert breakdown by method
                    methods = conn.execute("""
                        SELECT detection_method, COUNT(*) as c FROM alerts GROUP BY detection_method
                    """).fetchall()
                    method_dist = {row["detection_method"]: row["c"] for row in methods}

                    health_mgr.heartbeat("sqlite")
                    return {
                        "total_alerts": total_alerts,
                        "high_risk_devices": high_risk,
                        "total_devices": total_devices,
                        "detection_methods": method_dist,
                    }
            except Exception as e:
                health_mgr.record_error("sqlite", f"Failed to get stats summary: {e}", degrade=True)
                return {
                    "total_alerts": 0,
                    "high_risk_devices": 0,
                    "total_devices": 0,
                    "detection_methods": {},
                }
