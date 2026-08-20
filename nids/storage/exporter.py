"""
SIEM Exporter: Asynchronous bounded queue exporter formatting alerts into ECS JSONL and CEF streams.
Includes overflow tracking, background thread dispatching, and sanitization.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import json
import queue
import threading
import time

from .models import AlertRecord


class SiemExporter:
    """
    Asynchronous, bounded-queue SIEM exporter writing formatted alerts to JSON-Lines.
    Defends against disk I/O bottlenecks and memory exhaustion.
    """

    def __init__(self, export_file_path: str = "data/siem_alerts.jsonl", max_queue_size: int = 5000):
        self.export_file_path = Path(export_file_path)
        self.export_file_path.parent.mkdir(parents=True, exist_ok=True)
        self.max_queue_size = max_queue_size
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self.dropped_events_count = 0
        self.total_exported_count = 0
        self._running = True

        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="SiemExporterWorker")
        self._worker_thread.start()

    def to_cef(self, alert: AlertRecord) -> str:
        """
        Format alert into ArcSight Common Event Format (CEF) standard.
        Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        """
        from ..security.sanitization import sanitize_for_cef
        severity = 8 if alert.detection_method == "HYBRID" else 5
        family_clean = sanitize_for_cef(alert.attack_family)
        src_clean = sanitize_for_cef(alert.src_ip)
        dst_clean = sanitize_for_cef(alert.dst_ip)
        method_clean = sanitize_for_cef(alert.detection_method)
        ml_clean = sanitize_for_cef(alert.ml_status)
        details_clean = sanitize_for_cef(alert.details or "Reconnaissance activity detected")

        cef_str = (
            f"CEF:0|HomeGateway|NIDS|1.0|RECON|{family_clean}|{severity}|"
            f"src={src_clean} dst={dst_clean} act=alert "
            f"cs1Label=DetectionMethod cs1={method_clean} "
            f"cs2Label=MLStatus cs2={ml_clean} "
            f"cfp1Label=ConfidenceScore cfp1={alert.confidence_score:.4f} "
            f"msg={details_clean}"
        )
        return cef_str

    def to_siem_json(self, alert: AlertRecord) -> Dict[str, Any]:
        """
        Format alert into Elastic / Splunk ECS (Elastic Common Schema) compatible JSON.
        """
        from ..security.sanitization import sanitize_for_log
        return {
            "@timestamp": alert.iso_timestamp,
            "event": {
                "kind": "alert",
                "category": ["network", "intrusion_detection"],
                "type": ["info"],
                "module": "nids",
                "dataset": "nids.reconnaissance",
                "action": "detected",
                "severity": 3 if alert.detection_method == "HYBRID" else 2,
            },
            "source": {
                "ip": sanitize_for_log(alert.src_ip),
            },
            "destination": {
                "ip": sanitize_for_log(alert.dst_ip),
            },
            "threat": {
                "framework": "MITRE ATT&CK",
                "tactic": {"name": "Reconnaissance", "id": "TA0043"},
                "technique": {"name": "Network Service Discovery", "id": "T1046"},
            },
            "nids": {
                "attack_family": sanitize_for_log(alert.attack_family),
                "detection_method": sanitize_for_log(alert.detection_method),
                "confidence_score": round(alert.confidence_score, 4),
                "ml_status": sanitize_for_log(alert.ml_status),
                "suricata_signature": sanitize_for_log(alert.suricata_signature) if alert.suricata_signature else None,
                "suricata_sid": alert.suricata_sid,
                "details": sanitize_for_log(alert.details) if alert.details else None,
            }
        }

    def export(self, alert: AlertRecord) -> bool:
        """
        Enqueues alert for asynchronous export. Returns True if queued, False if dropped due to queue overflow.
        """
        from ..health import get_health_manager
        health_mgr = get_health_manager()
        json_record = self.to_siem_json(alert)

        try:
            self._queue.put_nowait(json_record)
            health_mgr.heartbeat("siem_exporter", {
                "queue_depth": self._queue.qsize(),
                "dropped_events": self.dropped_events_count,
            })
            return True
        except queue.Full:
            self.dropped_events_count += 1
            health_mgr.record_error(
                "siem_exporter",
                f"SIEM export queue full (depth {self.max_queue_size}); dropped {self.dropped_events_count} events",
                degrade=True
            )
            return False

    def _worker_loop(self) -> None:
        """Background thread writing queued alerts to JSONL log file."""
        while self._running:
            try:
                item = self._queue.get(timeout=0.2)
                line = json.dumps(item) + "\n"
                with open(self.export_file_path, "a", encoding="utf-8") as f:
                    f.write(line)
                self.total_exported_count += 1
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                from ..health import get_health_manager
                get_health_manager().record_error("siem_exporter", f"File write error: {e}", degrade=True)

    def flush(self) -> None:
        """Blocks until all queued events are written to disk."""
        self._queue.join()

    def close(self) -> None:
        self.flush()
        self._running = False
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.0)
