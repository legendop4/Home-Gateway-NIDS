"""
Hybrid Decision Fusion Engine: Combines Suricata signature detections
and calibrated Transformer sequence scores into unified alerts.
"""

from typing import Dict, Optional, Tuple
import datetime
import time
import threading
import numpy as np

from ..capture.eve_streamer import SuricataEvent
from ..feature_extraction.window_sequencer import WindowSequencer
from ..ml.transformer_model import TransformerInferenceEngine
from ..storage.database import NidsDatabase
from ..storage.exporter import SiemExporter
from ..storage.models import AlertRecord, FlowMetricRecord


class DecisionEngine:
    """
    Evaluates signature alerts and 10x60s sequence anomaly scores.
    Handles graceful ML_UNAVAILABLE states and persists validated alerts.
    """

    def __init__(
        self,
        db: NidsDatabase,
        exporter: SiemExporter,
        transformer_engine: TransformerInferenceEngine,
        sequencer: WindowSequencer,
        decision_threshold: float = 0.70,
        alert_cooldown_sec: float = 120.0,
        min_packets_for_ml: int = 5,
        max_pending_alerts: int = 5000,
    ):
        self.db = db
        self.exporter = exporter
        self.ml_engine = transformer_engine
        self.sequencer = sequencer
        self.decision_threshold = decision_threshold
        self.alert_cooldown_sec = alert_cooldown_sec
        self.min_packets_for_ml = min_packets_for_ml
        self.max_pending_alerts = max_pending_alerts

        self._last_alert_time: Dict[str, float] = {}
        self._pending_suricata: Dict[str, SuricataEvent] = {}
        self._lock = threading.Lock()

    def _prune_cooldown_cache(self, current_time: float) -> None:
        """Evicts expired cooldown entries or enforces max bound."""
        if len(self._last_alert_time) >= self.max_pending_alerts:
            cutoff = current_time - (self.alert_cooldown_sec * 2)
            expired = [ip for ip, ts in self._last_alert_time.items() if ts < cutoff]
            for ip in expired:
                self._last_alert_time.pop(ip, None)
                self._pending_suricata.pop(ip, None)

            # If still at or over limit, drop oldest entries to leave space for new entry
            if len(self._last_alert_time) >= self.max_pending_alerts:
                excess = (len(self._last_alert_time) - self.max_pending_alerts) + max(1, int(self.max_pending_alerts * 0.10))
                sorted_ips = sorted(self._last_alert_time.keys(), key=lambda ip: self._last_alert_time[ip])
                for ip in sorted_ips[:excess]:
                    self._last_alert_time.pop(ip, None)
                    self._pending_suricata.pop(ip, None)

    def handle_suricata_event(self, event: SuricataEvent) -> Optional[AlertRecord]:
        """
        Process a Suricata signature alert and immediately evaluate against current ML sequence.
        """
        with self._lock:
            src_ip = event.src_ip
            now = time.time()
            self._prune_cooldown_cache(now)

            from ..health import get_health_manager, HealthStatus
            health_mgr = get_health_manager()
            health_mgr.heartbeat("fusion_engine")
            health_mgr.heartbeat("suricata", {"last_signature": event.signature, "src_ip": src_ip})

            # Store pending signature
            self._pending_suricata[src_ip] = event

            # Check cooldown
            if (now - self._last_alert_time.get(src_ip, 0.0)) < self.alert_cooldown_sec:
                return None

            # Get 10x60s sequence for this source IP
            seq, mask = self.sequencer.get_sequence_tensor(src_ip, include_active=True)

            ml_score = 0.0
            ml_status = "ACTIVE"
            try:
                if self.ml_engine.is_available:
                    ml_score = self.ml_engine.predict_score(seq, mask)
                else:
                    ml_status = "ML_UNAVAILABLE"
            except Exception:
                ml_status = "ML_UNAVAILABLE"

            # Determine detection method
            if ml_status == "ACTIVE" and ml_score >= self.decision_threshold:
                method = "HYBRID"
                family = "Reconnaissance / Fast Scan"
                conf = float(round(ml_score, 4))
                details = f"Suricata rule match [{event.signature}] confirmed by Sequence Transformer anomaly score ({ml_score:.2f})."
            else:
                method = "SURICATA"
                family = "Reconnaissance / Fast Scan"
                conf = 1.0  # Signature certainty
                if ml_status == "ML_UNAVAILABLE":
                    details = f"Suricata rule match [{event.signature}]. Notice: ML engine is ML_UNAVAILABLE."
                else:
                    details = f"Suricata rule match [{event.signature}]. ML score ({ml_score:.2f}) below threshold."

            iso_ts = datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc).isoformat()
            alert = AlertRecord(
                timestamp=now,
                iso_timestamp=iso_ts,
                src_ip=src_ip,
                dst_ip=event.dst_ip,
                attack_family=family,
                detection_method=method,
                confidence_score=conf,
                suricata_signature=event.signature,
                suricata_sid=event.signature_id,
                ml_status=ml_status,
                details=details,
            )

            # Persist and export
            alert_id = self.db.insert_alert(alert)
            alert.id = alert_id
            self.exporter.export(alert)
            self._last_alert_time[src_ip] = now
            return alert

    def evaluate_periodic_ml(self, src_ip: str) -> Optional[AlertRecord]:
        """
        Periodically called per active IP to catch slow/stealth scans that evade Suricata signatures.
        """
        with self._lock:
            now = time.time()
            from ..health import get_health_manager, HealthStatus
            health_mgr = get_health_manager()
            health_mgr.heartbeat("fusion_engine")

            if (now - self._last_alert_time.get(src_ip, 0.0)) < self.alert_cooldown_sec:
                return None

            seq, mask = self.sequencer.get_sequence_tensor(src_ip, include_active=True)

            # Check if there is sufficient traffic activity
            total_active_packets = np.sum(seq[:, 5]) * 60.0  # sum(packet_rate * 60)
            if total_active_packets < self.min_packets_for_ml:
                return None

            ml_status = "ACTIVE"
            try:
                if not self.ml_engine.is_available:
                    health_mgr.update_status("transformer", HealthStatus.ML_UNAVAILABLE, message="Transformer weights missing or model disabled")
                    return None
                ml_score = self.ml_engine.predict_score(seq, mask)
                health_mgr.heartbeat("transformer", {"last_evaluated_ip": src_ip, "last_score": round(ml_score, 4)})
            except Exception as e:
                health_mgr.record_error("transformer", str(e))
                return None

            # Log metric to DB for graphs
            latest_win = seq[-1]
            metric = FlowMetricRecord(
                timestamp=now,
                src_ip=src_ip,
                dst_port_count=float(latest_win[0]),
                dst_ip_count=float(latest_win[1]),
                syn_ratio=float(latest_win[2]),
                syn_ack_ratio=float(latest_win[3]),
                rst_ratio=float(latest_win[4]),
                packet_rate=float(latest_win[5]),
                byte_rate=float(latest_win[6]),
                flow_duration_mean=float(latest_win[7]),
                anomaly_score=float(round(ml_score, 4)),
            )
            self.db.insert_metric(metric)

            # Trigger alert if ML score exceeds threshold
            if ml_score >= self.decision_threshold:
                iso_ts = datetime.datetime.fromtimestamp(now, tz=datetime.timezone.utc).isoformat()
                alert = AlertRecord(
                    timestamp=now,
                    iso_timestamp=iso_ts,
                    src_ip=src_ip,
                    dst_ip="Target Subnet",
                    attack_family="Reconnaissance / Stealth Scan",
                    detection_method="TRANSFORMER_RECON",
                    confidence_score=float(round(ml_score, 4)),
                    suricata_signature=None,
                    suricata_sid=None,
                    ml_status="ACTIVE",
                    details=f"Multi-window stealth reconnaissance pattern detected by 10x60s Transformer (Score: {ml_score:.2f}).",
                )
                alert_id = self.db.insert_alert(alert)
                alert.id = alert_id
                self.exporter.export(alert)
                self._last_alert_time[src_ip] = now
                return alert

            return None
