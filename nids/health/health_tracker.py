"""
Centralized System Health, Watchdog, and Dependency-Aware Status Engine for Home-Gateway NIDS.
Tracks operational status, dependencies, and structured transition logging across:
- packet_capture
- flow_tracker
- suricata
- transformer
- fusion_engine
- sqlite
- dashboard_api
- siem_exporter

Exposes: UP, DEGRADED, DOWN, ML_UNAVAILABLE.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List, Tuple
import json
import logging
import time
import threading
from collections import deque


class HealthStatus(str, Enum):
    UP = "UP"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"
    ML_UNAVAILABLE = "ML_UNAVAILABLE"


# Configure structured health logger
logger = logging.getLogger("nids.health")
logger.setLevel(logging.INFO)


@dataclass
class HealthTransitionEvent:
    timestamp: str
    component: str
    old_status: str
    new_status: str
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "level": "ERROR" if self.new_status in [HealthStatus.DOWN.value, HealthStatus.DEGRADED.value] else "INFO",
            "component": self.component,
            "event_type": "health_transition",
            "old_status": self.old_status,
            "new_status": self.new_status,
            "reason": self.reason,
            "details": self.details,
        }


@dataclass
class ComponentHealth:
    name: str
    status: HealthStatus = HealthStatus.UP
    message: str = "Component operational"
    last_heartbeat: float = field(default_factory=time.time)
    error_count: int = 0
    last_error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "last_heartbeat_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.last_heartbeat)),
            "age_seconds": round(time.time() - self.last_heartbeat, 2),
            "error_count": self.error_count,
            "last_error": self.last_error,
            "dependencies": self.dependencies,
            "details": self.details,
        }


class SystemHealthManager:
    """
    Thread-safe centralized health coordinator with dependency resolution,
    continuous watchdog monitoring, and structured transition audit logging.
    """

    # Explicit Directed Dependency Graph
    DEPENDENCY_GRAPH = {
        "packet_capture": [],
        "flow_tracker": ["packet_capture"],
        "suricata": ["packet_capture"],
        "transformer": ["flow_tracker"],
        "fusion_engine": ["suricata", "transformer", "sqlite"],
        "sqlite": [],
        "dashboard_api": ["sqlite"],
        "siem_exporter": [],
    }
    CORE_COMPONENTS = [
        "packet_capture",
        "flow_tracker",
        "suricata",
        "transformer",
        "fusion_engine",
        "sqlite",
        "dashboard_api",
        "siem_exporter",
    ]

    def __init__(
        self,
        heartbeat_timeout_seconds: float = 120.0,
        enable_watchdog: bool = False,
        watchdog_interval_seconds: float = 5.0,
    ):
        self._lock = threading.Lock()
        self.heartbeat_timeout = heartbeat_timeout_seconds
        self.watchdog_interval = watchdog_interval_seconds
        self.components: Dict[str, ComponentHealth] = {}
        self.transition_history: deque = deque(maxlen=200)

        # Initialize all nodes from dependency graph
        for comp, deps in self.DEPENDENCY_GRAPH.items():
            self.components[comp] = ComponentHealth(
                name=comp,
                dependencies=deps,
            )

        self._watchdog_thread: Optional[threading.Thread] = None
        self._watchdog_running = False
        if enable_watchdog:
            self.start_watchdog()

    def reset(self) -> None:
        """Resets all component states for clean test isolation."""
        with self._lock:
            self.components.clear()
            self.transition_history.clear()
            for comp, deps in self.DEPENDENCY_GRAPH.items():
                self.components[comp] = ComponentHealth(
                    name=comp,
                    dependencies=deps,
                )

    def start_watchdog(self) -> None:
        """Starts asynchronous background watchdog daemon."""
        with self._lock:
            if self._watchdog_running:
                return
            self._watchdog_running = True
            self._watchdog_thread = threading.Thread(
                target=self._watchdog_loop,
                daemon=True,
                name="HealthWatchdogThread",
            )
            self._watchdog_thread.start()

    def stop_watchdog(self) -> None:
        """Stops background watchdog."""
        self._watchdog_running = False
        if self._watchdog_thread and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=2.0)

    def _watchdog_loop(self) -> None:
        while self._watchdog_running:
            try:
                self.evaluate_watchdog()
            except Exception as e:
                logger.error(f"[HealthWatchdog] Error in evaluation loop: {e}")
            time.sleep(self.watchdog_interval)

    def _record_transition(
        self,
        component_name: str,
        old_status: HealthStatus,
        new_status: HealthStatus,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        if old_status == new_status:
            return

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        event = HealthTransitionEvent(
            timestamp=ts,
            component=component_name,
            old_status=old_status.value,
            new_status=new_status.value,
            reason=reason,
            details=details or {},
        )
        self.transition_history.append(event)
        # Emit structured log
        log_json = json.dumps(event.to_dict())
        if new_status in [HealthStatus.DOWN, HealthStatus.DEGRADED]:
            logger.warning(log_json)
        else:
            logger.info(log_json)

    def heartbeat(self, component_name: str, details: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            if component_name not in self.components:
                self.components[component_name] = ComponentHealth(
                    name=component_name,
                    dependencies=self.DEPENDENCY_GRAPH.get(component_name, []),
                )
            comp = self.components[component_name]
            old_status = comp.status
            comp.last_heartbeat = time.time()

            if comp.status == HealthStatus.DOWN:
                comp.status = HealthStatus.UP
                comp.message = "Component recovered via heartbeat"
                self._record_transition(component_name, old_status, HealthStatus.UP, "heartbeat_recovered", details)

            if details:
                comp.details.update(details)

    def update_status(
        self,
        component_name: str,
        status: HealthStatus,
        message: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            if component_name not in self.components:
                self.components[component_name] = ComponentHealth(
                    name=component_name,
                    dependencies=self.DEPENDENCY_GRAPH.get(component_name, []),
                )
            comp = self.components[component_name]
            old_status = comp.status
            comp.status = status
            comp.message = message or f"Status transitioned to {status.value}"
            comp.last_heartbeat = time.time()
            if details:
                comp.details.update(details)

            self._record_transition(component_name, old_status, status, message or "status_update", details)

    def record_error(
        self,
        component_name: str,
        error_msg: str,
        degrade: bool = True,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            if component_name not in self.components:
                self.components[component_name] = ComponentHealth(
                    name=component_name,
                    dependencies=self.DEPENDENCY_GRAPH.get(component_name, []),
                )
            comp = self.components[component_name]
            comp.error_count += 1
            comp.last_error = error_msg
            comp.last_heartbeat = time.time()
            if details:
                comp.details.update(details)

            if degrade and comp.status == HealthStatus.UP:
                old_status = comp.status
                comp.status = HealthStatus.DEGRADED
                comp.message = f"Error: {error_msg}"
                self._record_transition(component_name, old_status, HealthStatus.DEGRADED, error_msg, details)

    def evaluate_watchdog(self) -> None:
        """
        Evaluates heartbeat timeouts and applies dependency degradation.
        """
        with self._lock:
            now = time.time()

            # 1. Heartbeat Timeout Evaluation
            for name, comp in self.components.items():
                if comp.status == HealthStatus.ML_UNAVAILABLE:
                    continue  # Intentionally disabled ML does not timeout

                time_since_hb = now - comp.last_heartbeat
                old_status = comp.status

                if time_since_hb > (self.heartbeat_timeout * 3):
                    if comp.status != HealthStatus.DOWN:
                        comp.status = HealthStatus.DOWN
                        comp.message = f"Heartbeat missed for {int(time_since_hb)}s (timeout threshold exceeded)"
                        self._record_transition(name, old_status, HealthStatus.DOWN, "heartbeat_timeout_expired")
                elif time_since_hb > self.heartbeat_timeout:
                    if comp.status == HealthStatus.UP:
                        comp.status = HealthStatus.DEGRADED
                        comp.message = f"Heartbeat delayed ({int(time_since_hb)}s)"
                        self._record_transition(name, old_status, HealthStatus.DEGRADED, "heartbeat_delayed")

            # 2. Dependency Graph Propagation
            # If packet_capture is DOWN, flow_tracker cannot receive telemetry -> DEGRADED
            if self.components["packet_capture"].status == HealthStatus.DOWN:
                if self.components["flow_tracker"].status == HealthStatus.UP:
                    old_st = self.components["flow_tracker"].status
                    self.components["flow_tracker"].status = HealthStatus.DEGRADED
                    self.components["flow_tracker"].message = "Upstream packet_capture is DOWN (telemetry starved)"
                    self._record_transition("flow_tracker", old_st, HealthStatus.DEGRADED, "upstream_capture_down")

    def get_system_health(self) -> Dict[str, Any]:
        """
        Aggregates system-wide operational health and resolves overall state.
        """
        self.evaluate_watchdog()

        with self._lock:
            now = time.time()
            comp_dicts = {}
            has_down = False
            has_degraded = False
            has_ml_unavailable = False

            for name, comp in self.components.items():
                comp_dicts[name] = comp.to_dict()

                # Critical components whose DOWN state brings overall status DOWN
                if comp.status == HealthStatus.DOWN:
                    has_down = True
                elif comp.status == HealthStatus.DEGRADED:
                    has_degraded = True
                elif comp.status == HealthStatus.ML_UNAVAILABLE:
                    has_ml_unavailable = True

            # Overall Status resolution
            if has_down:
                overall_status = HealthStatus.DOWN.value
            elif has_degraded or has_ml_unavailable:
                overall_status = HealthStatus.DEGRADED.value
            else:
                overall_status = HealthStatus.UP.value

            return {
                "overall_status": overall_status,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "components": comp_dicts,
                "recent_transitions": [t.to_dict() for t in list(self.transition_history)[-10:]],
            }


# Global singleton instance
_global_health_manager: Optional[SystemHealthManager] = None
_health_lock = threading.Lock()


def get_health_manager() -> SystemHealthManager:
    global _global_health_manager
    with _health_lock:
        if _global_health_manager is None:
            _global_health_manager = SystemHealthManager(heartbeat_timeout_seconds=30.0, enable_watchdog=True)
        return _global_health_manager
