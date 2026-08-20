"""
Unit tests for Centralized System Health and Component Status Tracker.
Tests UP, DEGRADED, DOWN, and ML_UNAVAILABLE states across all subsystems.
"""

import pytest
import time
from nids.health import HealthStatus, ComponentHealth, SystemHealthManager


def test_health_manager_initialization():
    mgr = SystemHealthManager()
    health = mgr.get_system_health()
    assert health["overall_status"] == HealthStatus.UP.value
    for comp in SystemHealthManager.CORE_COMPONENTS:
        assert comp in health["components"]
        assert health["components"][comp]["status"] == HealthStatus.UP.value


def test_health_status_transitions():
    mgr = SystemHealthManager()

    # 1. Update ML to ML_UNAVAILABLE
    mgr.update_status("transformer", HealthStatus.ML_UNAVAILABLE, message="Weights missing")
    health = mgr.get_system_health()
    assert health["components"]["transformer"]["status"] == HealthStatus.ML_UNAVAILABLE.value
    assert health["overall_status"] == HealthStatus.DEGRADED.value

    # 2. Record Error -> DEGRADED
    mgr.record_error("flow_tracker", "Memory threshold exceeded")
    health = mgr.get_system_health()
    assert health["components"]["flow_tracker"]["status"] == HealthStatus.DEGRADED.value
    assert health["components"]["flow_tracker"]["error_count"] == 1

    # 3. Mark Critical Component DOWN
    mgr.update_status("sqlite", HealthStatus.DOWN, message="Database locked")
    health = mgr.get_system_health()
    assert health["components"]["sqlite"]["status"] == HealthStatus.DOWN.value
    assert health["overall_status"] == HealthStatus.DOWN.value

    # 4. Heartbeat recovery
    mgr.heartbeat("sqlite")
    health = mgr.get_system_health()
    assert health["components"]["sqlite"]["status"] == HealthStatus.UP.value


def test_heartbeat_timeout():
    mgr = SystemHealthManager(heartbeat_timeout_seconds=0.1)
    mgr.heartbeat("packet_capture")
    time.sleep(0.35)
    health = mgr.get_system_health()
    # After 3x timeout, status transitions to DOWN
    assert health["components"]["packet_capture"]["status"] in [HealthStatus.DEGRADED.value, HealthStatus.DOWN.value]
