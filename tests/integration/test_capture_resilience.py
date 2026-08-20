"""
Integration Tests: Capture Adapter Failure Resilience and Dependency Propagation.
Verifies missing/corrupted PCAPs degrade packet_capture and propagate degradation to flow_tracker.
"""

import pytest
from pathlib import Path

from nids.health import get_health_manager, HealthStatus
from nids.capture.adapters import PcapCaptureAdapter


def test_missing_pcap_capture_failure(tmp_path):
    health_mgr = get_health_manager()
    missing_pcap = str(tmp_path / "non_existent_capture.pcap")

    adapter = PcapCaptureAdapter(pcap_path=missing_pcap)

    packets_received = []
    # Must NOT raise unhandled exception
    adapter.start(callback=lambda pkt: packets_received.append(pkt))

    assert len(packets_received) == 0

    health = health_mgr.get_system_health()
    assert health["components"]["packet_capture"]["error_count"] > 0
    assert health["components"]["packet_capture"]["status"] == HealthStatus.DEGRADED.value


def test_corrupted_pcap_header_handling(tmp_path):
    health_mgr = get_health_manager()
    corrupted_pcap = tmp_path / "corrupted_capture.pcap"
    corrupted_pcap.write_bytes(b"\x00\x01\x02\x03CORRUPTED_PCAP_MAGIC_HEADER")

    adapter = PcapCaptureAdapter(pcap_path=str(corrupted_pcap))

    packets = []
    adapter.start(callback=lambda p: packets.append(p))

    assert len(packets) == 0
    health = health_mgr.get_system_health()
    assert health["components"]["packet_capture"]["error_count"] > 0


def test_capture_down_dependency_propagation():
    health_mgr = get_health_manager()

    # Manually transition packet_capture to DOWN
    health_mgr.update_status("packet_capture", HealthStatus.DOWN, message="NIC interface link down")

    # Evaluate dependency graph
    health = health_mgr.get_system_health()

    assert health["components"]["packet_capture"]["status"] == HealthStatus.DOWN.value
    # flow_tracker must report DEGRADED due to telemetry starvation
    assert health["components"]["flow_tracker"]["status"] == HealthStatus.DEGRADED.value
    assert "telemetry starved" in health["components"]["flow_tracker"]["message"].lower() or "upstream" in health["components"]["flow_tracker"]["message"].lower()
