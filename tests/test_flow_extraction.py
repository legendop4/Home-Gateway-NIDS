"""
Unit tests for FlowTracker and PacketSummary.
"""

import pytest
import time
from nids.feature_extraction.flow_tracker import FlowTracker, PacketSummary


def test_packet_summary_creation():
    pkt = PacketSummary(
        timestamp=1700000000.0,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=44444,
        dst_port=80,
        protocol="TCP",
        length=60,
        is_syn=True,
        is_ack=False,
    )
    assert pkt.src_ip == "192.168.1.10"
    assert pkt.dst_port == 80
    assert pkt.is_syn is True
    assert pkt.is_ack is False


def test_flow_canonical_key():
    tracker = FlowTracker()
    pkt_fwd = PacketSummary(timestamp=100.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1234, dst_port=80, protocol="TCP")
    pkt_rev = PacketSummary(timestamp=101.0, src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=80, dst_port=1234, protocol="TCP")

    key_fwd = tracker.get_canonical_key(pkt_fwd)
    key_rev = tracker.get_canonical_key(pkt_rev)
    assert key_fwd == key_rev


def test_flow_tracking_and_flags():
    tracker = FlowTracker()

    # Step 1: SYN packet from client
    p1 = PacketSummary(timestamp=100.0, src_ip="192.168.1.5", dst_ip="8.8.8.8", src_port=50000, dst_port=53, protocol="TCP", length=50, is_syn=True)
    flow = tracker.process_packet(p1)
    assert flow.packet_count == 1
    assert flow.syn_count == 1
    assert flow.byte_count == 50
    assert flow.completed_handshake is False

    # Step 2: ACK packet
    p2 = PacketSummary(timestamp=100.5, src_ip="8.8.8.8", dst_ip="192.168.1.5", src_port=53, dst_port=50000, protocol="TCP", length=100, is_ack=True)
    flow2 = tracker.process_packet(p2)
    assert flow2.packet_count == 2
    assert flow2.syn_count == 1
    assert flow2.ack_count == 1
    assert flow2.completed_handshake is True
    assert flow2.duration == 0.5


def test_flow_pruning():
    tracker = FlowTracker(flow_timeout_sec=10.0)
    p1 = PacketSummary(timestamp=100.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1000, dst_port=80, protocol="TCP")
    tracker.process_packet(p1)
    assert len(tracker.flows) == 1

    pruned = tracker.prune_expired_flows(current_time=120.0)
    assert pruned == 1
    assert len(tracker.flows) == 0
