"""
Unit tests for WindowSequencer, WindowMetrics, 10x60s rolling buffers, and zero-padding masks.
"""

import pytest
import numpy as np
from nids.feature_extraction.flow_tracker import PacketSummary
from nids.feature_extraction.window_sequencer import WindowSequencer, WindowMetrics, FEATURE_DIM


def test_window_metrics_feature_vector():
    metrics = WindowMetrics(src_ip="192.168.1.10", window_start=0.0, window_end=60.0)

    # Ingest 10 SYN packets to 5 distinct ports
    for i in range(10):
        pkt = PacketSummary(
            timestamp=float(i),
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=40000 + i,
            dst_port=80 + (i % 5),
            protocol="TCP",
            length=100,
            is_syn=True,
            is_ack=False,
        )
        metrics.add_packet(pkt, flow_duration=0.1)

    vec = metrics.to_feature_vector(window_size_sec=60.0)
    assert len(vec) == FEATURE_DIM == 8
    assert vec[0] == 5.0  # dst_port_count (5 ports)
    assert vec[1] == 1.0  # dst_ip_count
    assert vec[2] == 1.0  # syn_ratio = 10 / 10 = 1.0
    assert vec[3] == 10.0  # syn_ack_ratio = 10 / 1.0 = 10.0
    assert vec[4] == 0.0  # rst_ratio
    assert round(vec[5], 4) == round(10.0 / 60.0, 4)  # packet_rate


def test_sequencer_sliding_and_mask():
    sequencer = WindowSequencer(window_size_sec=60.0, sequence_length=10)
    src_ip = "192.168.1.20"

    # Send packets across 3 contiguous 60s windows
    # Window 0: 0-60s
    for t in [10.0, 20.0]:
        sequencer.process_packet(PacketSummary(timestamp=t, src_ip=src_ip, dst_ip="1.1.1.1", dst_port=80, protocol="TCP", length=50))

    # Window 1: 60-120s
    for t in [70.0, 80.0]:
        sequencer.process_packet(PacketSummary(timestamp=t, src_ip=src_ip, dst_ip="1.1.1.1", dst_port=443, protocol="TCP", length=50))

    # Window 2: 120-180s (current active window)
    sequencer.process_packet(PacketSummary(timestamp=130.0, src_ip=src_ip, dst_ip="1.1.1.1", dst_port=8080, protocol="TCP", length=50))

    # Inspect sequence tensor
    seq, mask = sequencer.get_sequence_tensor(src_ip, include_active=True)
    assert seq.shape == (10, 8)
    assert mask.shape == (10,)

    # Total 3 valid windows, so mask must have 7 zeros followed by 3 ones
    assert np.sum(mask) == 3.0
    assert list(mask[:7]) == [0.0] * 7
    assert list(mask[7:]) == [1.0] * 3

    # The latest window (index 9) must contain dst_port_count = 1
    assert seq[9, 0] == 1.0
