"""
PCAP Parser: Extracts 10x60s feature sequences from recorded PCAP capture files.
"""

from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np

from ..capture.adapters import PcapCaptureAdapter
from ..feature_extraction.flow_tracker import FlowTracker, PacketSummary
from ..feature_extraction.window_sequencer import WindowSequencer


def parse_pcap_to_sequences(
    pcap_path: str,
    window_size_sec: float = 60.0,
    sequence_length: int = 10,
) -> Dict[str, List[Tuple[np.ndarray, np.ndarray]]]:
    """
    Parses a PCAP file and produces a list of (sequence, mask) arrays per Source IP.
    Returns: Dict[src_ip, List[(seq, mask)]]
    """
    flow_tracker = FlowTracker()
    sequencer = WindowSequencer(window_size_sec=window_size_sec, sequence_length=sequence_length)
    ip_sequences: Dict[str, List[Tuple[np.ndarray, np.ndarray]]] = {}

    def _packet_callback(packet: PacketSummary):
        flow = flow_tracker.process_packet(packet)
        closed_win = sequencer.process_packet(packet, flow_duration=flow.duration)
        if closed_win is not None:
            # Capture rolling sequence state
            seq, mask = sequencer.get_sequence_tensor(closed_win.src_ip, include_active=False)
            if closed_win.src_ip not in ip_sequences:
                ip_sequences[closed_win.src_ip] = []
            ip_sequences[closed_win.src_ip].append((seq, mask))

    adapter = PcapCaptureAdapter(pcap_path)
    adapter.start(_packet_callback)

    # Ingest final active states
    for src_ip in sequencer.get_all_active_ips():
        seq, mask = sequencer.get_sequence_tensor(src_ip, include_active=True)
        if src_ip not in ip_sequences:
            ip_sequences[src_ip] = []
        ip_sequences[src_ip].append((seq, mask))

    return ip_sequences
