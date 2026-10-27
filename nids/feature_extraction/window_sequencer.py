"""
Window Sequencer: Aggregates network flows into sliding 60-second buckets
and maintains a sequence buffer of 10 windows per Source IP.
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Set, Tuple
import numpy as np
import time

from .flow_tracker import PacketSummary


FEATURE_NAMES = [
    "dst_port_count",
    "dst_ip_count",
    "syn_ratio",
    "syn_ack_ratio",
    "rst_ratio",
    "packet_rate",
    "byte_rate",
    "flow_duration_mean",
]

FEATURE_DIM = len(FEATURE_NAMES)  # 8


@dataclass
class WindowMetrics:
    src_ip: str
    window_start: float
    window_end: float
    dst_ports: Set[int] = field(default_factory=set)
    dst_ips: Set[str] = field(default_factory=set)
    total_packets: int = 0
    total_bytes: int = 0
    tcp_packets: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    flow_durations: List[float] = field(default_factory=list)

    def add_packet(self, packet: PacketSummary, flow_duration: float = 0.0) -> None:
        self.total_packets += 1
        self.total_bytes += packet.length
        if packet.dst_port > 0:
            self.dst_ports.add(packet.dst_port)
        if packet.dst_ip:
            self.dst_ips.add(packet.dst_ip)
        
        if packet.protocol == "TCP":
            self.tcp_packets += 1
            if packet.is_syn:
                self.syn_count += 1
            if packet.is_ack:
                self.ack_count += 1
            if packet.is_rst:
                self.rst_count += 1
            if packet.is_fin:
                self.fin_count += 1
        
        if flow_duration > 0:
            self.flow_durations.append(flow_duration)

    def to_feature_vector(self, window_size_sec: float = 60.0) -> np.ndarray:
        """
        Convert window summary into normalized 8-dimensional feature vector.
        """
        dst_port_count = float(len(self.dst_ports))
        dst_ip_count = float(len(self.dst_ips))

        tcp_denom = float(self.tcp_packets) if self.tcp_packets > 0 else 1.0
        syn_ratio = float(self.syn_count) / tcp_denom
        ack_denom = float(self.ack_count) if self.ack_count > 0 else 1.0
        syn_ack_ratio = float(self.syn_count) / ack_denom
        rst_ratio = float(self.rst_count) / tcp_denom

        eff_duration = max(1.0, window_size_sec)
        packet_rate = float(self.total_packets) / eff_duration
        byte_rate = float(self.total_bytes) / eff_duration

        mean_duration = float(np.mean(self.flow_durations)) if self.flow_durations else 0.0

        vec = np.array([
            dst_port_count,
            dst_ip_count,
            syn_ratio,
            syn_ack_ratio,
            rst_ratio,
            packet_rate,
            byte_rate,
            mean_duration,
        ], dtype=np.float32)

        return vec

    def to_dict(self) -> Dict[str, float]:
        vec = self.to_feature_vector()
        return {name: float(val) for name, val in zip(FEATURE_NAMES, vec)}


class WindowSequencer:
    """
    Maintains active 60s windows and a rolling 10-window sequence per Source IP.
    """

    def __init__(
        self,
        window_size_sec: float = 60.0,
        sequence_length: int = 10,
        max_tracked_ips: int = 10000,
    ):
        self.window_size_sec = window_size_sec
        self.sequence_length = sequence_length
        self.max_tracked_ips = max_tracked_ips
        # Map: src_ip -> current active WindowMetrics
        self.active_windows: Dict[str, WindowMetrics] = {}
        # Map: src_ip -> deque of closed WindowMetrics (max length = sequence_length)
        self.window_history: Dict[str, Deque[WindowMetrics]] = {}

    def _evict_oldest_ips(self, count: int = 100) -> None:
        """Evicts oldest tracked IPs when memory bound is reached."""
        if not self.active_windows:
            return
        sorted_ips = sorted(self.active_windows.keys(), key=lambda ip: self.active_windows[ip].window_end)
        for ip in sorted_ips[:count]:
            self.active_windows.pop(ip, None)
            self.window_history.pop(ip, None)

    def process_packet(self, packet: PacketSummary, flow_duration: float = 0.0) -> Optional[WindowMetrics]:
        """
        Ingest a packet. If the 60s window for this source IP has elapsed,
        closes the window, shifts it to history, and creates a fresh active window.
        Returns the closed window if one just completed, else None.
        """
        src_ip = packet.src_ip
        ts = packet.timestamp

        closed_window: Optional[WindowMetrics] = None

        if src_ip not in self.active_windows:
            if len(self.active_windows) >= self.max_tracked_ips:
                self._evict_oldest_ips(count=max(1, int(self.max_tracked_ips * 0.10)))

            self.active_windows[src_ip] = WindowMetrics(
                src_ip=src_ip,
                window_start=ts,
                window_end=ts + self.window_size_sec,
            )
            if src_ip not in self.window_history:
                self.window_history[src_ip] = deque(maxlen=self.sequence_length)

        active = self.active_windows[src_ip]

        # Check if window expired
        while ts >= active.window_end:
            closed_window = active
            self.window_history[src_ip].append(closed_window)

            # Start next contiguous window
            next_start = active.window_end
            next_end = next_start + self.window_size_sec
            active = WindowMetrics(
                src_ip=src_ip,
                window_start=next_start,
                window_end=next_end,
            )
            self.active_windows[src_ip] = active

        active.add_packet(packet, flow_duration=flow_duration)
        return closed_window

    def flush_expired(self, current_time: float) -> List[WindowMetrics]:
        """
        Force close any active windows whose window_end <= current_time.
        """
        closed: List[WindowMetrics] = []
        for src_ip, active in list(self.active_windows.items()):
            if current_time >= active.window_end:
                self.window_history[src_ip].append(active)
                closed.append(active)
                # Roll to next window
                self.active_windows[src_ip] = WindowMetrics(
                    src_ip=src_ip,
                    window_start=active.window_end,
                    window_end=active.window_end + self.window_size_sec,
                )
        return closed

    def get_sequence_tensor(self, src_ip: str, include_active: bool = True) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns (sequence_array, mask_array):
        - sequence_array: shape (sequence_length, 8)
        - mask_array: shape (sequence_length,), 1.0 for valid windows, 0.0 for zero-padded slots.
        The most recent window is placed at index -1.
        """
        windows: List[WindowMetrics] = []
        if src_ip in self.window_history:
            windows.extend(list(self.window_history[src_ip]))

        if include_active and src_ip in self.active_windows:
            active = self.active_windows[src_ip]
            if active.total_packets > 0:
                windows.append(active)

        # Slice to at most sequence_length
        windows = windows[-self.sequence_length:]

        seq = np.zeros((self.sequence_length, FEATURE_DIM), dtype=np.float32)
        mask = np.zeros((self.sequence_length,), dtype=np.float32)

        num_valid = len(windows)
        if num_valid > 0:
            start_idx = self.sequence_length - num_valid
            for i, win in enumerate(windows):
                seq[start_idx + i] = win.to_feature_vector(self.window_size_sec)
                mask[start_idx + i] = 1.0

        return seq, mask

    def feed_custom_window(self, src_ip: str, window: WindowMetrics) -> None:
        """Helper to append a custom or historical window to an IP's sequence buffer."""
        if src_ip not in self.window_history:
            self.window_history[src_ip] = deque(maxlen=self.sequence_length)
        self.window_history[src_ip].append(window)

    def feed_window_features(self, src_ip: str, feature_dict: Dict[str, Any]) -> None:
        """Helper to append a synthetic/custom feature window to an IP's sequence buffer."""
        wm = WindowMetrics(
            src_ip=src_ip,
            window_start=time.time() - 60.0,
            window_end=time.time(),
            dst_ports=set(range(int(feature_dict.get("dst_port_count", 1)))),
            dst_ips={f"10.0.0.{i+1}" for i in range(int(feature_dict.get("dst_ip_count", 1)))},
            total_packets=max(1, int(feature_dict.get("packet_rate", 1.0) * 60.0)),
            total_bytes=int(feature_dict.get("byte_rate", 100.0) * 60.0),
            tcp_packets=max(1, int(feature_dict.get("packet_rate", 1.0) * 60.0)),
            syn_count=int(feature_dict.get("syn_ratio", 0.1) * max(1, int(feature_dict.get("packet_rate", 1.0) * 60.0))),
            ack_count=max(1, int(feature_dict.get("syn_ack_ratio", 1.0))),
            rst_count=int(feature_dict.get("rst_ratio", 0.0) * max(1, int(feature_dict.get("packet_rate", 1.0) * 60.0))),
            flow_durations=[feature_dict.get("flow_duration_mean", 1.0)],
        )
        self.feed_custom_window(src_ip, wm)

    def get_all_active_ips(self) -> List[str]:
        return list(self.active_windows.keys())

    def clear(self) -> None:
        self.active_windows.clear()
        self.window_history.clear()

