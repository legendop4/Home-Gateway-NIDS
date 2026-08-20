"""
Flow Tracker Module: Maintains bidirectional TCP/UDP flow states and extracts packet headers.
"""

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple
import time


@dataclass
class PacketSummary:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "OTHER"  # TCP, UDP, ICMP, OTHER
    length: int = 0
    is_syn: bool = False
    is_ack: bool = False
    is_fin: bool = False
    is_rst: bool = False
    is_psh: bool = False
    is_urg: bool = False
    raw_flags: int = 0


@dataclass
class FlowState:
    flow_key: Tuple[str, str, int, int, str]
    start_time: float
    last_time: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    completed_handshake: bool = False

    def update(self, packet: PacketSummary) -> None:
        self.last_time = packet.timestamp
        self.packet_count += 1
        self.byte_count += packet.length
        if packet.is_syn:
            self.syn_count += 1
        if packet.is_ack:
            self.ack_count += 1
        if packet.is_rst:
            self.rst_count += 1
        if packet.is_fin:
            self.fin_count += 1
        
        # Check basic handshake completion heuristic
        if self.syn_count > 0 and self.ack_count > 0:
            self.completed_handshake = True

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)


class FlowTracker:
    """
    Manages active network flows indexed by canonical 5-tuple.
    Periodically prunes inactive flows.
    """

    def __init__(self, flow_timeout_sec: float = 120.0, max_active_flows: int = 50000):
        self.flow_timeout_sec = flow_timeout_sec
        self.max_active_flows = max_active_flows
        self.flows: Dict[Tuple[str, str, int, int, str], FlowState] = {}
        self.last_prune_time: float = time.time()

    @staticmethod
    def get_canonical_key(packet: PacketSummary) -> Tuple[str, str, int, int, str]:
        # Canonical ordering so forward and reverse traffic map to the same flow
        if (packet.src_ip, packet.src_port) <= (packet.dst_ip, packet.dst_port):
            return (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol)
        else:
            return (packet.dst_ip, packet.src_ip, packet.dst_port, packet.src_port, packet.protocol)

    def process_packet(self, packet: PacketSummary) -> FlowState:
        key = self.get_canonical_key(packet)
        flow = self.flows.get(key)
        if flow is None:
            # Check capacity before creating new flow
            if len(self.flows) >= self.max_active_flows:
                self.prune_expired_flows(current_time=packet.timestamp)
                if len(self.flows) >= self.max_active_flows:
                    # Force evict oldest 10% flows
                    num_to_evict = max(1, int(self.max_active_flows * 0.10))
                    sorted_keys = sorted(self.flows.keys(), key=lambda k: self.flows[k].last_time)
                    for k in sorted_keys[:num_to_evict]:
                        del self.flows[k]
                    from ..health import get_health_manager
                    get_health_manager().record_error(
                        "flow_tracker",
                        f"Flow table exceeded max_active_flows ({self.max_active_flows}); evicted {num_to_evict} oldest flows",
                        degrade=False
                    )

            flow = FlowState(
                flow_key=key,
                start_time=packet.timestamp,
                last_time=packet.timestamp,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                src_port=packet.src_port,
                dst_port=packet.dst_port,
                protocol=packet.protocol,
            )
            self.flows[key] = flow

        flow.update(packet)

        # Periodic prune every 60 seconds
        if packet.timestamp - self.last_prune_time > 60.0:
            self.prune_expired_flows(current_time=packet.timestamp)
            from ..health import get_health_manager
            get_health_manager().heartbeat("flow_tracker", {"active_flows": len(self.flows)})

        return flow

    def prune_expired_flows(self, current_time: float) -> int:
        expired_keys = [
            k for k, flow in self.flows.items()
            if (current_time - flow.last_time) > self.flow_timeout_sec
        ]
        for k in expired_keys:
            del self.flows[k]
        self.last_prune_time = current_time
        return len(expired_keys)

    def clear(self) -> None:
        self.flows.clear()
