"""
Capture Adapters: Abstracts packet capture across PCAP files, Scapy sniffer, and mock streams.
"""

from abc import ABC, abstractmethod
from typing import Callable, Generator, List, Optional
import time
import scapy.all as scapy_all

from ..feature_extraction.flow_tracker import PacketSummary


class BaseCaptureAdapter(ABC):
    """Abstract interface for packet sources."""

    @abstractmethod
    def start(self, callback: Callable[[PacketSummary], None]) -> None:
        """Start capturing and streaming packets to callback."""
        pass

    @abstractmethod
    def stop(self) -> None:
        """Stop packet capture."""
        pass


def scapy_pkt_to_summary(pkt) -> Optional[PacketSummary]:
    """Convert Scapy packet to PacketSummary."""
    if not pkt.haslayer(scapy_all.IP):
        return None

    ip_layer = pkt[scapy_all.IP]
    ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    length = int(len(pkt))

    src_port = 0
    dst_port = 0
    protocol = "OTHER"
    is_syn = False
    is_ack = False
    is_fin = False
    is_rst = False
    is_psh = False
    is_urg = False

    if pkt.haslayer(scapy_all.TCP):
        protocol = "TCP"
        tcp = pkt[scapy_all.TCP]
        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        flags = int(tcp.flags)
        raw_syn = bool(flags & 0x02)
        raw_ack = bool(flags & 0x10)
        is_syn = raw_syn and not raw_ack  # Pure SYN initiator
        is_ack = raw_ack and not raw_syn  # Pure ACK or Data ACK
        is_fin = bool(flags & 0x01)
        is_rst = bool(flags & 0x04)
        is_psh = bool(flags & 0x08)
        is_urg = bool(flags & 0x20)
    elif pkt.haslayer(scapy_all.UDP):
        protocol = "UDP"
        udp = pkt[scapy_all.UDP]
        src_port = int(udp.sport)
        dst_port = int(udp.dport)
    elif pkt.haslayer(scapy_all.ICMP):
        protocol = "ICMP"

    return PacketSummary(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        is_syn=is_syn,
        is_ack=is_ack,
        is_fin=is_fin,
        is_rst=is_rst,
        is_psh=is_psh,
        is_urg=is_urg,
        raw_flags=flags if protocol == "TCP" else 0,
    )


class PcapCaptureAdapter(BaseCaptureAdapter):
    """Replays packets from a .pcap / .pcapng file."""

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self._running = False

    def start(self, callback: Callable[[PacketSummary], None]) -> None:
        self._running = True
        from ..health import get_health_manager
        health_mgr = get_health_manager()
        health_mgr.heartbeat("packet_capture", {"source": "pcap", "file": self.pcap_path})
        try:
            reader = scapy_all.PcapReader(self.pcap_path)
            for pkt in reader:
                if not self._running:
                    break
                summary = scapy_pkt_to_summary(pkt)
                if summary:
                    callback(summary)
            reader.close()
            health_mgr.heartbeat("packet_capture", {"status": "pcap_completed"})
        except Exception as e:
            health_mgr.record_error("packet_capture", str(e))
            print(f"[PcapCaptureAdapter] Error reading {self.pcap_path}: {e}")
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False


class ScapyCaptureAdapter(BaseCaptureAdapter):
    """Live packet capture using Scapy sniff on a network interface."""

    def __init__(self, interface: str = "wlan0", bpf_filter: str = "ip"):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self._running = False
        self._async_sniffer = None

    def start(self, callback: Callable[[PacketSummary], None]) -> None:
        self._running = True

        def _handler(pkt):
            if not self._running:
                return
            summary = scapy_pkt_to_summary(pkt)
            if summary:
                callback(summary)

        try:
            self._async_sniffer = scapy_all.AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=_handler,
                store=False,
            )
            self._async_sniffer.start()
        except Exception as e:
            print(f"[ScapyCaptureAdapter] Error sniffing on {self.interface}: {e}")
            self._running = False

    def stop(self) -> None:
        self._running = False
        if self._async_sniffer and self._async_sniffer.running:
            self._async_sniffer.stop()


class MockCaptureAdapter(BaseCaptureAdapter):
    """In-memory packet stream for testing and simulation."""

    def __init__(self, packets: Optional[List[PacketSummary]] = None):
        self.packets = packets or []
        self._running = False

    def start(self, callback: Callable[[PacketSummary], None]) -> None:
        self._running = True
        for pkt in self.packets:
            if not self._running:
                break
            callback(pkt)
        self._running = False

    def stop(self) -> None:
        self._running = False
