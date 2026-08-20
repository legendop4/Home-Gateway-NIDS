"""
Reproducible Attack Simulation & Lab Traffic Generator.
Generates streams of PacketSummary objects for:
- BENIGN (HTTP/S, DNS, streaming)
- FAST_SCAN (Nmap -sS style)
- SLOW_SCAN (Nmap -T1 style spread over multiple 60s windows)
- RANDOMIZED_SCAN (Random ports at low rate)
- FIN_SCAN (Nmap -sF)
- NULL_SCAN (Nmap -sN)
"""

from typing import Generator, List
import random
import time

from ..feature_extraction.flow_tracker import PacketSummary


class ReconTrafficGenerator:
    """
    Generates synthetic packet streams for testing detection engines without raw sockets.
    """

    def __init__(self, base_timestamp: float = None):
        self.base_timestamp = base_timestamp or time.time()

    def generate_benign_stream(
        self,
        src_ip: str = "192.168.10.101",
        dst_ip: str = "93.184.216.34",
        duration_sec: float = 600.0,
        packets_per_min: int = 150,
    ) -> List[PacketSummary]:
        """Generates realistic benign web browsing and HTTPS traffic."""
        packets = []
        t = self.base_timestamp
        num_minutes = int(duration_sec / 60.0)

        for minute in range(num_minutes):
            for _ in range(packets_per_min):
                src_port = random.randint(35000, 60000)
                dst_port = random.choice([443, 80, 53])

                # 3-way handshake SYN
                packets.append(PacketSummary(
                    timestamp=t, src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port, protocol="TCP",
                    length=64, is_syn=True, is_ack=False
                ))
                t += 0.05

                # ACK + Data
                for _ in range(random.randint(3, 8)):
                    packets.append(PacketSummary(
                        timestamp=t, src_ip=src_ip, dst_ip=dst_ip,
                        src_port=src_port, dst_port=dst_port, protocol="TCP",
                        length=random.randint(200, 1400), is_syn=False, is_ack=True, is_psh=True
                    ))
                    t += random.uniform(0.01, 0.1)

            t = self.base_timestamp + (minute + 1) * 60.0

        return packets

    def generate_fast_scan_stream(
        self,
        src_ip: str = "192.168.10.105",
        target_ip: str = "192.168.10.50",
        ports: List[int] = None,
        start_offset_sec: float = 120.0,
    ) -> List[PacketSummary]:
        """Generates fast Nmap SYN scan burst (100+ ports probed in < 30 seconds)."""
        packets = []
        t = self.base_timestamp + start_offset_sec
        port_list = ports or list(range(1, 101))

        for port in port_list:
            src_port = random.randint(40000, 60000)
            packets.append(PacketSummary(
                timestamp=t, src_ip=src_ip, dst_ip=target_ip,
                src_port=src_port, dst_port=port, protocol="TCP",
                length=54, is_syn=True, is_ack=False
            ))
            t += 0.02

        return packets

    def generate_slow_stealth_scan_stream(
        self,
        src_ip: str = "192.168.10.120",
        target_ip: str = "192.168.10.50",
        num_windows: int = 10,
        probes_per_window: int = 3,
    ) -> List[PacketSummary]:
        """Generates slow reconnaissance spread across multiple 60s windows (Nmap -T1 style)."""
        packets = []
        candidate_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080]
        port_idx = 0

        for w in range(num_windows):
            t = self.base_timestamp + (w * 60.0) + random.uniform(5.0, 15.0)
            for _ in range(probes_per_window):
                if port_idx < len(candidate_ports):
                    port = candidate_ports[port_idx]
                    port_idx += 1
                    src_port = random.randint(40000, 60000)
                    packets.append(PacketSummary(
                        timestamp=t, src_ip=src_ip, dst_ip=target_ip,
                        src_port=src_port, dst_port=port, protocol="TCP",
                        length=54, is_syn=True, is_ack=False
                    ))
                    t += random.uniform(10.0, 20.0)

        return packets

    def generate_fin_null_scan_stream(
        self,
        src_ip: str = "192.168.10.130",
        target_ip: str = "192.168.10.50",
        scan_type: str = "FIN",
        ports: List[int] = None,
    ) -> List[PacketSummary]:
        """Generates FIN scan (-sF) or NULL scan (-sN) probe stream."""
        packets = []
        t = self.base_timestamp + 60.0
        port_list = ports or [21, 22, 23, 25, 80, 443, 8080]

        for port in port_list:
            src_port = random.randint(40000, 60000)
            is_fin = (scan_type.upper() == "FIN")
            packets.append(PacketSummary(
                timestamp=t, src_ip=src_ip, dst_ip=target_ip,
                src_port=src_port, dst_port=port, protocol="TCP",
                length=54, is_syn=False, is_ack=False, is_fin=is_fin
            ))
            t += 0.5

        return packets
