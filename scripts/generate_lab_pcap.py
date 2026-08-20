"""
Lab PCAP Generator: Synthesizes reproducible lab packet capture (.pcap) files
for benign network browsing, fast Nmap-style SYN scans, and stealthy slow scans.
"""

from pathlib import Path
import random
import scapy.all as scapy_all


def generate_pcaps(output_dir: str = "data/pcaps"):
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    print(f"Generating lab PCAPs in {out_path}...")

    # 1. Benign Traffic PCAP (10 minutes of browsing / streaming)
    benign_packets = []
    base_time = 1700000000.0
    client_ip = "192.168.10.101"
    gateway_ip = "192.168.10.1"
    server_ips = ["93.184.216.34", "142.250.190.46", "151.101.1.69", "1.1.1.1"]

    t = base_time
    for minute in range(10):
        # 3-5 connections per minute
        for _ in range(random.randint(3, 5)):
            dst_ip = random.choice(server_ips)
            dst_port = 443 if dst_ip != "1.1.1.1" else 53
            src_port = random.randint(35000, 60000)

            # SYN
            syn_pkt = scapy_all.Ether() / scapy_all.IP(src=client_ip, dst=dst_ip) / scapy_all.TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
            syn_pkt.time = t
            benign_packets.append(syn_pkt)
            t += 0.05

            # SYN-ACK from server
            syn_ack = scapy_all.Ether() / scapy_all.IP(src=dst_ip, dst=client_ip) / scapy_all.TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=1001)
            syn_ack.time = t
            benign_packets.append(syn_ack)
            t += 0.05

            # ACK from client
            ack_pkt = scapy_all.Ether() / scapy_all.IP(src=client_ip, dst=dst_ip) / scapy_all.TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=2001)
            ack_pkt.time = t
            benign_packets.append(ack_pkt)
            t += 0.1

            # Bidirectional Data exchange (client request + server response)
            for d in range(random.randint(5, 12)):
                # Client request packet
                req_pkt = scapy_all.Ether() / scapy_all.IP(src=client_ip, dst=dst_ip) / scapy_all.TCP(sport=src_port, dport=dst_port, flags="PA", seq=1001 + d * 200, ack=2001 + d * 500) / scapy_all.Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
                req_pkt.time = t
                benign_packets.append(req_pkt)
                t += 0.02

                # Server response packet
                resp_pkt = scapy_all.Ether() / scapy_all.IP(src=dst_ip, dst=client_ip) / scapy_all.TCP(sport=dst_port, dport=src_port, flags="PA", seq=2001 + d * 500, ack=1001 + (d + 1) * 200) / scapy_all.Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n" + b"X" * 800)
                resp_pkt.time = t
                benign_packets.append(resp_pkt)
                t += random.uniform(0.01, 0.1)

        t = base_time + (minute + 1) * 60.0

    benign_pcap_path = out_path / "lab_benign.pcap"
    scapy_all.wrpcap(str(benign_pcap_path), benign_packets)
    print(f"  [+] Created {benign_pcap_path} ({len(benign_packets)} packets)")

    # 2. Fast Port Scan PCAP (Nmap -T4 -sS style)
    fast_packets = []
    attacker_ip = "192.168.10.105"
    target_ip = "192.168.10.50"
    t = base_time + 180.0  # Starts at minute 3

    for port in range(1, 101):
        src_port = random.randint(40000, 60000)
        # SYN probe
        syn_pkt = scapy_all.Ether() / scapy_all.IP(src=attacker_ip, dst=target_ip) / scapy_all.TCP(sport=src_port, dport=port, flags="S", seq=random.randint(1000, 9999))
        syn_pkt.time = t
        fast_packets.append(syn_pkt)

        # Closed ports reply with RST-ACK (typical in port scan)
        if port not in [22, 80, 443]:
            rst_pkt = scapy_all.Ether() / scapy_all.IP(src=target_ip, dst=attacker_ip) / scapy_all.TCP(sport=port, dport=src_port, flags="RA", seq=0, ack=syn_pkt[scapy_all.TCP].seq + 1)
            rst_pkt.time = t + 0.002
            fast_packets.append(rst_pkt)
        t += 0.02

    fast_pcap_path = out_path / "lab_fast_scan.pcap"
    scapy_all.wrpcap(str(fast_pcap_path), fast_packets)
    print(f"  [+] Created {fast_pcap_path} ({len(fast_packets)} packets)")

    # 3. Slow / Stealth Scan PCAP (Nmap -T1 style spread across 10 minutes)
    stealth_packets = []
    stealth_attacker_ip = "192.168.10.120"
    ports_to_probe = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080]

    t = base_time
    port_idx = 0
    for minute in range(10):
        # Probe exactly 2 ports per 60-second window
        for _ in range(2):
            if port_idx < len(ports_to_probe):
                port = ports_to_probe[port_idx]
                port_idx += 1
                src_port = random.randint(40000, 60000)

                # Stealth SYN
                syn_pkt = scapy_all.Ether() / scapy_all.IP(src=stealth_attacker_ip, dst=target_ip) / scapy_all.TCP(sport=src_port, dport=port, flags="S", seq=random.randint(1000, 9999))
                syn_pkt.time = t + random.uniform(5.0, 25.0)
                stealth_packets.append(syn_pkt)

                # RST response
                rst_pkt = scapy_all.Ether() / scapy_all.IP(src=target_ip, dst=stealth_attacker_ip) / scapy_all.TCP(sport=port, dport=src_port, flags="RA", seq=0, ack=syn_pkt[scapy_all.TCP].seq + 1)
                rst_pkt.time = syn_pkt.time + 0.05
                stealth_packets.append(rst_pkt)

        t = base_time + (minute + 1) * 60.0

    stealth_pcap_path = out_path / "lab_stealth_scan.pcap"
    scapy_all.wrpcap(str(stealth_pcap_path), stealth_packets)
    print(f"  [+] Created {stealth_pcap_path} ({len(stealth_packets)} packets)")


if __name__ == "__main__":
    generate_pcaps()
