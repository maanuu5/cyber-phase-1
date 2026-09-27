import os
import time
from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap

def create_sample_pcap(filepath):
    packets = []
    base_time = time.time()

    # 1. Normal HTTPS packet
    pkt1 = IP(src='192.168.1.10', dst='142.250.190.46')/TCP(sport=54321, dport=443, flags='A')
    pkt1.time = base_time
    packets.append(pkt1)

    # 2. Suspicious Telnet packet (port 23)
    pkt2 = IP(src='10.0.0.50', dst='192.168.1.1')/TCP(sport=49152, dport=23, flags='S')
    pkt2.time = base_time + 0.1
    packets.append(pkt2)

    # 3. Port Scan (15 distinct ports)
    for p in range(1, 16):
        pkt = IP(src='10.0.0.60', dst='192.168.1.1')/TCP(sport=50000, dport=p, flags='S')
        pkt.time = base_time + 0.2 + (p * 0.05)
        packets.append(pkt)

    # 4. SYN Flood (25 SYN packets)
    for i in range(25):
        pkt = IP(src='10.0.0.70', dst='192.168.1.1')/TCP(sport=40000 + i, dport=80, flags='S')
        pkt.time = base_time + 1.5 + (i * 0.02)
        packets.append(pkt)

    # 5. ICMP Flood (20 ICMP packets)
    for i in range(20):
        pkt = IP(src='10.0.0.80', dst='192.168.1.1')/ICMP()
        pkt.time = base_time + 2.5 + (i * 0.02)
        packets.append(pkt)

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    wrpcap(filepath, packets)
    print(f"Generated sample PCAP file with {len(packets)} packets at {filepath}")

if __name__ == '__main__':
    pcap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', 'sample_test.pcap')
    create_sample_pcap(pcap_path)
