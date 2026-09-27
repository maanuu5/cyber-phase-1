import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

def extract_features(packet):
    """
    Extracts core network features from a Scapy packet or feature dict.
    Returns a dictionary with src_ip, dst_ip, src_port, dst_port, protocol, size, tcp_flags, timestamp.
    Returns None if packet is malformed or non-IP.
    """
    if packet is None:
        return None

    # If already a dictionary (e.g. synthetic test input), return normalized dict or None if invalid
    if isinstance(packet, dict):
        required_keys = {'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'size', 'tcp_flags', 'timestamp'}
        if not required_keys.issubset(packet.keys()):
            return None
        return packet

    try:
        features = {
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': 'OTHER',
            'size': len(packet),
            'tcp_flags': None,
            'timestamp': float(getattr(packet, 'time', time.time()))
        }

        # IP layer parsing
        if packet.haslayer(IP):
            features['src_ip'] = packet[IP].src
            features['dst_ip'] = packet[IP].dst
        elif packet.haslayer(IPv6):
            features['src_ip'] = packet[IPv6].src
            features['dst_ip'] = packet[IPv6].dst
        else:
            # Non-IP packet (e.g. ARP, raw L2)
            return None

        # Transport layer parsing
        if packet.haslayer(TCP):
            features['protocol'] = 'TCP'
            features['src_port'] = int(packet[TCP].sport)
            features['dst_port'] = int(packet[TCP].dport)
            features['tcp_flags'] = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            features['protocol'] = 'UDP'
            features['src_port'] = int(packet[UDP].sport)
            features['dst_port'] = int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            features['protocol'] = 'ICMP'

        return features
    except Exception:
        # Catch any unexpected malformed packet error and return None safely
        return None
