import time
from collections import defaultdict, deque

# ==========================================
# Detection Thresholds & Rule Configuration
# ==========================================

# Port Scan rule configuration
PORT_SCAN_WINDOW_SEC = 5.0
PORT_SCAN_THRESHOLD = 10  # distinct destination ports

# SYN Flood rule configuration
SYN_FLOOD_WINDOW_SEC = 5.0
SYN_FLOOD_THRESHOLD = 20  # SYN packets

# ICMP Flood rule configuration
ICMP_FLOOD_WINDOW_SEC = 5.0
ICMP_FLOOD_THRESHOLD = 15  # ICMP packets

# Packet Burst rule configuration
PACKET_BURST_WINDOW_SEC = 2.0
PACKET_BURST_THRESHOLD = 30  # overall packets

# Abnormally Large Packet Anomaly threshold (bytes)
LARGE_PACKET_THRESHOLD = 1500

# Suspicious Ports list
SUSPICIOUS_PORTS = {
    21,    # FTP
    23,    # Telnet
    135,   # RPC
    139,   # NetBIOS
    445,   # SMB
    1433,  # MSSQL
    3389,  # RDP
    4444,  # Metasploit default listener
    5900,  # VNC
    6667   # IRC
}

# Cooldown period (in seconds) per (src_ip, alert_type) to prevent spamming duplicate alerts
ALERT_COOLDOWN_SEC = 3.0


class RuleEngine:
    """
    Stateful Detection Rule Engine using sliding windows for traffic analysis.
    """
    def __init__(self):
        # Sliding windows keyed by src_ip
        self.port_scan_history = defaultdict(deque)     # (timestamp, dst_port)
        self.syn_flood_history = defaultdict(deque)     # timestamp
        self.icmp_flood_history = defaultdict(deque)    # timestamp
        self.packet_burst_history = defaultdict(deque)  # timestamp

        # Cooldown tracking: (src_ip, alert_type) -> last_alert_timestamp
        self.last_alert_time = {}

    def _should_suppress_alert(self, src_ip, alert_type, now):
        """Returns True if an alert of alert_type for src_ip occurred within ALERT_COOLDOWN_SEC."""
        key = (src_ip, alert_type)
        last_time = self.last_alert_time.get(key, 0)
        if now - last_time < ALERT_COOLDOWN_SEC:
            return True
        self.last_alert_time[key] = now
        return False

    def reset_state(self):
        """Resets all sliding windows and alert histories (useful for testing)."""
        self.port_scan_history.clear()
        self.syn_flood_history.clear()
        self.icmp_flood_history.clear()
        self.packet_burst_history.clear()
        self.last_alert_time.clear()

    def analyze(self, features):
        """
        Analyzes packet features against all detection rules.
        Returns a list of alert dictionaries (empty list if no rules triggered or if features is None).
        """
        if not features or not isinstance(features, dict):
            return []

        src_ip = features.get('src_ip')
        dst_ip = features.get('dst_ip')
        src_port = features.get('src_port')
        dst_port = features.get('dst_port')
        protocol = features.get('protocol')
        size = features.get('size', 0)
        tcp_flags = features.get('tcp_flags') or ''
        now = features.get('timestamp', time.time())

        if not src_ip:
            return []

        alerts = []

        # -----------------------------------------------------------
        # Rule 1: Suspicious Port
        # -----------------------------------------------------------
        matched_port = None
        if dst_port in SUSPICIOUS_PORTS:
            matched_port = dst_port
        elif src_port in SUSPICIOUS_PORTS:
            matched_port = src_port

        if matched_port is not None:
            alert_type = 'Suspicious Port'
            if not self._should_suppress_alert(src_ip, alert_type, now):
                alerts.append({
                    'type': alert_type,
                    'risk_level': 'Medium',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'details': f"Traffic detected on suspicious port {matched_port} ({protocol})"
                })

        # -----------------------------------------------------------
        # Rule 2: Port Scan (same src_ip hitting N distinct dst_ports)
        # -----------------------------------------------------------
        if dst_port is not None:
            q = self.port_scan_history[src_ip]
            q.append((now, dst_port))
            while q and now - q[0][0] > PORT_SCAN_WINDOW_SEC:
                q.popleft()
            
            distinct_ports = {port for ts, port in q}
            if len(distinct_ports) > PORT_SCAN_THRESHOLD:
                alert_type = 'Port Scan'
                if not self._should_suppress_alert(src_ip, alert_type, now):
                    alerts.append({
                        'type': alert_type,
                        'risk_level': 'High',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'details': f"Source IP hit {len(distinct_ports)} distinct ports within {PORT_SCAN_WINDOW_SEC}s"
                    })

        # -----------------------------------------------------------
        # Rule 3: SYN Flood (more than N TCP SYN packets)
        # -----------------------------------------------------------
        if protocol == 'TCP' and 'S' in tcp_flags and 'A' not in tcp_flags:
            q = self.syn_flood_history[src_ip]
            q.append(now)
            while q and now - q[0] > SYN_FLOOD_WINDOW_SEC:
                q.popleft()

            if len(q) > SYN_FLOOD_THRESHOLD:
                alert_type = 'SYN Flood'
                if not self._should_suppress_alert(src_ip, alert_type, now):
                    alerts.append({
                        'type': alert_type,
                        'risk_level': 'Critical',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'details': f"High SYN packet rate: {len(q)} SYN packets within {SYN_FLOOD_WINDOW_SEC}s"
                    })

        # -----------------------------------------------------------
        # Rule 4: ICMP Flood (more than N ICMP packets)
        # -----------------------------------------------------------
        if protocol == 'ICMP':
            q = self.icmp_flood_history[src_ip]
            q.append(now)
            while q and now - q[0] > ICMP_FLOOD_WINDOW_SEC:
                q.popleft()

            if len(q) > ICMP_FLOOD_THRESHOLD:
                alert_type = 'ICMP Flood'
                if not self._should_suppress_alert(src_ip, alert_type, now):
                    alerts.append({
                        'type': alert_type,
                        'risk_level': 'High',
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'details': f"High ICMP packet rate: {len(q)} ICMP packets within {ICMP_FLOOD_WINDOW_SEC}s"
                    })

        # -----------------------------------------------------------
        # Rule 5: Packet Burst (overall packet rate exceeds threshold)
        # -----------------------------------------------------------
        q = self.packet_burst_history[src_ip]
        q.append(now)
        while q and now - q[0] > PACKET_BURST_WINDOW_SEC:
            q.popleft()

        if len(q) > PACKET_BURST_THRESHOLD:
            alert_type = 'Packet Burst'
            if not self._should_suppress_alert(src_ip, alert_type, now):
                alerts.append({
                    'type': alert_type,
                    'risk_level': 'Medium',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'details': f"Packet rate spike: {len(q)} packets within {PACKET_BURST_WINDOW_SEC}s"
                })

        # -----------------------------------------------------------
        # Rule 6: Abnormally Large Packet Anomaly
        # -----------------------------------------------------------
        if size > LARGE_PACKET_THRESHOLD:
            alert_type = 'Anomaly Alert'
            if not self._should_suppress_alert(src_ip, alert_type, now):
                alerts.append({
                    'type': alert_type,
                    'risk_level': 'Medium',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'details': f"Abnormally large packet detected: {size} bytes (exceeds {LARGE_PACKET_THRESHOLD}B MTU limit)"
                })

        return alerts
