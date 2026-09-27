import time
from detection.features import extract_features
from detection.rules import (
    RuleEngine, PORT_SCAN_THRESHOLD, SYN_FLOOD_THRESHOLD,
    ICMP_FLOOD_THRESHOLD, PACKET_BURST_THRESHOLD
)

def run_test_matrix():
    engine = RuleEngine()
    print("=" * 70)
    print("    SPDS REPORT TEST MATRIX VERIFICATION (REPORT §12, T01-T08)")
    print("=" * 70)

    results = []

    # T01: Normal traffic -> Normal
    engine.reset_state()
    pkt = {'src_ip': '192.168.1.5', 'dst_ip': '8.8.8.8', 'src_port': 52345, 'dst_port': 443, 'protocol': 'TCP', 'size': 120, 'tcp_flags': 'A', 'timestamp': time.time()}
    alerts = engine.analyze(extract_features(pkt))
    passed = len(alerts) == 0
    results.append(('T01', 'Normal traffic', 'Normal (0 alerts)', 'Normal' if passed else f'Alerts: {alerts}', passed))

    # T02: Traffic to port 23 -> Suspicious Alert
    engine.reset_state()
    pkt = {'src_ip': '192.168.1.10', 'dst_ip': '10.0.0.1', 'src_port': 40000, 'dst_port': 23, 'protocol': 'TCP', 'size': 64, 'tcp_flags': 'S', 'timestamp': time.time()}
    alerts = engine.analyze(extract_features(pkt))
    passed = any(a['type'] == 'Suspicious Port' for a in alerts)
    results.append(('T02', 'Traffic to port 23', 'Suspicious Port Alert', alerts[0]['type'] if passed else 'No alert', passed))

    # T03: Multiple port connection attempts -> Port Scan Alert
    engine.reset_state()
    scan_alerts = []
    t0 = time.time()
    for p in range(1, PORT_SCAN_THRESHOLD + 3):
        p_pkt = {'src_ip': '192.168.1.20', 'dst_ip': '10.0.0.1', 'src_port': 50000, 'dst_port': p, 'protocol': 'TCP', 'size': 60, 'tcp_flags': 'S', 'timestamp': t0 + p * 0.05}
        scan_alerts.extend(engine.analyze(extract_features(p_pkt)))
    passed = any(a['type'] == 'Port Scan' for a in scan_alerts)
    results.append(('T03', 'Multiple port connection attempts', 'Port Scan Alert', 'Port Scan Alert' if passed else 'No alert', passed))

    # T04: High ICMP rate -> Flood Alert
    engine.reset_state()
    icmp_alerts = []
    t0 = time.time()
    for i in range(ICMP_FLOOD_THRESHOLD + 3):
        i_pkt = {'src_ip': '192.168.1.30', 'dst_ip': '10.0.0.1', 'src_port': None, 'dst_port': None, 'protocol': 'ICMP', 'size': 84, 'tcp_flags': None, 'timestamp': t0 + i * 0.02}
        icmp_alerts.extend(engine.analyze(extract_features(i_pkt)))
    passed = any(a['type'] == 'ICMP Flood' for a in icmp_alerts)
    results.append(('T04', 'High ICMP rate', 'ICMP Flood Alert', 'ICMP Flood Alert' if passed else 'No alert', passed))

    # T05: Large number of SYN packets -> SYN Flood Alert
    engine.reset_state()
    syn_alerts = []
    t0 = time.time()
    for i in range(SYN_FLOOD_THRESHOLD + 3):
        s_pkt = {'src_ip': '192.168.1.40', 'dst_ip': '10.0.0.1', 'src_port': 30000 + i, 'dst_port': 80, 'protocol': 'TCP', 'size': 54, 'tcp_flags': 'S', 'timestamp': t0 + i * 0.02}
        syn_alerts.extend(engine.analyze(extract_features(s_pkt)))
    passed = any(a['type'] == 'SYN Flood' for a in syn_alerts)
    results.append(('T05', 'Large number of SYN packets', 'SYN Flood Alert', 'SYN Flood Alert' if passed else 'No alert', passed))

    # T06: Abnormally large packet -> Anomaly Alert
    engine.reset_state()
    pkt = {'src_ip': '192.168.1.50', 'dst_ip': '10.0.0.1', 'src_port': 5000, 'dst_port': 80, 'protocol': 'UDP', 'size': 9000, 'tcp_flags': None, 'timestamp': time.time()}
    alerts = engine.analyze(extract_features(pkt))
    passed = any(a['type'] == 'Anomaly Alert' for a in alerts)
    results.append(('T06', 'Abnormally large packet', 'Anomaly Alert', alerts[0]['type'] if passed else 'No alert', passed))

    # T07: Mixed normal + suspicious traffic -> correct classification
    engine.reset_state()
    mixed_packets = [
        {'src_ip': '192.168.1.100', 'dst_ip': '8.8.8.8', 'src_port': 54321, 'dst_port': 443, 'protocol': 'TCP', 'size': 120, 'tcp_flags': 'A', 'timestamp': time.time()},
        {'src_ip': '192.168.1.101', 'dst_ip': '10.0.0.1', 'src_port': 40000, 'dst_port': 23, 'protocol': 'TCP', 'size': 64, 'tcp_flags': 'S', 'timestamp': time.time() + 0.1}
    ]
    all_mixed_alerts = []
    for m_pkt in mixed_packets:
        all_mixed_alerts.extend(engine.analyze(extract_features(m_pkt)))
    passed = len(all_mixed_alerts) == 1 and all_mixed_alerts[0]['type'] == 'Suspicious Port' and all_mixed_alerts[0]['src_ip'] == '192.168.1.101'
    results.append(('T07', 'Mixed normal + suspicious traffic', 'Correct classification of each', '1 Suspicious Alert (192.168.1.101)' if passed else 'Incorrect', passed))

    # T08: Malformed/unexpected packet -> handled safely, no crash
    engine.reset_state()
    try:
        f1 = extract_features("invalid_raw_bytes")
        a1 = engine.analyze(f1)
        f2 = extract_features(None)
        a2 = engine.analyze(f2)
        passed = True
    except Exception:
        passed = False
    results.append(('T08', 'Malformed/unexpected packet', 'Handled safely, no crash', 'Safely handled (0 crashes)', passed))

    # Output Summary Table
    print(f"{'Test Case':<10} | {'Input Scenario':<35} | {'Expected Result':<25} | {'Status'}")
    print("-" * 80)
    all_passed = True
    for tid, scenario, expected, actual, p in results:
        status_str = "PASS" if p else "FAIL"
        if not p: all_passed = False
        print(f"{tid:<10} | {scenario:<35} | {expected:<25} | {status_str}")

    print("=" * 80)
    if all_passed:
        print("ALL 8 REPORT TEST CASES (T01-T08) PASSED SUCCESSFULLY!")
    else:
        print("SOME TEST CASES FAILED.")

if __name__ == '__main__':
    run_test_matrix()
