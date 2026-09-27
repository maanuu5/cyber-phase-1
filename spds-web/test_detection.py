import time
from detection.features import extract_features
from detection.rules import (
    RuleEngine, PORT_SCAN_THRESHOLD, SYN_FLOOD_THRESHOLD,
    ICMP_FLOOD_THRESHOLD, PACKET_BURST_THRESHOLD
)
from storage.db import init_db, insert_alert, get_recent_alerts, get_summary_stats, clear_alerts

def run_tests():
    engine = RuleEngine()
    print("=" * 60)
    print("  SPDS INTEGRATED DETECTION & STORAGE TEST SUITE (DAY 3)")
    print("=" * 60)
    
    # Initialize and clear DB for clean test run
    init_db()
    clear_alerts()

    passed_tests = 0
    total_tests = 8

    # -------------------------------------------------------------
    # Test 1: Normal Traffic
    # -------------------------------------------------------------
    engine.reset_state()
    normal_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '142.250.190.46',
        'src_port': 54321,
        'dst_port': 443,
        'protocol': 'TCP',
        'size': 120,
        'tcp_flags': 'A',
        'timestamp': time.time()
    }
    feats = extract_features(normal_packet)
    alerts = engine.analyze(feats)
    for a in alerts:
        insert_alert(a)

    print(f"\n[Test 1] Normal Traffic (IP {normal_packet['src_ip']} -> {normal_packet['dst_ip']}:{normal_packet['dst_port']})")
    print(f"Result: {len(alerts)} alert(s) returned.")
    if len(alerts) == 0:
        print("--> PASS (No false alerts)")
        passed_tests += 1
    else:
        print(f"--> FAIL (Unexpected alerts: {alerts})")

    # -------------------------------------------------------------
    # Test 2: Suspicious Port Traffic
    # -------------------------------------------------------------
    engine.reset_state()
    suspicious_packet = {
        'src_ip': '10.0.0.50',
        'dst_ip': '192.168.1.1',
        'src_port': 49152,
        'dst_port': 23,  # Telnet
        'protocol': 'TCP',
        'size': 64,
        'tcp_flags': 'S',
        'timestamp': time.time()
    }
    feats = extract_features(suspicious_packet)
    alerts = engine.analyze(feats)
    for a in alerts:
        insert_alert(a)

    print(f"\n[Test 2] Suspicious Port (Telnet Port 23)")
    print(f"Alerts: {alerts}")
    if any(a['type'] == 'Suspicious Port' for a in alerts):
        print("--> PASS (Suspicious Port correctly flagged & inserted into DB)")
        passed_tests += 1
    else:
        print("--> FAIL (Suspicious Port not flagged)")

    # -------------------------------------------------------------
    # Test 3: Port Scan Simulation
    # -------------------------------------------------------------
    engine.reset_state()
    scan_ip = '10.0.0.60'
    start_time = time.time()
    scan_alerts = []
    for p in range(1, PORT_SCAN_THRESHOLD + 5):
        pkt = {
            'src_ip': scan_ip,
            'dst_ip': '192.168.1.1',
            'src_port': 50000,
            'dst_port': p,
            'protocol': 'TCP',
            'size': 60,
            'tcp_flags': 'S',
            'timestamp': start_time + (p * 0.05)
        }
        feats = extract_features(pkt)
        detected = engine.analyze(feats)
        for a in detected:
            insert_alert(a)
        scan_alerts.extend(detected)
    
    print(f"\n[Test 3] Port Scan ({PORT_SCAN_THRESHOLD + 4} distinct ports)")
    print(f"Alerts triggered: {scan_alerts}")
    if any(a['type'] == 'Port Scan' for a in scan_alerts):
        print("--> PASS (Port Scan correctly flagged & inserted into DB)")
        passed_tests += 1
    else:
        print("--> FAIL (Port Scan not flagged)")

    # -------------------------------------------------------------
    # Test 4: SYN Flood Simulation
    # -------------------------------------------------------------
    engine.reset_state()
    syn_ip = '10.0.0.70'
    start_time = time.time()
    syn_alerts = []
    for i in range(SYN_FLOOD_THRESHOLD + 5):
        pkt = {
            'src_ip': syn_ip,
            'dst_ip': '192.168.1.1',
            'src_port': 40000 + i,
            'dst_port': 80,
            'protocol': 'TCP',
            'size': 54,
            'tcp_flags': 'S',
            'timestamp': start_time + (i * 0.02)
        }
        feats = extract_features(pkt)
        detected = engine.analyze(feats)
        for a in detected:
            insert_alert(a)
        syn_alerts.extend(detected)

    print(f"\n[Test 4] SYN Flood ({SYN_FLOOD_THRESHOLD + 5} SYN packets)")
    print(f"Alerts triggered: {syn_alerts}")
    if any(a['type'] == 'SYN Flood' and a['risk_level'] == 'Critical' for a in syn_alerts):
        print("--> PASS (SYN Flood correctly flagged & inserted into DB)")
        passed_tests += 1
    else:
        print("--> FAIL (SYN Flood not flagged correctly)")

    # -------------------------------------------------------------
    # Test 5: ICMP Flood Simulation
    # -------------------------------------------------------------
    engine.reset_state()
    icmp_ip = '10.0.0.80'
    start_time = time.time()
    icmp_alerts = []
    for i in range(ICMP_FLOOD_THRESHOLD + 5):
        pkt = {
            'src_ip': icmp_ip,
            'dst_ip': '192.168.1.1',
            'src_port': None,
            'dst_port': None,
            'protocol': 'ICMP',
            'size': 84,
            'tcp_flags': None,
            'timestamp': start_time + (i * 0.02)
        }
        feats = extract_features(pkt)
        detected = engine.analyze(feats)
        for a in detected:
            insert_alert(a)
        icmp_alerts.extend(detected)

    print(f"\n[Test 5] ICMP Flood ({ICMP_FLOOD_THRESHOLD + 5} ICMP packets)")
    print(f"Alerts triggered: {icmp_alerts}")
    if any(a['type'] == 'ICMP Flood' for a in icmp_alerts):
        print("--> PASS (ICMP Flood correctly flagged & inserted into DB)")
        passed_tests += 1
    else:
        print("--> FAIL (ICMP Flood not flagged)")

    # -------------------------------------------------------------
    # Test 6: Packet Burst Simulation
    # -------------------------------------------------------------
    engine.reset_state()
    burst_ip = '10.0.0.90'
    start_time = time.time()
    burst_alerts = []
    for i in range(PACKET_BURST_THRESHOLD + 5):
        pkt = {
            'src_ip': burst_ip,
            'dst_ip': '192.168.1.1',
            'src_port': 1000 + i,
            'dst_port': 8080,
            'protocol': 'UDP',
            'size': 500,
            'tcp_flags': None,
            'timestamp': start_time + (i * 0.01)
        }
        feats = extract_features(pkt)
        detected = engine.analyze(feats)
        for a in detected:
            insert_alert(a)
        burst_alerts.extend(detected)

    print(f"\n[Test 6] Packet Burst ({PACKET_BURST_THRESHOLD + 5} overall packets)")
    print(f"Alerts triggered: {burst_alerts}")
    if any(a['type'] == 'Packet Burst' for a in burst_alerts):
        print("--> PASS (Packet Burst correctly flagged & inserted into DB)")
        passed_tests += 1
    else:
        print("--> FAIL (Packet Burst not flagged)")

    # -------------------------------------------------------------
    # Test 7: Malformed / Missing-field Packet Handling
    # -------------------------------------------------------------
    engine.reset_state()
    malformed_inputs = [
        "not_a_packet_object",
        None,
        {'src_ip': '10.0.0.1'},
        12345
    ]
    malformed_passed = True
    print("\n[Test 7] Malformed Packet Resilience")
    for item in malformed_inputs:
        try:
            feats = extract_features(item)
            alerts = engine.analyze(feats)
            for a in alerts:
                insert_alert(a)
        except Exception as e:
            print(f" CRASH! Exception raised: {e}")
            malformed_passed = False

    if malformed_passed:
        print("--> PASS (All malformed packets handled safely)")
        passed_tests += 1
    else:
        print("--> FAIL (Engine crashed on malformed packet)")

    # -------------------------------------------------------------
    # Test 8: SQLite Database Verification (Reading alerts & stats back)
    # -------------------------------------------------------------
    print("\n[Test 8] SQLite Database Integrity & Query Verification")
    db_alerts = get_recent_alerts(limit=50)
    stats = get_summary_stats()

    print(f"Total rows retrieved from spds.db: {len(db_alerts)}")
    print(f"Summary stats from spds.db: {stats}")

    if len(db_alerts) > 0 and stats['total_alerts'] == len(db_alerts):
        print("Sample DB Row 1:", db_alerts[0])
        print("--> PASS (Alerts correctly queried from spds.db with matching stats)")
        passed_tests += 1
    else:
        print(f"--> FAIL (DB row count mismatch: retrieved {len(db_alerts)}, stats say {stats['total_alerts']})")

    # Summary
    print("\n" + "=" * 60)
    print(f" TEST RESULTS: {passed_tests}/{total_tests} Tests Passed")
    print("=" * 60)

    if passed_tests == total_tests:
        print("SUCCESS: Day 3 Storage & DB integration acceptance criteria met!")
    else:
        print("WARNING: Some integration tests failed.")

if __name__ == '__main__':
    run_tests()
