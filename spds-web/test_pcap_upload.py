import os
import json
from app import app
from storage.db import clear_alerts, get_recent_alerts, get_summary_stats

def run_pcap_upload_tests():
    print("=" * 60)
    print("      SPDS PCAP UPLOAD & REPLAY TEST SUITE (DAY 4)")
    print("=" * 60)

    # Clear DB before test
    clear_alerts()

    # Flask test client
    client = app.test_client()
    sample_pcap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads', 'sample_test.pcap')

    if not os.path.exists(sample_pcap_path):
        print(f"Error: {sample_pcap_path} not found.")
        return

    print(f"\n[Test 1] Uploading PCAP file: {os.path.basename(sample_pcap_path)}")
    with open(sample_pcap_path, 'rb') as f:
        response = client.post('/api/upload_pcap', data={
            'file': (f, 'sample_test.pcap')
        }, content_type='multipart/form-data')

    print(f"HTTP Status Code: {response.status_code}")
    data = json.loads(response.data)
    print("API Response JSON:", json.dumps(data, indent=2))

    assert response.status_code == 200, "Expected HTTP status 200"
    assert data['success'] is True, "Expected success: True"
    assert data['total_packets'] == 62, "Expected 62 total packets"
    assert data['alerts_count'] > 0, "Expected alerts_count > 0"

    print("\n--> PASS: /api/upload_pcap successfully processed PCAP!")

    # Test 2: Database Persistence Verification
    print("\n[Test 2] Database Persistence Verification for PCAP Alerts")
    recent_alerts = get_recent_alerts(limit=50)
    stats = get_summary_stats()

    print(f"Retrieved {len(recent_alerts)} alerts from spds.db")
    print("Summary Stats:", stats)

    assert len(recent_alerts) == data['alerts_count'], "DB row count should match API alerts_count"
    assert stats['total_alerts'] == data['alerts_count'], "Stats total_alerts should match API alerts_count"

    print("\nDetected alert types in DB:")
    for a in recent_alerts:
        print(f" - [{a['risk_level']}] {a['alert_type']} from {a['src_ip']} to {a['dst_ip']}: {a['details']}")

    print("\n" + "=" * 60)
    print(" SUCCESS: Day 4 PCAP Upload & Replay acceptance criteria met!")
    print("=" * 60)

if __name__ == '__main__':
    run_pcap_upload_tests()
