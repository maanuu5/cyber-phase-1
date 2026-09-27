import time
import json
from app import app

def run_live_capture_tests():
    print("=" * 60)
    print("      SPDS LIVE CAPTURE API TEST SUITE (DAY 5)")
    print("=" * 60)

    client = app.test_client()

    # Test 1: GET /api/interfaces
    print("\n[Test 1] Listing available interfaces (GET /api/interfaces)")
    res = client.get('/api/interfaces')
    assert res.status_code == 200, "Expected HTTP 200"
    ifaces_data = json.loads(res.data)
    print("Interfaces API response:", json.dumps(ifaces_data, indent=2))
    assert ifaces_data['success'] is True
    assert len(ifaces_data['interfaces']) > 0, "Expected at least 1 interface"
    
    selected_iface = ifaces_data['interfaces'][0]['id']
    print(f"--> PASS: Retrived {len(ifaces_data['interfaces'])} network interface(s). Selected: {selected_iface}")

    # Test 2: POST /api/start_capture
    print(f"\n[Test 2] Starting live capture on interface: {selected_iface}")
    res = client.post('/api/start_capture', json={'interface': selected_iface})
    print(f"Start Capture HTTP Status: {res.status_code}")
    start_data = json.loads(res.data)
    print("Start Response:", start_data)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert start_data['success'] is True

    # Check status
    res = client.get('/api/capture_status')
    status_data = json.loads(res.data)
    print("Capture Status Response:", status_data)
    assert status_data['status']['is_running'] is True, "Expected is_running: True"
    print("--> PASS: Live capture started successfully!")

    # Wait 2 seconds while capture runs in background
    print("Sleeping 2 seconds while live capture runs...")
    time.sleep(2.0)

    # Check status again
    res = client.get('/api/capture_status')
    status_data = json.loads(res.data)
    print("Updated Status Response:", status_data)

    # Test 3: POST /api/stop_capture
    print("\n[Test 3] Stopping live capture (POST /api/stop_capture)")
    res = client.post('/api/stop_capture')
    print(f"Stop Capture HTTP Status: {res.status_code}")
    stop_data = json.loads(res.data)
    print("Stop Response:", stop_data)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    assert stop_data['success'] is True

    # Check final status
    res = client.get('/api/capture_status')
    status_data = json.loads(res.data)
    print("Final Status Response:", status_data)
    assert status_data['status']['is_running'] is False, "Expected is_running: False"
    print("--> PASS: Live capture stopped successfully!")

    print("\n" + "=" * 60)
    print(" SUCCESS: Day 5 Live Capture API acceptance criteria met!")
    print("=" * 60)

if __name__ == '__main__':
    run_live_capture_tests()
