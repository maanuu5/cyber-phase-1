# Suspicious Packet Detection System (SPDS) — Web Dashboard

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1.3-green.svg)](https://flask.palletsprojects.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.7.0-red.svg)](https://scapy.net/)
[![SQLite](https://img.shields.io/badge/Database-SQLite3-lightgrey.svg)](https://www.sqlite.org/)

## 🛡️ Overview
The **Suspicious Packet Detection System (SPDS)** is a real-time network security dashboard built with Python, Flask, Scapy, and SQLite. It provides dual-mode operation supporting both **Live Packet Capture** over network interfaces and **PCAP File Upload/Replay** analysis.

SPDS implements 6 stateful detection rules matching the project report specifications (§10.2 / §11 / §12):
1. **Port Scan** (*High Risk*): Detects single source IPs probing distinct ports.
2. **SYN Flood** (*Critical Risk*): Detects TCP SYN packet rate spikes.
3. **ICMP Flood** (*High Risk*): Detects ICMP packet floods.
4. **Suspicious Port** (*Medium Risk*): Flags connections to high-risk ports (e.g. 23 Telnet, 3389 RDP, 4444 Metasploit).
5. **Packet Burst** (*Medium Risk*): Identifies general traffic volume spikes.
6. **Large Packet Anomaly** (*Medium Risk*): Flags packets exceeding standard MTU frame limits.

---

## 🚀 Quick Start Guide

### Prerequisites
1. **Npcap Driver (Windows):** Required for Scapy live sniffing. Installed automatically with [Wireshark](https://www.wireshark.org/) or available standalone at [npcap.com](https://npcap.com/).
2. **Python 3.10+** installed on system.
3. **Administrator Permissions:** The command prompt / terminal **must be run as Administrator** for live packet sniffing on Windows network interfaces.

### Installation & Execution
```bash
# 1. Navigate to project root
cd spds-web

# 2. Create & Activate Virtual Environment
python -m venv venv
venv\Scripts\activate      # Windows PowerShell: .\venv\Scripts\Activate.ps1

# 3. Install Dependencies
pip install -r requirements.txt

# 4. Run Flask Server (as Administrator for live capture)
python app.py
```

Open your browser and navigate to: **`http://localhost:5000`**

---

## 📂 Project Architecture
```
spds-web/
├── app.py                   # Main Flask Application & REST API Endpoints
├── capture/
│   ├── sniffer.py           # Background Live Packet Capture Thread Handler
│   └── pcap_reader.py       # PCAP File Reader & Analysis Pipeline
├── detection/
│   ├── features.py          # Network Packet Feature Extractor
│   └── rules.py             # Stateful Detection Engine & Sliding Windows
├── storage/
│   └── db.py                # SQLite Database Interface & Aggregation Queries
├── templates/
│   └── index.html           # Real-Time Dashboard Web Interface
├── static/
│   ├── css/style.css        # Cyber Security Dark Theme Stylesheet
│   └── js/dashboard.js      # Dashboard Polling & Chart.js Interactivity
├── uploads/                 # Storage Directory for Uploaded PCAP Files
│   └── sample_test.pcap     # Pre-packaged Test PCAP File for Demos
├── spds.db                  # SQLite Database (Auto-generated at runtime)
├── test_detection.py        # Standalone Rule Engine & DB Integration Tests
├── test_live_capture.py     # Live Capture API Integration Tests
├── test_pcap_upload.py      # PCAP Upload API Integration Tests
├── test_matrix_report.py    # Complete Report Test Matrix (§12 T01-T08)
└── requirements.txt         # Frozen Dependencies
```

---

## 💻 Demo Script & Step-by-Step Presentation

### Live Capture Demo
1. Open terminal **as Administrator** and start server (`python app.py`).
2. Open `http://localhost:5000` in browser.
3. In the **Live Packet Capture Control** card, select your active network interface (e.g. Wi-Fi / Ethernet).
4. Click **▶ Start Live Capture**. Notice the live status dot turns green and packet counter increments in real time.
5. In another terminal or command window, trigger test traffic:
   - `ping 127.0.0.1` or ping external IP.
6. Click **⏹ Stop Capture**. Observed traffic and generated alerts are displayed in the alerts table and stats metrics cards.

### PCAP Replay Demo (Fallback / Standalone)
1. On the dashboard under **PCAP File Upload & Replay**, click **Choose File**.
2. Select `uploads/sample_test.pcap` (located in the project folder).
3. Click **⚡ Process & Analyze PCAP**.
4. The dashboard instantly processes 62 packets, populating:
   - Total Alerts & Risk Level breakdown.
   - Attack Source IP list (`10.0.0.80`, `10.0.0.70`, `10.0.0.60`, `10.0.0.50`).
   - Color-coded alert table rows (Critical, High, Medium).
   - Real-time line chart trend dataset.

---

## 🧪 Verification & Test Suite
To execute all automated verification suites:

```bash
# Run Detection Engine & SQLite Unit Tests
python test_detection.py

# Run PCAP Upload & API Tests
python test_pcap_upload.py

# Run Live Capture API Tests
python test_live_capture.py

# Run Report Test Matrix (§12 T01-T08)
python test_matrix_report.py
```
