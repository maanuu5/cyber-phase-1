# Suspicious Packet Detection System — Website Build Plan (8-Day Agent Roadmap)

## Overview
Turn the CLI-based SPDS described in the project report into a Flask website that supports **both** live packet capture and pcap file upload/replay, running locally on Windows (localhost demo only — no deployment).

Keep detection rules and risk levels consistent with the report (§10.2 detection rules, §11 risk classification) so the website matches what's already documented.

## Tech Stack (all free, local, zero-cost)
- **Backend:** Python 3.10+, Flask
- **Packet capture:** Scapy (requires the Npcap driver on Windows)
- **Storage:** SQLite (`sqlite3`, built into Python — no server needed)
- **Frontend:** HTML/CSS/vanilla JS, polling via `fetch` every ~2s (no websockets — keeps dependencies minimal), Chart.js from CDN for a simple packet-rate graph
- No paid APIs, no cloud services

## Prerequisites (before Day 1)
- Npcap installed (bundled with Wireshark, or standalone from npcap.com) — required for Scapy to sniff on Windows
- Terminal/IDE must run **as Administrator** whenever live capture is tested
- Python 3.10+ and pip available

## Folder Structure
```
spds-web/
├── app.py
├── capture/
│   ├── sniffer.py
│   └── pcap_reader.py
├── detection/
│   ├── features.py
│   └── rules.py
├── storage/
│   └── db.py
├── templates/
│   └── index.html
├── static/
│   ├── css/style.css
│   └── js/dashboard.js
├── uploads/          (uploaded pcap files land here)
├── spds.db           (created at runtime)
└── requirements.txt
```

## Detection Rules Reference (from report §10.2 / §11)
- **Port Scan** — same source IP hits N distinct destination ports within window T → alert
- **SYN Flood** — source IP sends more than N TCP SYN packets within window T → alert
- **ICMP Flood** — source IP sends more than N ICMP packets within window T → alert
- **Suspicious Port** — traffic touches a port on a defined risky-ports list (e.g. 23 Telnet, 3389 RDP, 4444) → alert
- **Packet Burst** — source IP's overall packet rate exceeds a threshold → alert
- **Risk levels:** Low / Medium / High / Critical (report §11)

---

## Day 1 — Environment & Scaffolding
1. Verify Npcap: run `python -c "from scapy.all import get_if_list; print(get_if_list())"` as Administrator — must list interfaces with no error.
2. Create the folder structure above.
3. `python -m venv venv`, activate it, `pip install flask scapy`, freeze to `requirements.txt`.
4. Build a minimal `app.py` with a single `/` route returning "SPDS running".

**Acceptance:** `python app.py` serves on `localhost:5000`; Scapy lists interfaces without error.

## Day 2 — Detection Engine (standalone, no Flask/capture yet)
1. `detection/features.py`: `extract_features(packet)` → dict with `src_ip, dst_ip, src_port, dst_port, protocol, size, tcp_flags, timestamp`. Wrap in try/except so a malformed packet returns `None` instead of crashing.
2. `detection/rules.py`: implement the 5 rules above using sliding-window structures (e.g. `defaultdict(deque)` keyed by `src_ip`). Each rule returns `None` or an alert dict: `{type, risk_level, src_ip, dst_ip, details}`.
3. Write `test_detection.py` feeding synthetic feature-dicts simulating: normal traffic, port scan, SYN flood, ICMP flood, suspicious port, packet burst, and one malformed/missing-field packet. Print each rule's output.

**Acceptance:** `test_detection.py` correctly flags each scenario and doesn't crash on the malformed one.

## Day 3 — Storage Layer
1. `storage/db.py`: `init_db()` creates `spds.db` with an `alerts` table (`id, timestamp, alert_type, risk_level, src_ip, dst_ip, details`).
2. Functions: `insert_alert(alert)`, `get_recent_alerts(limit=50)`, `get_summary_stats()` (total alerts, breakdown by risk level, top 5 source IPs).
3. Wire the Day 2 test script to write detected alerts into the DB and read them back.

**Acceptance:** `spds.db` contains rows matching what was detected, queryable via the `sqlite3` CLI or a DB browser.

## Day 4 — Pcap Upload/Replay Mode
1. `capture/pcap_reader.py`: `process_pcap_file(filepath)` using `scapy.rdpcap()` — loop through packets, run each through `extract_features` + the rule engine, insert alerts into the DB, return a summary dict.
2. Flask route `POST /api/upload_pcap`: accepts a file upload, saves it to `uploads/`, calls `process_pcap_file`, returns a JSON summary.
3. Test with a small `.pcap` exported from Wireshark (or `curl -F file=@sample.pcap http://localhost:5000/api/upload_pcap`).

**Acceptance:** uploading a pcap returns correctly classified alerts in the JSON response and they land in `spds.db`.

## Day 5 — Live Capture Mode
1. `capture/sniffer.py`: `start_sniffing(interface)` runs `scapy.sniff(iface=interface, prn=callback, store=False)` in a background `threading.Thread`; `stop_sniffing()` sets a flag checked via `stop_filter`. The callback runs the same feature-extraction + rules + DB-insert pipeline as pcap mode.
2. Flask routes: `GET /api/interfaces`, `POST /api/start_capture` (body: interface name), `POST /api/stop_capture`.
3. Run Flask **as Administrator**, start capture on your active interface, generate your own traffic (browse, ping), confirm normal traffic logs as "Normal" without false alerts.

**Acceptance:** capture starts/stops via API calls (test with curl/Postman before the UI exists); alerts appear in the DB in near real time.

## Day 6 — Dashboard Frontend
1. `templates/index.html`: interface dropdown + Start/Stop buttons, pcap upload form, live alerts table, stats cards (total packets, total alerts, breakdown by risk level), a simple line chart (Chart.js via CDN) of alerts-per-minute.
2. `static/js/dashboard.js`: poll `/api/alerts` and `/api/stats` every ~2s via `fetch`, update the DOM; wire button clicks to the start/stop/upload endpoints.
3. `static/css/style.css`: color-code rows by risk level (Low/Medium/High/Critical) matching report §11.

**Acceptance:** `localhost:5000` shows a live-updating dashboard; starting capture or uploading a pcap visibly populates the table and stats with no page refresh.

## Day 7 — Test Against the Report's Own Test Matrix (§12, T01–T08)
Run each case and confirm it matches the report's "Expected Result":
- T01 Normal traffic → Normal
- T02 Traffic to port 23 → Suspicious Alert
- T03 Multiple port connection attempts → Port Scan Alert
- T04 High ICMP rate → Flood Alert
- T05 Large number of SYN packets → SYN Flood Alert
- T06 Abnormally large packet → Anomaly Alert
- T07 Mixed normal + suspicious traffic → correct classification of each
- T08 Malformed/unexpected packet → handled safely, no crash

Generate test traffic only against **your own machine** (e.g. `ping` with a large payload for T06, `nmap localhost` for T03, a small Scapy script or `hping3` against loopback for T04/T05). Fix any bugs found.

**Acceptance:** all 8 test cases pass and match the report's expected results.

## Day 8 — Polish, Docs, Demo Prep
1. Write `README.md`: install Npcap → `pip install -r requirements.txt` → run terminal as Administrator → `python app.py` → open `http://localhost:5000`.
2. Take dashboard screenshots mid-alert for your submission/slides.
3. Prepare a short demo script (order of actions) plus a known-good pcap file as a fallback in case live capture hits permission issues on demo day.
4. Optional: record a short screen-capture run-through as backup.

**Acceptance:** the whole system runs start-to-finish on a clean checkout following only the README.

---

## If You Have Extra Days (up to 10)
- **Extra day A:** split Day 6 into backend wiring + visual polish.
- **Extra day B:** add a "top talkers" table, CSV export of alerts, or a basic login gate if your evaluator wants one.

## Notes for the Agent
- Keep detection thresholds (window size, packet counts) as constants at the top of `rules.py` so they're easy to tune without touching logic.
- Never sniff or scan networks/devices other than your own during testing or the demo.
- If Npcap/admin permissions block live capture, the pcap-upload path (Day 4) still fully demonstrates the system — don't let Day 5 block progress on Day 6+.
