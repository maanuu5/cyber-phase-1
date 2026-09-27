import os
from scapy.all import rdpcap
from detection.features import extract_features
from detection.rules import RuleEngine
from storage.db import insert_alert

def process_pcap_file(filepath, db_path=None):
    """
    Reads a PCAP file using Scapy, processes packets through extract_features
    and RuleEngine, inserts detected alerts into SQLite DB, and returns a summary dict.
    """
    if not os.path.exists(filepath):
        return {
            'success': False,
            'error': f"File not found: {filepath}"
        }

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        return {
            'success': False,
            'error': f"Failed to parse PCAP file: {str(e)}"
        }

    engine = RuleEngine()
    total_packets = len(packets)
    processed_packets = 0
    all_alerts = []

    for pkt in packets:
        feats = extract_features(pkt)
        if feats is not None:
            processed_packets += 1
            detected_alerts = engine.analyze(feats)
            for alert in detected_alerts:
                alert_id = insert_alert(alert, db_path=db_path)
                alert_copy = dict(alert)
                alert_copy['id'] = alert_id
                all_alerts.append(alert_copy)

    return {
        'success': True,
        'filename': os.path.basename(filepath),
        'total_packets': total_packets,
        'processed_packets': processed_packets,
        'alerts_count': len(all_alerts),
        'alerts': all_alerts
    }
