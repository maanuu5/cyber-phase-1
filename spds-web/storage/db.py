import os
import sqlite3
from datetime import datetime

# Default database path: spds.db in the spds-web directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, 'spds.db')

def get_db_connection(db_path=None):
    """Establishes a connection to the SQLite database with Row factory enabled."""
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path=None):
    """Creates the alerts table if it does not already exist."""
    path = db_path or DEFAULT_DB_PATH
    conn = get_db_connection(path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            details TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_alert(alert, db_path=None):
    """
    Inserts an alert dict into the alerts table.
    alert dict must contain: type, risk_level, src_ip, dst_ip, details.
    Optionally contains timestamp (ISO/formatted string or numeric epoch).
    """
    if not alert or not isinstance(alert, dict):
        return None

    path = db_path or DEFAULT_DB_PATH
    init_db(path)

    # Format timestamp if missing or if epoch float
    ts = alert.get('timestamp')
    if ts is None:
        formatted_ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(ts, (int, float)):
        formatted_ts = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    else:
        formatted_ts = str(ts)

    conn = get_db_connection(path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (timestamp, alert_type, risk_level, src_ip, dst_ip, details)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        formatted_ts,
        alert.get('type', 'Unknown'),
        alert.get('risk_level', 'Low'),
        alert.get('src_ip', '0.0.0.0'),
        alert.get('dst_ip', '0.0.0.0'),
        alert.get('details', '')
    ))
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return alert_id

def get_recent_alerts(limit=50, db_path=None):
    """Retrieves recent alerts up to limit, ordered by most recent first."""
    path = db_path or DEFAULT_DB_PATH
    init_db(path)
    conn = get_db_connection(path)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, timestamp, alert_type, risk_level, src_ip, dst_ip, details
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_summary_stats(db_path=None):
    """
    Returns summary metrics:
    - total_alerts: total count
    - risk_breakdown: counts by risk level (Low, Medium, High, Critical)
    - top_source_ips: top 5 source IPs by alert count
    """
    path = db_path or DEFAULT_DB_PATH
    init_db(path)
    conn = get_db_connection(path)
    cursor = conn.cursor()

    # Total alerts count
    cursor.execute('SELECT COUNT(*) as count FROM alerts')
    total_alerts = cursor.fetchone()['count']

    # Risk breakdown
    cursor.execute('''
        SELECT risk_level, COUNT(*) as count
        FROM alerts
        GROUP BY risk_level
    ''')
    risk_rows = cursor.fetchall()
    risk_breakdown = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
    for r in risk_rows:
        risk_breakdown[r['risk_level']] = r['count']

    # Top 5 Source IPs
    cursor.execute('''
        SELECT src_ip, COUNT(*) as count
        FROM alerts
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 5
    ''')
    ip_rows = cursor.fetchall()
    top_source_ips = [{'src_ip': r['src_ip'], 'count': r['count']} for r in ip_rows]

    conn.close()

    return {
        'total_alerts': total_alerts,
        'risk_breakdown': risk_breakdown,
        'top_source_ips': top_source_ips
    }

def clear_alerts(db_path=None):
    """Clears all records from the alerts table."""
    path = db_path or DEFAULT_DB_PATH
    init_db(path)
    conn = get_db_connection(path)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM alerts')
    conn.commit()
    conn.close()
