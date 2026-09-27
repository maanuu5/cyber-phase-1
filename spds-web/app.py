import os
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from capture.pcap_reader import process_pcap_file
from capture.sniffer import sniffer
from storage.db import init_db, get_recent_alerts, get_summary_stats, clear_alerts

app = Flask(__name__)

# Configure Uploads directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max limit

# Ensure database is initialized
init_db()

@app.route('/')
def index():
    return render_template('index.html')

# ==========================================
# PCAP Upload Routes
# ==========================================

@app.route('/api/upload_pcap', methods=['POST'])
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file field in request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400

    filename = secure_filename(file.filename)
    if not filename:
        filename = "uploaded.pcap"

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        file.save(filepath)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to save uploaded file: {str(e)}'}), 500

    # Process PCAP file through detection engine and DB
    summary = process_pcap_file(filepath)
    return jsonify(summary)

# ==========================================
# Live Capture Routes
# ==========================================

@app.route('/api/interfaces', methods=['GET'])
def list_interfaces():
    ifaces = sniffer.get_interfaces()
    return jsonify({'success': True, 'interfaces': ifaces})

@app.route('/api/start_capture', methods=['POST'])
def start_capture():
    data = request.get_json(silent=True) or request.form
    interface = data.get('interface')

    if not interface:
        # Fall back to first available interface if unspecified
        ifaces = sniffer.get_interfaces()
        if ifaces:
            interface = ifaces[0]['id']
        else:
            interface = 'default'

    res = sniffer.start_sniffing(interface)
    status_code = 200 if res.get('success') else 400
    return jsonify(res), status_code

@app.route('/api/stop_capture', methods=['POST'])
def stop_capture():
    res = sniffer.stop_sniffing()
    status_code = 200 if res.get('success') else 400
    return jsonify(res), status_code

@app.route('/api/capture_status', methods=['GET'])
def capture_status():
    status = sniffer.get_status()
    return jsonify({'success': True, 'status': status})

# ==========================================
# Alerts & Database Routes
# ==========================================

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    limit = request.args.get('limit', default=50, type=int)
    alerts = get_recent_alerts(limit=limit)
    return jsonify({'success': True, 'count': len(alerts), 'alerts': alerts})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    stats = get_summary_stats()
    status = sniffer.get_status()
    stats['live_capture'] = status
    return jsonify({'success': True, 'stats': stats})

@app.route('/api/clear_db', methods=['POST'])
def clear_db_route():
    clear_alerts()
    return jsonify({'success': True, 'message': 'Database cleared successfully'})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
