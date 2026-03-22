from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import subprocess
import sys
import json

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('dashboard.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

CORS(app)  # Enable CORS for frontend

UPLOAD_FOLDER = '../uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALERTS_FILE = os.path.join(BASE_DIR, 'alerts.json')
ML_SCRIPT = os.path.join(BASE_DIR, 'ml', 'predict_with_alerts.py')

# API: Get alerts (shared alerts.json at root)
@app.route('/api/alerts')
def get_alerts():
    alerts = []
    alerts_file = ALERTS_FILE
    if os.path.exists(alerts_file):
        with open(alerts_file, 'r') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    alerts = alerts[-200:]  # limit
    return jsonify(alerts[::-1])

@app.route('/api/top_attackers')
def get_top_attackers():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, 'r') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    continue
    # Count attacks by src_ip (non-BENIGN)
    attackers = {}
    for a in alerts[-100:]:
        if a.get('predicted_label') != 'BENIGN' and a.get('src_ip'):
            ip = a['src_ip']
            attackers[ip] = attackers.get(ip, 0) + 1
    top = sorted(attackers.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify(top)

@app.route('/api/block/<ip>', methods=['POST'])
def block_ip(ip):
    """Simulate blocking an IP (or use pf)"""
    if ip == 'unknown':
        return jsonify({"success": False, "message": "Cannot block unknown IP"})
    
    # Simulate blocking (print to console)
    print(f"[ACTION] Blocking IP: {ip}")
    
    return jsonify({"success": True, "message": f"Blocked {ip} (simulated)"})

@app.route('/api/metrics')
def get_metrics():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, 'r') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    continue
    non_benign = len([a for a in alerts if a.get('predicted_label') != 'BENIGN'])
    ddos = len([a for a in alerts if a.get('predicted_label') == 'DDoS'])
    return jsonify({"activeAlerts": non_benign, "ddosCount": ddos})

# Upload CSV to root uploads/
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    return jsonify({"message": "File uploaded", "path": filepath})

# Run detection - spawn ML from root cwd
@app.route('/run', methods=['POST'])
def run_detection():
    data = request.get_json()
    filepath = data.get('path') or data.get('file_path')
    if not filepath or not os.path.exists(filepath):
        return jsonify({"error": "Invalid file path"}), 400

    # clear old alerts at root
    with open(ALERTS_FILE, 'w'):
        pass

    # Spawn from root: cd .. && python ml/predict_with_alerts.py $filepath
    subprocess.Popen([sys.executable, ML_SCRIPT, filepath])

    return jsonify({"message": "Detection started"})

if __name__ == '__main__':
    app.run(debug=True, port=5001)

