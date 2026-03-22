from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import os
import subprocess
import sys
import json
import time

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

CORS(app)  # Enable CORS for frontend

UPLOAD_FOLDER = '../uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__name__), '..'))
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

blocked_ips_list = []
blocked_count = 0

@app.route('/api/block/<ip>', methods=['POST'])
def block_ip(ip):
    global blocked_count
    if ip == 'unknown':
        return jsonify({"success": False, "message": "Cannot block unknown IP"})
    
    if ip not in blocked_ips_list:
        blocked_ips_list.append(ip)
        blocked_count += 1
    
    print(f"[ACTION] Blocked IP: {ip}")
    
    # Optional: actual pf blocking (requires sudo)
    # try:
    #     subprocess.run(['sudo', 'pfctl', '-t', 'blocked_ips', '-T', 'add', ip], check=True)
    # except:
    #     pass
    
    return jsonify({"success": True, "message": f"Blocked {ip}", "blocked_count": blocked_count})

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

@app.route('/api/threat_summary')
def get_threat_summary():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, 'r') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    continue
    non_benign = [a for a in alerts if a.get('predicted_label') != 'BENIGN']
    total = len(non_benign)
    
    if non_benign:
        attack_types = {}
        attackers = {}
        critical_count = 0
        for a in non_benign:
            label = a.get('predicted_label', 'Unknown')
            attack_types[label] = attack_types.get(label, 0) + 1
            ip = a.get('src_ip', 'unknown')
            attackers[ip] = attackers.get(ip, 0) + 1
            if 'DDoS' in label or 'DoS' in label:
                critical_count += 1
        
        top_attack = max(attack_types, key=attack_types.get)
        top_ip = max(attackers, key=attackers.get)
    else:
        top_attack = 'None'
        top_ip = 'None'
        critical_count = 0
    
    return jsonify({
        "top_attack": top_attack,
        "top_ip": top_ip,
        "total_alerts": total,
        "critical": critical_count
    })

@app.route('/api/attack_locations')
def get_attack_locations():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, 'r') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    continue
    non_benign = [a for a in alerts[-50:] if a.get('predicted_label') != 'BENIGN' and a.get('src_ip')]
    
    locations = []
    seen_ips = {}
    for a in non_benign:
        ip = a['src_ip']
        if ip not in seen_ips:
            h1 = hash(ip) % 180 - 90  # lat -90 to 90
            h2 = hash(ip[::-1]) % 360 - 180  # lon -180 to 180
            label = a.get('predicted_label', 'Unknown')
            seen_ips[ip] = True
            locations.append({
                "ip": ip,
                "lat": round(h1, 4),
                "lon": round(h2, 4),
                "type": label
            })
            if len(locations) >= 10:
                break
    return jsonify(locations)

@app.route('/api/live_packets')
def get_live_packets():
    # Mock live packets (scapy sniff simulation)
    import random
    packets = []
    protocols = ['TCP', 'UDP', 'ICMP']
    for i in range(10):
        now = int(time.time())
        src_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        dst_ip = f"10.0.{random.randint(1,10)}.{random.randint(1,255)}"
        proto = random.choice(protocols)
        size = random.randint(64, 1500)
        packets.append({
            "time": now - random.randint(0,30),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "size": size
        })
    return jsonify(packets)

@app.route('/api/network_traffic')
def get_network_traffic():
    try:
        import psutil
        stats = psutil.net_io_counters()
        return jsonify({
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv,
            "pps": random.randint(100, 1000)  # estimated packets/sec
        })
    except:
        return jsonify({"pps": 0, "bytes_sent": 0, "bytes_recv": 0, "packets_sent": 0, "packets_recv": 0})

@app.route('/api/attack_timeline')
def get_attack_timeline():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, 'r') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
    timeline = []
    now = int(time.time())
    for minute in range(10, 0, -1):
        t_start = now - minute * 60
        t_end = t_start + 60
        count = len([a for a in alerts if a.get('predicted_label') != 'BENIGN' and t_start <= a.get('time', 0) < t_end])
        timeline.append({
            "time": f"{minute}m ago",
            "alerts": count
        })
    return jsonify(timeline)

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
@app.route('/api/progress')\ndef get_progress():\n    progress_file = os.path.join(BASE_DIR, 'progress.json')\n    if os.path.exists(progress_file):\n        with open(progress_file, 'r') as f:\n            return jsonify(json.load(f))\n    return jsonify({'percentage': 0, 'message': 'Waiting...'})\n\n@app.route('/run', methods=['POST'])\ndef run_detection():\n    data = request.get_json()\n    filepath = data.get('path') or data.get('file_path')\n    if not filepath or not os.path.exists(filepath):\n        return jsonify({"error": "Invalid file path"}), 400\n\n    # clear old alerts at root\n    with open(ALERTS_FILE, 'w'):\n        pass\n\n    # Spawn from root: cd .. && python ml/predict_with_alerts.py $filepath\n    subprocess.Popen([sys.executable, ML_SCRIPT, filepath])\n\n    return jsonify({"message": "Detection started"})

if __name__ == '__main__':
    app.run(debug=True, port=5001)
