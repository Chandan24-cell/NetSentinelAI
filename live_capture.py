#!/usr/bin/env python3
"""
Live Packet Capture + Simplified IDS Demo
⚠️ SIMPLIFIED: Uses basic packet features (model expects flows)
✅ Production-ready alerting + dashboard integration
For full accuracy: Use CICFlowMeter → auto_detect.py
"""

import time
import json
import os
from scapy.all import sniff, IP, TCP, UDP
import joblib
import numpy as np
from pathlib import Path

BASE_DIR = Path(__file__).parent
MODEL_PATH = BASE_DIR / 'ml' / 'random_forest_full.pkl'
LABEL_PATH = BASE_DIR / 'ml' / 'models' / 'label_mapping.json'
ALERTS_FILE = BASE_DIR / 'alerts.json'

print("📡 Starting live capture (interface: any)...")
print("⚠️ Uses simplified packet features - for production use CICFlowMeter")
print("Press Ctrl+C to stop")
print(f"📈 Alerts → {ALERTS_FILE} → http://localhost:5001/dashboard")

# Load model
model = joblib.load(MODEL_PATH)
with open(LABEL_PATH) as f:
    label_map = json.load(f)
reverse_label_map = {v: k for k, v in label_map.items()}

def extract_features(packet):
    """Simplified packet → feature vector (padded to 78 for model)"""
    features = np.zeros(78)
    
    if IP in packet:
        features[0] = len(packet)  # packet_len
        features[1] = packet[IP].proto  # protocol
        
        if TCP in packet:
            features[2] = packet[TCP].sport
            features[3] = packet[TCP].dport
        elif UDP in packet:
            features[2] = packet[UDP].sport
            features[3] = packet[UDP].dport
            
    return features

def packet_callback(packet):
    try:
        features = extract_features(packet)
        pred = model.predict([features])[0]
        
        if pred != 0:  # BENIGN=0
            alert = {
                "time": time.time(),
                "predicted_label": reverse_label_map[pred],
                "src_ip": packet[IP].src if IP in packet else "unknown",
                "dst_ip": packet[IP].dst if IP in packet else "unknown",
                "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER",
                "note": "live_packet_demo"
            }
            ALERTS_FILE.parent.mkdir(exist_ok=True)
            with open(ALERTS_FILE, 'a') as f:
                f.write(json.dumps(alert) + '\n')
            print(f"🚨 LIVE ALERT: {alert['predicted_label']} from {alert['src_ip']}")
            
    except Exception as e:
        pass  # Silent fail on bad packets

# Start sniffing
sniff(prn=packet_callback, store=0, filter="tcp or udp")

