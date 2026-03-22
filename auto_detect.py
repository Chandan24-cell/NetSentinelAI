#!/usr/bin/env python3
"""
Auto-Detect New CSV Files for IDS
Watches 'captures/' folder (where CICFlowMeter saves flows)
Auto-runs ml/predict_with_alerts.py on new CSVs
"""

import time
import os
import subprocess
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path

BASE_DIR = Path(__file__).parent
WATCH_FOLDER = BASE_DIR / 'captures'
ML_SCRIPT = BASE_DIR / 'ml' / 'predict_with_alerts.py'
ALERTS_FILE = BASE_DIR / 'alerts.json'

os.makedirs(WATCH_FOLDER, exist_ok=True)
print(f"👀 Watching {WATCH_FOLDER} for new CSV files...")
print(f"📈 Alerts will appear in {ALERTS_FILE}")
print("Press Ctrl+C to stop")

class CSVHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory or not event.src_path.endswith('.csv'):
            return
            
        print(f"📁 New CSV detected: {event.src_path}")
        time.sleep(1)  # Let file fully write
        
        if Path(event.src_path).exists():
            # Clear old alerts
            ALERTS_FILE.write_text('')
            
            # Run prediction
            cmd = ['python3', str(ML_SCRIPT), event.src_path]
            print(f"🔍 Running: {' '.join(cmd)}")
            
            proc = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                cwd=str(BASE_DIR)
            )
            
            stdout, stderr = proc.communicate()
            if stdout:
                print("STDOUT:", stdout.decode())
            if stderr:
                print("STDERR:", stderr.decode())
            
            print(f"✅ Analysis complete! Check dashboard: http://localhost:5001/dashboard")
        else:
            print(f"⚠️ CSV disappeared: {event.src_path}")

if __name__ == "__main__":
    event_handler = CSVHandler()
    observer = Observer()
    observer.schedule(event_handler, str(WATCH_FOLDER), recursive=False)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\n👋 Watcher stopped")
    observer.join()

