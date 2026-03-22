from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import os
import subprocess
import json

app = Flask(__name__)
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)



# 🔹 API: Get alerts
@app.route('/api/alerts')
def get_alerts():
    alerts = []
    if os.path.exists('alerts.json'):
        with open('alerts.json', 'r') as f:
            for line in f:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    continue

    alerts = alerts[-200:]  # limit
    return jsonify(alerts[::-1])

# 🔹 Upload CSV
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    return jsonify({"message": "File uploaded", "path": file_path})

# 🔹 Run detection
@app.route('/run', methods=['POST'])
def run_detection():
    print("Received /run request")
    data = request.get_json()
    if data is None:
        print("No JSON data received")
        return jsonify({"error": "Invalid JSON - expected application/json"}), 400
    
    file_path = data.get("file_path")
    print(f"Received file_path: '{file_path}'")
    
    if not file_path:
        print("Missing file_path")
        return jsonify({"error": "Missing 'file_path' in request body"}), 400

    # Ensure absolute path
    if not os.path.isabs(file_path):
        file_path = os.path.join(os.getcwd(), file_path)
        print(f"Converted to absolute: {file_path}")

    print(f"Checking if exists: {file_path}")
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return jsonify({"error": f"File does not exist: {file_path}"}), 400

    print(f"Starting prediction subprocess for {file_path}")

    # clear old alerts
    open('alerts.json', 'w').close()

    subprocess.Popen(["python3", "predict_with_alerts.py", file_path])
    return jsonify({"message": "Detection started"})

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    return response

@app.route('/', methods=['OPTIONS'])
def preflight():
    return '', 200

if __name__ == '__main__':
    app.run(debug=True, port=5001)
