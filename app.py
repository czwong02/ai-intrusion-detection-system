from flask import Flask, render_template, jsonify
import os
import joblib
import numpy as np
from scapy.all import *
import pcapy
import time

app = Flask(__name__)

# Load the trained AI model (No scaler)
model = joblib.load('rf_model.pkl')

# Simulate normal and malicious traffic
def generate_normal_traffic():
    send(IP(dst="192.168.1.1")/TCP(dport=80, flags="S"))

def generate_port_scan():
    for port in range(20, 1024):
        send(IP(dst="192.168.1.1")/TCP(dport=port, flags="S"))

# Capture live network traffic
def capture_packets():
    cap = pcapy.open_live("eth0", 65536, 1, 0)  # Change 'eth0' to your network interface
    while True:
        header, packet = cap.next()
        yield packet

# Preprocess packet for model prediction (Scaler removed)
def preprocess_packet(packet):
    ip_layer = IP(packet)
    tcp_layer = ip_layer.getlayer(TCP)
    # Directly use the raw features without scaling
    features = np.array([len(packet), ip_layer.ttl, tcp_layer.dport])
    return features.reshape(1, -1)

# Classify packets
def classify_packet(packet):
    features = preprocess_packet(packet)
    prediction = model.predict(features)
    return prediction

# Log malicious activities
def log_malicious_activity(packet):
    ip_layer = IP(packet)
    with open('intrusion_log.txt', 'a') as f:
        f.write(f"{time.ctime()} - Malicious: {ip_layer.src} -> {ip_layer.dst}\n")

# Route: Dashboard Page
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# Route: Traffic Simulation
@app.route('/simulate_traffic', methods=['POST'])
def simulate_traffic():
    generate_normal_traffic()
    generate_port_scan()
    return jsonify({'status': 'Traffic generated successfully!'})

# Route: Real-time Detection
@app.route('/start_detection', methods=['POST'])
def start_detection():
    detected_alerts = []
    for packet in capture_packets():
        prediction = classify_packet(packet)
        if prediction == 1:  # Malicious activity
            log_malicious_activity(packet)
            detected_alerts.append(f"Malicious packet detected!")
        if len(detected_alerts) > 10:  # Stop after 10 detections for demo
            break
    return jsonify(detected_alerts)

# Route: View Logs
@app.route('/view_logs', methods=['GET'])
def view_logs():
    alerts = []
    if os.path.exists('intrusion_log.txt'):
        with open('intrusion_log.txt', 'r') as f:
            alerts = f.readlines()
    return jsonify(alerts)

# Route: Generate Reports
@app.route('/generate_report', methods=['POST'])
def generate_report():
    report = {}
    if os.path.exists('intrusion_log.txt'):
        with open('intrusion_log.txt', 'r') as f:
            for line in f:
                date = line.split('-')[0].strip()
                if date not in report:
                    report[date] = 0
                report[date] += 1
    return jsonify(report)

if __name__ == '__main__':
    app.run(debug=True)
