import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.tls.all import TLS, TLSClientHello
import threading
import time
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
import socket
import subprocess
import logging
import random
from faker import Faker
from dnslib import *
import os
from math import log2

logging.basicConfig(filename='nemesis_log.txt', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Nemesis perfected. The ultimate beast is unleashed.")

traffic_history = []
threat_scores = {}
signatures = {}
signature_counter = 0
lock = threading.Lock()
fake = Faker()

def extract_features(packet):
    if IP in packet:
        src_ip = packet[IP].src
        timestamp = time.time()
        packet_size = len(packet)
        payload = packet.load if hasattr(packet, 'load') else b''
        entropy = calculate_entropy(payload)
        
        if TCP in packet:
            src_port, dst_port, flags = packet[TCP].sport, packet[TCP].dport, packet[TCP].flags
        elif UDP in packet:
            src_port, dst_port, flags = packet[UDP].sport, packet[UDP].dport, 0
        else:
            src_port, dst_port, flags = 0, 0, 0
        
        tls_version = 0
        suspicious_tls = False
        if TLS in packet and TLSClientHello in packet:
            tls_version = packet[TLSClientHello].version
            if hasattr(packet[TLSClientHello], 'ciphers'):
                weak_ciphers = {0x0004, 0x0005}
                suspicious_tls = any(c in weak_ciphers for c in packet[TLSClientHello].ciphers)
        
        return [src_ip, src_port, dst_port, packet_size, timestamp, flags, entropy, tls_version, suspicious_tls]
    return None

def calculate_entropy(payload):
    if not payload:
        return 0
    length = len(payload)
    freq = {}
    for byte in payload:
        freq[byte] = freq.get(byte, 0) + 1
    return -sum((f/length) * log2(f/length) for f in freq.values())

def build_lstm_model():
    model = Sequential([
        LSTM(64, input_shape=(10, 8), return_sequences=True),
        LSTM(32),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy')
    return model

def train_lstm(model):
    while True:
        try:
            time.sleep(120)
            with lock:
                if len(traffic_history) < 50:
                    continue
                data = np.array([x[1:-1] for x in traffic_history[-50:]])
                sequences = np.array([data[i:i+10] for i in range(len(data)-10)])
                labels = []
                for i in range(len(data)-10):
                    window = traffic_history[i+10-20:i+10]
                    syn_count = sum(1 for x in window if x[5] & 2)
                    avg_size = np.mean([x[3] for x in window])
                    avg_entropy = np.mean([x[6] for x in window])
                    threat = 1 if (syn_count > 5 or avg_size > 2000 or avg_entropy > 6) else 0
                    labels.append([threat])
                labels = np.array(labels)
                model.fit(sequences, labels, epochs=5, batch_size=8, verbose=0)
                logging.info("LSTM retrained with enhanced threat labels")
        except Exception as e:
            logging.error(f"LSTM training crashed: {e}")
            time.sleep(10)

def predict_threat(model, features):
    numeric_features = [x[1:-1] for x in features]
    seq = np.zeros((10, 8))
    start_idx = max(0, 10 - len(numeric_features))
    seq[start_idx:] = numeric_features[-10:] if len(numeric_features) >= 10 else numeric_features
    seq = seq.reshape(1, 10, 8)
    score = model.predict(seq, verbose=0)[0][0]
    return score > 0.7

def generate_signature(packet):
    global signature_counter
    if TCP in packet and packet[TCP].flags & 2:
        key = f"{packet[IP].src}:{packet[TCP].sport}"
        if key not in signatures:
            signatures[key] = {'count': 1, 'last_seen': time.time()}
        else:
            signatures[key]['count'] += 1
            signatures[key]['last_seen'] = time.time()
        
        signature_counter += 1
        if signature_counter % 30 == 0:
            current_time = time.time()
            expired = [k for k, v in signatures.items() if current_time - v['last_seen'] > 300]
            for k in expired:
                del signatures[k]
            logging.debug(f"Cleaned {len(expired)} expired signatures")
        
        if len(signatures) > 1000:
            oldest = min(signatures.items(), key=lambda x: x[1]['last_seen'])[0]
            del signatures[oldest]
        
        if signatures[key]['count'] > 20:
            return True, f"Zero-day SYN pattern from {key}"
    return False, ""

def deploy_dns_trap(ip):
    fake_domain = f"{fake.word()}-{random.randint(1000, 9999)}.nemesis-trap.com"
    pkt = IP(dst=ip)/UDP()/DNS(id=random.randint(0, 65535), qd=DNSQR(qname=fake_domain))
    try:
        scapy.send(pkt, verbose=0)
        logging.info(f"Deployed DNS trap to {ip}: {fake_domain} (awaiting response)")
    except Exception as e:
        logging.error(f"DNS trap failed for {ip}: {e}")

def tarpit(ip):
    for _ in range(3):
        tarpit_packet = IP(dst=ip)/TCP(sport=random.randint(1024, 65535), 
                                       dport=random.randint(1, 1023), 
                                       flags="SA", window=0)
        try:
            scapy.send(tarpit_packet, verbose=0)
            time.sleep(random.uniform(0.1, 0.5))
            logging.info(f"Tarpitted {ip} with randomized port and delay")
        except Exception as e:
            logging.error(f"Tarpit failed for {ip}: {e}")

def block_ip(ip):
    if ip not in threat_scores:
        if os.geteuid() != 0:
            logging.error(f"Root required to block {ip}. Logging only.")
            threat_scores[ip] = 999
        else:
            try:
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
                threat_scores[ip] = 0
                logging.warning(f"IP {ip} blocked with extreme prejudice")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to block {ip}: {e}")

def analyze_packet(packet, model):
    features = extract_features(packet)
    if not features:
        logging.debug("Skipping invalid packet")
        return
    
    src_ip = features[0]
    with lock:
        traffic_history.append(features)
        if len(traffic_history) > 1000:
            traffic_history.pop(0)
    
    if features[3] > 65535 or (features[5] & 2 and sum(1 for x in traffic_history[-20:] if x[0] == src_ip and x[5] & 2) > 10):
        threat_scores[src_ip] = threat_scores.get(src_ip, 0) + 50
        logging.warning(f"Rule-based threat from {src_ip}: Oversized or SYN flood")
    
    if features[7] and (features[7] < 0x0303 or features[8]):
        threat_scores[src_ip] = threat_scores.get(src_ip, 0) + 20
        logging.warning(f"Suspicious TLS from {src_ip}: version={hex(features[7])}, weak_ciphers={features[8]}")
    
    if predict_threat(model, traffic_history):
        threat_scores[src_ip] = threat_scores.get(src_ip, 0) + 30
        logging.warning(f"LSTM predicted threat from {src_ip}")
    
    is_zero_day, sig_reason = generate_signature(packet)
    if is_zero_day:
        threat_scores[src_ip] = threat_scores.get(src_ip, 0) + 40
        logging.warning(sig_reason)
    
    score = threat_scores.get(src_ip, 0)
    if score > 100:
        block_ip(src_ip)
        deploy_dns_trap(src_ip)
        tarpit(src_ip)
        del threat_scores[src_ip]
    
    if random.random() < 0.1:
        logging.info(f"Traffic from {src_ip}: size={features[3]}, entropy={features[6]}, TLS={features[7]}")

def watchdog(model):
    global train_thread
    while True:
        if not train_thread.is_alive():
            logging.warning("LSTM thread died. Restarting...")
            train_thread = threading.Thread(target=train_lstm, args=(model,), daemon=True)
            train_thread.start()
        time.sleep(30)

def start_nemesis(interface="eth0"):
    logging.info(f"Nemesis unleashed on {interface}. None shall stand against me.")
    model = build_lstm_model()
    
    global train_thread
    train_thread = threading.Thread(target=train_lstm, args=(model,), daemon=True)
    train_thread.start()
    
    watchdog_thread = threading.Thread(target=watchdog, args=(model,), daemon=True)
    watchdog_thread.start()
    
    try:
        scapy.sniff(iface=interface, prn=lambda p: analyze_packet(p, model), store=0)
    except Exception as e:
        logging.error(f"Nemesis faltered: {e}")

if __name__ == "__main__":
    interface = input("Enter interface (e.g., eth0): ") or "eth0"
    try:
        socket.if_nametoindex(interface)
        start_nemesis(interface)
    except OSError:
        print(f"Interface {interface} not found. Use 'ifconfig' or 'ip link'.")