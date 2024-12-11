import joblib
import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import tkinter as tk
from tkinter import ttk
from threading import Thread

# Đường dẫn đến mô hình đã huấn luyện
MODEL_PATH = r"C:\\Model\\joblib\\attack_detection_model.pkl"

# Tải mô hình
try:
    model = joblib.load(MODEL_PATH)
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    exit()

# Tên các cột đặc trưng khi mô hình được huấn luyện
MODEL_FEATURES = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts', 'sbytes', 'dbytes',
    'rate', 'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss', 'sinpkt', 'dinpkt',
    'sjit', 'djit', 'swin', 'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
    'smean', 'dmean', 'trans_depth', 'response_body_len', 'ct_srv_src', 'ct_state_ttl',
    'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login',
    'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

# Bản đồ mã hóa cho cột 'service'
SERVICE_ENCODING = {
    'http': 1,
    'ftp': 2,
    'dns': 3,
    'ssh': 4,
    'other': 5
}

# Bản đồ loại tấn công từ mô hình
ATTACK_MAPPING = {
    0: "Normal",
    1: "Fuzzer",
    2: "Analysis",
    3: "Backdoor",
    4: "DoS",
    5: "Exploits",
    6: "Generic",
    7: "Reconnaissance",
    8: "Shellcode",
    9: "Worms"
}

# Hàm chuyển đổi gói tin thành DataFrame
def packet_to_dataframe(packet):
    try:
        proto = packet[IP].proto if IP in packet else None
        service_raw = "http" if TCP in packet and packet[TCP].dport == 80 else "other"
        service = SERVICE_ENCODING.get(service_raw, 5)
        return pd.DataFrame([{
            'dur': 0,
            'proto': proto,
            'service': service,
            'state': 0,
            'spkts': 1,
            'dpkts': 1,
            'sbytes': len(packet),
            'dbytes': len(packet),
            'rate': 0.0,
            'sttl': packet[IP].ttl if IP in packet else 0,
            'dttl': 0,
            'sload': 0.0,
            'dload': 0.0,
            'sloss': 0,
            'dloss': 0,
            'sinpkt': 0.0,
            'dinpkt': 0.0,
            'sjit': 0.0,
            'djit': 0.0,
            'swin': 0,
            'stcpb': 0,
            'dtcpb': 0,
            'dwin': 0,
            'tcprtt': 0.0,
            'synack': 0.0,
            'ackdat': 0.0,
            'smean': 0,
            'dmean': 0,
            'trans_depth': 0,
            'response_body_len': 0,
            'ct_srv_src': 0,
            'ct_state_ttl': 0,
            'ct_dst_ltm': 0,
            'ct_src_dport_ltm': 0,
            'ct_dst_sport_ltm': 0,
            'ct_dst_src_ltm': 0,
            'is_ftp_login': 0,
            'ct_ftp_cmd': 0,
            'ct_flw_http_mthd': 0,
            'ct_src_ltm': 0,
            'ct_srv_dst': 0,
            'is_sm_ips_ports': 0
        }])
    except Exception as e:
        print(f"Error processing packet: {e}")
        return pd.DataFrame()

# Hàm dự đoán từ gói tin
def predict_attack(packet):
    data = packet_to_dataframe(packet)
    if not data.empty:
        data = data.reindex(columns=MODEL_FEATURES, fill_value=0)
        prediction = model.predict(data)
        attack_type = ATTACK_MAPPING.get(prediction[0], "normal")
        update_gui(f"Prediction: {attack_type}")
    else:
        update_gui("Packet data could not be processed.")

# Hàm cập nhật giao diện
def update_gui(message):
    log_box.insert(tk.END, message + "\n")
    log_box.see(tk.END)

# Hàm xóa log
def clear_log():
    log_box.delete(1.0, tk.END)

# Hàm lắng nghe gói tin
def start_sniffing():
    global sniffing
    sniffing = True
    update_gui("Listening for packets... Press Stop to halt.")
    sniff(prn=predict_attack, filter="ip", store=0, stop_filter=lambda x: not sniffing)

# Hàm dừng lắng nghe gói tin
def stop_sniffing():
    global sniffing
    sniffing = False
    update_gui("Sniffing stopped.")

# Khởi tạo giao diện
root = tk.Tk()
root.title("Network Attack Detection")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

log_label = ttk.Label(frame, text="Log:")
log_label.grid(row=0, column=0, sticky=tk.W)

log_box = tk.Text(frame, width=80, height=20)
log_box.grid(row=1, column=0, pady=5)

start_button = ttk.Button(frame, text="Start Sniffing", command=lambda: Thread(target=start_sniffing, daemon=True).start())
start_button.grid(row=2, column=0, pady=5, sticky=tk.W)

stop_button = ttk.Button(frame, text="Stop Sniffing", command=stop_sniffing)
stop_button.grid(row=2, column=0, pady=5)

clear_button = ttk.Button(frame, text="Clear Log", command=clear_log)
clear_button.grid(row=2, column=0, pady=5, sticky=tk.E)

root.mainloop()