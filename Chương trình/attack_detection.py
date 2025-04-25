import subprocess
import tkinter as tk
from tkinter import messagebox, filedialog
import pickle
import pyshark
import os
from main_code import analyze_packets
from mapping import protocol_to_int
from mapping import service_to_int
from mapping import state_to_int

# Đường dẫn đến TShark (đảm bảo bạn đã cài đặt TShark và thêm nó vào PATH)
TSHARK_CMD = "tshark"

# Mã ánh xạ kết quả dự đoán thành tên kiểu tấn công
ATTACK_TYPES = [
    'Analysis', 'Backdoor', 'DoS', 'Exploits', 'Fuzzers',
    'Generic', 'Normal', 'Reconnaissance', 'Worms'
]

# Hàm đọc mô hình đã lưu
def load_model(model_path):
    with open(model_path, 'rb') as file:
        return pickle.load(file)

# Hàm bắt gói tin từ TShark
def capture_packets(interface, packet_count):
    try:
        temp_pcap_file="temp_capture.pcap"
        # Bắt gói tin và lưu vào file .pcap tạm thời
        cmd = [TSHARK_CMD, "-i", interface, "-c", str(packet_count), "-w", temp_pcap_file]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"TShark error: {result.stderr}")

        # Đọc file .pcap và trả về danh sách gói tin
        packets = []
        cap = pyshark.FileCapture(temp_pcap_file, use_json=True, include_raw=True)
        for packet in cap:
            packets.append(packet)  # Thêm gói tin vào danh sách

        # Xóa file tạm sau khi đọc xong
        os.remove(temp_pcap_file)
        
        return packets 
    
    except Exception as e:
        messagebox.showerror("Lỗi", f"Lỗi khi bắt gói tin: {e}")
        return []

# Danh sách tên các đặc trưng
feature_names = [
    'dur', 'proto', 'service', 'state', 'spkts', 'dpkts',
    'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload',
    'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin',
    'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
    'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'ct_srv_src',
    'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
    'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd',
    'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
]

# Danh sách tên các đặc trưng
feature_names_result= [
    'dur', 'srcip', 'dstip', 'sport', 'dport', 'proto', 'service', 'state'
]


# Hàm dự đoán
def predict_attacks(features_list, model, feature_names):
    predictions = []
    for features in features_list:
        input_data = []
        for f in feature_names:
            if f == 'proto':
                input_data.append(protocol_to_int(features[f]))
            elif f == 'service':
                input_data.append(service_to_int(features[f]))
            elif f == 'state':
                input_data.append(state_to_int(features[f]))
            else: input_data.append(features[f])

        prediction = model.predict([input_data])[0]
        predictions.append(prediction)  # Ánh xạ số thành tên kiểu tấn công
    return predictions

# Hàm xử lý chính khi nhấn nút "Bắt gói tin và dự đoán"
def start_capture():
    interface = interface_entry.get()
    packet_count = int(packet_count_entry.get())
    model_path = model_path_entry.get()

    if not interface or not model_path:
        messagebox.showerror("Lỗi", "Vui lòng nhập giao diện mạng và đường dẫn mô hình.")
        return

    try:
        model = load_model(model_path)
    except Exception as e:
        messagebox.showerror("Lỗi", f"Lỗi khi tải mô hình: {e}")
        return

    packets = capture_packets(interface, packet_count)
    if not packets:
        return

    extracted_features = analyze_packets(packets)
    predictions = predict_attacks(extracted_features, model, feature_names)

    result_text.delete(1.0, tk.END)
    for i, (features, pred) in enumerate(zip(extracted_features, predictions)):
        result_text.insert(tk.END, f"Luồng dữ liệu {i+1}:\n")
        for feature_name in feature_names_result:
            value = features.get(feature_name, "Không có giá trị")
            result_text.insert(tk.END, f"  {feature_name}: {value}\n")
        result_text.insert(tk.END, f"  Dự đoán: {pred}\n")
        result_text.insert(tk.END, "-" * 50 + "\n")

# Hàm để chọn tệp mô hình
def browse_model():
    file_path = filedialog.askopenfilename(filetypes=[("Pickle files", "*.pkl")])
    model_path_entry.delete(0, tk.END)
    model_path_entry.insert(0, file_path)

# Tạo giao diện chính
root = tk.Tk()
root.title("Chương trình dự đoán kiểu tấn công từ gói tin")

# Nhập giao diện mạng
tk.Label(root, text="Giao diện mạng:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
interface_entry = tk.Entry(root)
interface_entry.grid(row=0, column=1, padx=10, pady=5)

# Nhập số lượng gói tin
tk.Label(root, text="Số lượng gói tin:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
packet_count_entry = tk.Entry(root)
packet_count_entry.grid(row=1, column=1, padx=10, pady=5)
packet_count_entry.insert(0, "10")

# Chọn mô hình
tk.Label(root, text="Đường dẫn mô hình:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
model_path_entry = tk.Entry(root, width=50)
model_path_entry.grid(row=2, column=1, padx=10, pady=5)
browse_button = tk.Button(root, text="Chọn tệp", command=browse_model)
browse_button.grid(row=2, column=2, padx=10, pady=5)

# Nút bắt đầu
start_button = tk.Button(root, text="Bắt gói tin và dự đoán", command=start_capture)
start_button.grid(row=3, column=0, columnspan=3, pady=10)

# Hiển thị kết quả
tk.Label(root, text="Kết quả:").grid(row=4, column=0, padx=10, pady=5, sticky="nw")
result_text = tk.Text(root, height=40, width=100)
result_text.grid(row=4, column=1, columnspan=2, padx=10, pady=5)

# Chạy ứng dụng
root.mainloop()
