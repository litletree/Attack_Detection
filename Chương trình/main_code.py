import pyshark
import csv
from collections import defaultdict
from determine_state import determine_state
from determine_tcp import analyze_tcp

# Hàm phân tích các gói tin và tính toán các trường 
def analyze_packets(capture):
    # Định nghĩa các trường cho 1 flow
    flows = defaultdict(lambda: {
        "timestamps": [],  # timestamps là list
        "flow_packets": [], #flow_packets là list
        'ttl_set': set(), #ttl_set là list
        
        'srcip': None, 'sport': None, 
        'dstip': None, 'dsport': None, 
        'proto': 0,
        'service': 0,
        'state': 0,
        'stream_id': 0,
        'rate': 0,

        'dur': 0, # Float
        'stime': 0, 'ltime': 0,
        'sbytes': 0, 'dbytes': 0, 
        'spkts': 0, 'dpkts': 0,
        'sttl': 0, 'dttl': 0, 
        'sloss': 0, 'dloss': 0, 
        'sload': 0, 'dload': 0, # Float
        'sinpkt': 0, 'dinpkt': 0, # Float
        'sjit': 0, 'djit': 0, # Float
        'swin': 0, 'dwin': 0, 
        'stcpb': 0, 'dtcpb': 0, 
        'smeansz': 0, 'dmeansz': 0,

        'trans_depth': 0, 
        'res_bdy_len': 0, 
        'ct_flw_http_mthd': 0, 

        'tcprtt': 0, 'synack': 0, 'ackdat': 0, # Float

        'is_ftp_login': 0, # Binary
        'ct_ftp_cmd': 0, 

        'ct_state_ttl': 0, 
        
        'is_sm_ips_ports': 0, # Binary
        'ct_srv_src': 0, 'ct_srv_dst': 0, 
        'ct_dst_ltm': 0, 'ct_src_ltm': 0, 
        'ct_src_dport_ltm': 0, 'ct_dst_sport_ltm': 0, 
        'ct_dst_src_ltm': 0
    })  # Lưu trữ thông tin flows

    for packet in capture:
        try:
            # Lấy thông tin cơ bản
            # IP
            if 'ARP' in packet:
                # Gói tin ARP
                src_ip = packet.arp.src_proto_ipv4  # Sender IP address
                dst_ip = packet.arp.dst_proto_ipv4  # Target IP address
            else:
                # Gói tin bình thường
                src_ip = packet.ip.src 
                dst_ip = packet.ip.dst

            # PORT, PROTOCOL, SERVICE
            if hasattr(packet, 'transport_layer') and packet.transport_layer:
                proto = packet.transport_layer
                if hasattr(packet, 'highest_layer') and packet.highest_layer != packet.transport_layer: 
                    service = packet.highest_layer 
                else: 
                    service = '-'
                sport = packet[packet.transport_layer].srcport 
                dport = packet[packet.transport_layer].dstport
            else:
                proto = packet.highest_layer
                service = '-'
                sport = 0
                dport = 0

            # TIME TO LIVE
            if hasattr(packet, 'ip') and packet.ip.ttl:
                sttl = packet.ip.ttl
            else:
                sttl = 0

            # Kiểm tra retransmission và duplicate ACKs, swin, dwin, stcpb, dtcpb, tcprtt, synack, ackdat đối với gói tin TCP
            retransmissions = False 
            duplicate_acks = False
            swin = stcpb = 0
            if 'tcp' in packet:
                # Kiểm tra giá trị retransmission và duplicate ACKs
                if 'analysis' in packet.tcp.field_names:
                    if 'retransmission' in packet.tcp.analysis.field_names:
                        retransmissions = True 
                    elif 'duplicate_ack' in packet.tcp.analysis.field_names:
                        duplicate_acks = True  
                
                # Lấy giá trị sequece number 
                if 'flags' in packet.tcp.field_names:
                    if packet.tcp.flags_syn == 1:
                        stcpb = int(packet.tcp.seq)

                # Lấy giá trị TCP window size
                swin = int(packet.tcp.window_size_value)

            # Kiểm tra gói tin FTP
            is_ftp_login = 0
            ct_ftp_cmd = 0
            if 'ftp' in packet:
                # Xác định đăng nhập FTP thành công (mã phản hồi 230)
                if hasattr(packet.ftp, 'response_code') and packet.ftp.response_code == '230':
                    is_ftp_login = 1
                
                # Đếm lệnh FTP
                if hasattr(packet.ftp, 'request_command'):
                    ct_ftp_cmd = 1
            
            # Kiểm tra gói tin HTTP
            fct_flw_http_mthd = 0
            trans_depth = 0
            res_bdy_len = 0
            if 'HTTP' in packet:
                if hasattr(packet.http, 'request_method'):  # HTTP request
                    fct_flw_http_mthd = 1
                    trans_depth = 1
                if hasattr(packet.http, 'response_code'):  # HTTP response
                    trans_depth = max(flow['trans_depth'] - 1, 0)
                    if hasattr(packet.http, 'content_length'):
                        res_bdy_len = int(packet.http.content_length)

            # Truy xuất stream_id
            stream_id = -1
            if "TCP" in packet and hasattr(packet.tcp, "stream"):
                stream_id = int(packet.tcp.stream)

            # Key định danh flow            
            flow_key = (src_ip, sport, dst_ip, dport, proto)
                
            # Cập nhật thông tin flow
            flows[flow_key]['srcip'] = src_ip
            flows[flow_key]['dstip'] = dst_ip

            flows[flow_key]['sport'] = sport
            flows[flow_key]['dsport'] = dport

            flows[flow_key]['proto'] = proto

            flows[flow_key]['stream_id'] = stream_id

            flows[flow_key]['service'] = service

            flows[flow_key]['spkts'] += 1
            flows[flow_key]['dpkts'] = 0

            flows[flow_key]['sbytes'] += int(packet.length)
            flows[flow_key]['dbytes'] = 0

            flows[flow_key]['stime'] = float(packet.sniff_timestamp) if 'stime' not in flows[flow_key] or flows[flow_key]['stime'] == 0 else flows[flow_key]['stime']
            flows[flow_key]['ltime'] = float(packet.sniff_timestamp)  # Ghi đè thời gian cuối

            flows[flow_key]['sttl'] = int(sttl)
            flows[flow_key]['dttl'] = 0
            if sttl != 0: flows[flow_key]['ttl_set'].add(sttl)

            if retransmissions or duplicate_acks: flows[flow_key]['sloss'] += 1 
            flows[flow_key]['dloss'] = 0
            
            flows[flow_key]['swin'] = swin if flows[flow_key]['swin'] == 0 else flows[flow_key]['swin']
            flows[flow_key]['dwin'] = 0

            flows[flow_key]['stcpb'] = stcpb if flows[flow_key]['stcpb'] == 0 else flows[flow_key]['stcpb']
            flows[flow_key]['dtcpb'] = 0

            # Cập nhật đặc trưng FTP
            flows[flow_key]['is_ftp_login'] = is_ftp_login if flows[flow_key]['is_ftp_login'] == 0 else flows[flow_key]['is_ftp_login'] # Ghi nhận đăng nhập thành công
            flows[flow_key]['ct_ftp_cmd'] += ct_ftp_cmd  # Đếm số lệnh FTP

            # Lưu thời gian bắt gói tin cho từng luồng
            flows[flow_key]['timestamps'].append(float(packet.sniff_timestamp))

            # Thêm packet vào trong flow_packets để xét state
            flows[flow_key]['flow_packets'].append(packet)

            flows[flow_key]['is_sm_ips_ports'] = 1 if src_ip == dst_ip and sport == dport else 0

            # Cập nhật đặc trưng HTTP
            flows[flow_key]['ct_flw_http_mthd'] += fct_flw_http_mthd
            flows[flow_key]['trans_depth'] += trans_depth
            flows[flow_key]['res_bdy_len'] += res_bdy_len

        except AttributeError:
            # Bỏ qua gói tin không hợp lệ
            continue

    # Hàm hoán đổi chiều của flow_key
    def reverse_flow_key(flow_key):
        src_ip, sport, dst_ip, dport, proto = flow_key  # Tách các thành phần
        return (dst_ip, dport, src_ip, sport, proto)
    
    # Tạo danh sách các flow_key cần xóa để tránh lỗi khi xóa trong quá trình duyệt
    to_remove_keys = []

    # Tính toán các trường bổ sung cho mỗi flow
    streams = analyze_tcp(capture)
    for key, flow in flows.items():
        flow['dur'] = flow['ltime'] - flow['stime']
        if flow['proto'] == 'TCP':
            flow['sload'] = flow['sbytes'] * 8 / flow['dur'] if flow['dur'] > 0 else 0
        else: flow['sload'] = (flow['sbytes'] * 8) / (flow['dur'] * 2) if flow['dur'] > 0 else 0
        flow['dload'] = 0
        flow['smeansz'] = flow['sbytes'] // flow['spkts'] if flow['spkts'] > 0 else 0
        flow['dmeansz'] = 0

        flow['ct_state_ttl'] = len(flow['ttl_set'])

        # Tính Sintpkt và Sjit sau khi xử lý tất cả gói tin
        timestamps = sorted(flow['timestamps'])
        interpacket_times = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        flow['sinpkt'] = (sum(interpacket_times) / len(interpacket_times) * 1000) if interpacket_times else 0
        flow['dinpkt'] = 0

        jitters = [abs(interpacket_times[i+1] - interpacket_times[i]) for i in range(len(interpacket_times) - 1)]
        flow['sjit'] = (sum(jitters) / len(jitters) * 1000) if jitters else 0
        flow['djit'] = 0

        flow['state'] = determine_state(flow['flow_packets'], flow['proto'])

        for stream_id, stream in streams.items():
            if(stream_id == flow['stream_id']):
                flow['synack'] = stream['synack']
                flow['ackdat'] = stream['ackdat']
                flow['tcprtt'] = stream['tcprtt']
                break

    # Cập nhật các giá trị từ phía đích
    for key, flow in flows.items():
        # Tìm flow chiều ngược lại
        if key not in to_remove_keys:
            reverse_key = reverse_flow_key(key)
            if reverse_key in flows:
                reverse_flow = flows[reverse_key]   
                flow['ltime'] = reverse_flow['ltime']
                flow['dbytes'] = reverse_flow['sbytes']
                flow['dpkts'] = reverse_flow['spkts']
                flow['dload'] = reverse_flow['sload']
                flow['dloss'] = reverse_flow['sloss']
                flow['dmeansz'] = reverse_flow['smeansz']
                flow['dttl'] = reverse_flow['sttl']  
                flow['dwin'] = reverse_flow['swin']  
                flow['dtcpb'] = reverse_flow['stcpb'] 
                flow['dinpkt'] = reverse_flow['sinpkt']
                flow['djit'] = reverse_flow['sjit']

                flow['dur'] = flow['ltime'] - flow['stime']
                flow['rate'] = (flow['spkts'] + flow['dpkts'] - 1) / flow['dur'] if flow['dur'] > 0 else 0
                # Đánh dấu flow chiều ngược lại để xóa
                to_remove_keys.append(reverse_key)
        else: continue

    # Xóa các flow chiều ngược lại đã xử lý
    for key in to_remove_keys:
        del flows[key]

    # Tính các trường kết nối bổ sung
    flow_count_window = 100  # Cửa sổ tối đa 100 flow gần nhất
    flow_keys = list(flows.keys())  # Danh sách các flow_key
    for i, key in enumerate(flow_keys):
        flow = flows[key]

        # Lấy cửa sổ các flow gần nhất
        window_keys = flow_keys[max(0, i - flow_count_window):i + 1]

        # Tính ct_srv_src: Số kết nối cùng dịch vụ và địa chỉ nguồn
        flow['ct_srv_src'] = sum(1 for k in window_keys if flows[k]['srcip'] == flow['srcip'] and flows[k]['service'] == flow['service'])

        # Tính ct_srv_dst: Số kết nối cùng dịch vụ và địa chỉ đích
        flow['ct_srv_dst'] = sum(1 for k in window_keys if flows[k]['dstip'] == flow['dstip'] and flows[k]['service'] == flow['service'])

        # Tính ct_dst_ltm: Số kết nối cùng địa chỉ đích
        flow['ct_dst_ltm'] = sum(1 for k in window_keys if flows[k]['dstip'] == flow['dstip'])

        # Tính ct_src_ltm: Số kết nối cùng địa chỉ nguồn
        flow['ct_src_ltm'] = sum(1 for k in window_keys if flows[k]['srcip'] == flow['srcip'])

        # Tính ct_src_dport_ltm: Số kết nối cùng địa chỉ nguồn và cổng đích
        flow['ct_src_dport_ltm'] = sum(1 for k in window_keys if flows[k]['srcip'] == flow['srcip'] and flows[k]['dsport'] == flow['dsport'])

        # Tính ct_dst_sport_ltm: Số kết nối cùng địa chỉ đích và cổng nguồn
        flow['ct_dst_sport_ltm'] = sum(1 for k in window_keys if flows[k]['dstip'] == flow['dstip'] and flows[k]['sport'] == flow['sport'])

        # Tính ct_dst_src_ltm: Số kết nối cùng địa chỉ nguồn và đích
        flow['ct_dst_src_ltm'] = sum(1 for k in window_keys if flows[k]['srcip'] == flow['srcip'] and flows[k]['dstip'] == flow['dstip'])

    # # Danh sách các trường cần trả về
    # required_fields = [
    #     'dur', 'proto', 'service', 'state', 'spkts', 'dpkts',
    #     'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sload', 'dload',
    #     'sloss', 'dloss', 'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin',
    #     'stcpb', 'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
    #     'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len', 'ct_srv_src',
    #     'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
    #     'ct_dst_src_ltm', 'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd',
    #     'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports'
    # ]

    # Bỏ flow vào result chỉ chứa các trường cần thiết
    results = []
    for key, flow in flows.items():
        results.append(flow)
    
    return results

# # Hàm xuất kết quả ra file CSV
# def export_to_csv(results, output_file):
#     # Định nghĩa các trường theo thứ tự yêu cầu
#     fields = [
#         'dur', 
#         'proto', 
#         'service', 
#         'state', 
#         'spkts', 'dpkts',
#         'sbytes', 'dbytes', 
#         'rate', 
#         'sttl', 'dttl', 
#         'sload', 'dload',
#         'sloss', 'dloss', 
#         'sinpkt', 'dinpkt', 
#         'sjit', 'djit',
#         'swin', 
#         'stcpb', 'dtcpb', 
#         'dwin', 
#         'tcprtt', 'synack', 'ackdat',
#         'smeansz', 'dmeansz', 
#         'trans_depth', 'res_bdy_len', 
#         'ct_srv_src',
#         'ct_state_ttl', 
#         'ct_dst_ltm', 
#         'ct_src_dport_ltm', 'ct_dst_sport_ltm',
#         'ct_dst_src_ltm', 
#         'is_ftp_login', 'ct_ftp_cmd', 
#         'ct_flw_http_mthd',
#         'ct_src_ltm', 
#         'ct_srv_dst', 
#         'is_sm_ips_ports'
#     ]

#     # Loại bỏ các field không cần thiết
#     fields_to_remove = [
#         'srcip', 'dstip', 'dsport', 'sport',
#         'stime', 'ltime', 'timestamps', 'flow_packets', 'stream_id', 'ttl_set'
#     ]

#     for flow in results:
#         for field in fields_to_remove:
#             if field in flow:
#                 del flow[field]

#     # Ghi dữ liệu ra file CSV
#     with open(output_file, mode='w', newline='') as file:
#         writer = csv.DictWriter(file, fieldnames=fields)
#         writer.writeheader()  # Ghi hàng đầu tiên là tên các trường
#         writer.writerows(results)  # Ghi từng flow vào file

# # Main
# if __name__ == "__main__":
    pcap_file = "fuzz-2006-06-26-2594.pcap"  # Đường dẫn đến file PCAP
    output_csv = "output.csv"    # Đường dẫn file CSV xuất ra

    # Phân tích file PCAP
    results = analyze_packets(pcap_file)

    # Xuất kết quả ra file CSV
    export_to_csv(results, output_csv)

    print(f"SUCCESS {output_csv}")
