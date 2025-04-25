import pyshark
from collections import defaultdict

def analyze_tcp(capture):

    # Lưu thông tin từng stream
    streams = defaultdict(lambda: {
        'stream_id': 0,
        'proto': None,
        'syn_time': 0,
        'synack_time': 0,
        'ack_time': 0,
        'tcprtt': 0,
        'synack': 0,
        'ackdat': 0
    })

    for packet in capture:
        try:
            if 'TCP' in packet and hasattr(packet.tcp, 'stream'):
                # Lấy thông tin cơ bản
                id = int(packet.tcp.stream)
                proto = "TCP"

                # Lấy TCP flags
                tcp_flags = int(packet.tcp.flags, 16)

                # Lấy stream_id
                stream_key = id

                # Cập nhật thông tin stream
                streams[stream_key]['stream_id'] = id
                streams[stream_key]['proto'] = proto

                # Phân loại gói tin
                timestamp = float(packet.sniff_timestamp)

                # SYN packet
                if tcp_flags & 0x02 and not tcp_flags & 0x10:  # SYN but not ACK
                    streams[stream_key]['syn_time'] = timestamp

                # SYN-ACK packet
                if tcp_flags & 0x12:  # SYN + ACK
                    streams[stream_key]['synack_time'] = timestamp

                # ACK packet (completing 3-way handshake)
                if tcp_flags & 0x10 and not tcp_flags & 0x02:  # ACK but not SYN
                    streams[stream_key]['ack_time'] = timestamp

        except AttributeError:
            continue

    # Tính toán các giá trị thời gian
    for key, stream in streams.items():
        if stream['syn_time'] and stream['synack_time']:
            stream['synack'] = stream['synack_time'] - stream['syn_time']
        if stream['synack_time'] and stream['ack_time']:
            stream['ackdat'] = stream['ack_time'] - stream['synack_time']
        if stream['syn_time'] and stream['ack_time']:
            stream['tcprtt'] = stream['ack_time'] - stream['syn_time']

    return streams