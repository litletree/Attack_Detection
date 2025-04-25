def determine_state(packets, protocol):
    if not isinstance(packets, list):
        packets = [packets]
        
    # Giao thức TCP
    if protocol == 'TCP':
        syn, syn_ack, ack, fin, rst, data_transmitted = False, False, False, False, False, False

        for packet in packets:
            if hasattr(packet, 'tcp'):
                # Kiểm tra cờ TCP
                if hasattr(packet.tcp, 'flags_syn') and packet.tcp.flags_syn:
                    syn = True
                if hasattr(packet.tcp, 'flags_ack') and packet.tcp.flags_ack:
                    ack = True
                if hasattr(packet.tcp, 'flags_syn') and hasattr(packet.tcp, 'flags_ack'):
                    if packet.tcp.flags_syn and packet.tcp.flags_ack:
                        syn_ack = True
                if hasattr(packet.tcp, 'flags_fin') and packet.tcp.flags_fin:
                    fin = True
                if hasattr(packet.tcp, 'flags_rst') and packet.tcp.flags_rst:
                    rst = True
                if hasattr(packet.tcp, 'len') and int(packet.tcp.len) > 0:  # Dữ liệu truyền tải
                    data_transmitted = True

        # Xác định trạng thái
        if syn and syn_ack and ack:
            if fin:
                return 'FIN'  # Kết thúc thành công
            if data_transmitted:
                return 'ACC'  # Flow đang truyền dữ liệu
            return 'CON'  # Kết nối thiết lập thành công
        if rst:
            return 'RST'  # Bị đặt lại
        if fin:
            return 'CLO'  # Kết thúc không rõ lý do
        return 'INT'  # Trạng thái không xác định

    # Giao thức UDP
    elif protocol == 'UDP':
        request, response = False, False
        for packet in packets:
        # UDP không có trạng thái như TCP -> phân tích thêm tầng ứng dụng
            if hasattr(packet, 'dns'):
                if hasattr(packet.dns, 'qry_name') and packet.dns.qry_name:
                    request = True
                if hasattr(packet.dns, 'flags_response') and packet.dns.flags_response:
                    response = True
        # Xác định trạng thái
        if request:             
            if response: 
                return "CON"  # DNS Response 
            return "REQ" # DNS Query
        return "INT" # Internal UDP Packet

    # Giao thức ICMP
    elif protocol == 'ICMP':
        for packet in packets:
            if hasattr(packet, 'icmp'):
                icmp_type = int(packet.icmp.type)

                # Echo Request
                if icmp_type == 8:
                    return 'REQ'
                # Echo Reply
                elif icmp_type == 0:
                    return 'ECO'
                elif packet.icmp.type == "3":
                    return "URH"  # Unreachable Host
                elif packet.icmp.type == "5":
                    return "PAR"  # Parameter Problem
                # Timestamp Request
                elif icmp_type == 13 or icmp_type == 11:
                    return 'TST'
                # Timestamp Reply
                elif icmp_type == 14:
                    return 'ECR'
        return 'INT'  # Trạng thái không xác định cho ICMP

    # Các giao thức khác
    else:
        return 'INT'  # Mặc định là 'INT' cho giao thức không xác định
