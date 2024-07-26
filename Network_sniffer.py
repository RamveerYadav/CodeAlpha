from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if protocol == 6:  # TCP
            protocol_name = "TCP"
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
        elif protocol == 17:  # UDP
            protocol_name = "UDP"
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
        else:
            protocol_name = "Other"
            src_port = dst_port = "N/A"

        print(f"{protocol_name} Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
    else:
        print("Non-IP Packet")

# Sniffing on the default interface
sniff(prn=packet_callback, store=0)
