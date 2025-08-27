from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        if packet.haslayer(TCP):
            protocol_name = 'TCP'
        elif packet.haslayer(UDP):
            protocol_name = 'UDP'
        elif packet.haslayer(ICMP):
            protocol_name = 'ICMP'
        else:
            protocol_name = 'Other'

        print(f"Packet: {src_ip} -> {dst_ip} (Protocol: {protocol_name})")

def main():
    print("Starting packet sniffer...")
    try:
        sniff(prn=packet_callback, store=0, count=10) 
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()