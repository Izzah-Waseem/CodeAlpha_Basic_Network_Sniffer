from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP, Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP, Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
        
        if packet.haslayer(Raw):
            raw_layer = packet[Raw]
            print(f"Payload: {raw_layer.load}")
    else:
        print("Non-IP Packet")

print("Starting network sniffer...")
sniff(prn=packet_callback, count=10)
