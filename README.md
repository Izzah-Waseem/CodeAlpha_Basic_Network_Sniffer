# CodeAlpha_Basic_Network_Sniffer
  A network sniffer in Python that captures and analyzes network traffic. This project helps us understand how data flows on a network and how network packets are structured.

**1. Importing Required Libraries**

    from scapy.all import sniff
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.http import Raw


**scapy.all:** Imports all essential modules from Scapy, a powerful Python library for network packet manipulation and analysis.
**scapy.layers.inet:** Imports IP, TCP, and UDP layers to handle IP, TCP, and UDP packets, respectively.
**scapy.layers.http:** Imports the Raw layer to access the payload data in packets.

**2. Defining the Packet Callback Function**

    def packet_callback(packet):
        if IP in packet:
            ip_layer = packet[IP]
            print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")


**packet_callback(packet):** This function is called for each packet captured by the sniffer.
**if IP in packet:** Checks if the packet contains an IP layer.
**ip_layer = packet[IP]:** Extracts the IP layer from the packet.
**print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}"):** Prints the source and destination IP addresses of the packet.

**3. Handling TCP and UDP Packets**

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP, Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
        
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP, Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")


**if TCP in packet:** Checks if the packet contains a TCP layer.
**tcp_layer = packet[TCP]:** Extracts the TCP layer from the packet.
**print(f"Protocol: TCP, Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}"):** Prints the TCP source and destination ports.

**elif UDP in packet:** Checks if the packet contains a UDP layer.
**udp_layer = packet[UDP]:** Extracts the UDP layer from the packet.
**print(f"Protocol: UDP, Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}"):** Prints the UDP source and destination ports.

**4. Handling the Payload**

        if packet.haslayer(Raw):
            raw_layer = packet[Raw]
            print(f"Payload: {raw_layer.load}")
    else:
        print("Non-IP Packet")


**if packet.haslayer(Raw):** Checks if the packet contains a Raw layer, which holds the payload data.
**raw_layer = packet[Raw]:** Extracts the Raw layer from the packet.
**print(f"Payload:** {raw_layer.load}"): Prints the payload data in the packet.
**else:** Handles non-IP packets by printing a message.

**5. Starting the Sniffer**

    print("Starting network sniffer...")
    sniff(prn=packet_callback, count=10)


**print("Starting network sniffer..."):** Prints a message indicating that the sniffer is starting.
**sniff(prn=packet_callback, count=10):** Starts the sniffer with the following parameters:
**prn=packet_callback:** Specifies the callback function to call for each captured packet.
**count=10:** Captures 10 packets before stopping.
=packet_callback, count=10)

**Summary**
This simple network sniffer captures and analyzes network traffic. It uses Scapy to capture packets and a callback function to inspect and print details about each packet. The sniffer handles IP, TCP, UDP, and Raw layers to provide information about the source, destination, protocol, and payload. The sniffer is set to capture 10 packets before stopping.
