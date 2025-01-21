from scapy.all import sniff, IP, TCP, UDP  

def packet_callback(packet):  
    # Check if the packet has an IP layer  
    if IP in packet:  
        ip_layer = packet[IP]  
        print(f"Source: {ip_layer.src}, Destination: {ip_layer.dst}")  

    # Check if the packet has a TCP layer  
    if TCP in packet:  
        tcp_layer = packet[TCP]  
        print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")  

    # Check if the packet has a UDP layer  
    if UDP in packet:  
        udp_layer = packet[UDP]  
        print(f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")  

# Start sniffing packets. You can specify the count and the filter if needed.  
print("Starting the network sniffer...")  
sniff(prn=packet_callback, store=False)
