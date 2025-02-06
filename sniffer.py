import signal
import sys
import os
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

captured_packets = []

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source: {ip_layer.src}, Destination: {ip_layer.dst}")
        captured_packets.append(packet)

    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}")

    if UDP in packet:
        udp_layer = packet[UDP]
        print(f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}")

def generate_report():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"packet_report_{timestamp}.txt"
    with open(report_filename, 'w') as file:
        for packet in captured_packets:
            if IP in packet:
                ip_layer = packet[IP]
                file.write(f"Source: {ip_layer.src}, Destination: {ip_layer.dst}\n")
            if TCP in packet:
                tcp_layer = packet[TCP]
                file.write(f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}\n")
            if UDP in packet:
                udp_layer = packet[UDP]
                file.write(f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}\n")
    print(f"\n[+] Report generated: {report_filename}")

def signal_handler(sig, frame):
    print("\n[!] Stopping the network sniffer...")
    generate_report()
    sys.exit(0)

if __name__ == "__main__":
    filter_opt = input("Enter a filter (e.g., 'tcp', 'udp', 'ip', or leave empty for no filter): ").strip()
    signal.signal(signal.SIGINT, signal_handler)

    print("Starting the network sniffer...")
    sniff(prn=packet_callback, store=False, filter=filter_opt)
