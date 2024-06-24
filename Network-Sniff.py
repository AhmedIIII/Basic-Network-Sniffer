from scapy.all import sniff, TCP, IP
import pyshark

# Callback function to process captured packets using Scapy
def packet_callback(packet):
    if TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        print(f"Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
        detailed_packet_analysis(packet)

# Function to analyze packet using Pyshark
def detailed_packet_analysis(packet):
    try:
        raw_packet = bytes(packet)
        pyshark_packet = pyshark.packet.packet.Packet(raw_packet, raw_mode=True)
        
        # Print detailed information from Pyshark
        print("Detailed Packet Analysis:")
        for layer in pyshark_packet.layers:
            print(layer)
    except Exception as e:
        print(f"Error analyzing packet with Pyshark: {e}")

if __name__ == "__main__":
    # Start sniffing on the network interface
    sniff(filter="tcp", prn=packet_callback, count=10)
