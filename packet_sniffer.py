# packet_sniffer.py

from scapy.all import sniff, wrpcap
from collections import Counter
from datetime import datetime
import matplotlib.pyplot as plt

# Store captured packets
captured_packets = []
protocol_counter = Counter()

# Callback function for each sniffed packet
def packet_callback(packet):
    captured_packets.append(packet)
    proto = packet.summary().split()[0]
    protocol_counter[proto] += 1
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {packet.summary()}")

def capture_packets(interface, packet_count):
    print(f"[+] Sniffing on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, count=packet_count, store=True)

def save_packets(filename="captured_packets.pcap"):
    wrpcap(filename, captured_packets)
    print(f"[+] Packets saved to: {filename}")

def plot_summary(output_image="packet_summary.png"):
    if not protocol_counter:
        print("[!] No packets captured to visualize.")
        return

    labels = list(protocol_counter.keys())
    counts = list(protocol_counter.values())

    plt.figure(figsize=(10, 6))
    plt.bar(labels, counts, color='skyblue')
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Number of Packets")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_image)
    print(f"[+] Packet summary saved as: {output_image}")

def main():
    interface = input("Enter interface (e.g., eth0, Wi-Fi): ").strip()
    packet_count = int(input("Enter number of packets to capture: "))
    
    capture_packets(interface, packet_count)
    save_packets()
    plot_summary()

if __name__ == "__main__":
    main()
