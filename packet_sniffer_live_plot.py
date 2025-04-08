# packet_sniffer_live_plot.py

from scapy.all import sniff, wrpcap
from collections import Counter
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from datetime import datetime

# Configuration
captured_packets = []
protocol_counter = Counter()
packet_limit = 30  # Number of packets to capture
interface = input("Enter network interface (e.g., Wi-Fi, eth0): ").strip()

# Callback for each packet
def packet_callback(packet):
    captured_packets.append(packet)
    proto = packet.summary().split()[0]
    protocol_counter[proto] += 1
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {packet.summary()}")

# Sniff packets in background
def start_sniffing():
    print(f"[+] Sniffing {packet_limit} packets on {interface}...")
    sniff(iface=interface, prn=packet_callback, count=packet_limit, store=True)
    print("[+] Capture complete.")
    wrpcap("captured_packets.pcap", captured_packets)
    print("[+] Packets saved to captured_packets.pcap")

# Plotting setup
fig, ax = plt.subplots()
bars = None

def animate(i):
    global bars
    ax.clear()
    if protocol_counter:
        labels = list(protocol_counter.keys())
        counts = list(protocol_counter.values())
        bars = ax.bar(labels, counts, color='skyblue')
        ax.set_title("Live Protocol Distribution")
        ax.set_ylabel("Packet Count")
        ax.set_xlabel("Protocol")
        plt.xticks(rotation=45)
        plt.tight_layout()

# Start sniffing in a separate thread
import threading
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

# Live plot
ani = animation.FuncAnimation(fig, animate, interval=1000)
plt.show()

# Wait for sniffing to finish before exiting
sniff_thread.join()

# Save final chart
def save_final_chart():
    labels = list(protocol_counter.keys())
    counts = list(protocol_counter.values())
    plt.figure(figsize=(10, 6))
    plt.bar(labels, counts, color='lightgreen')
    plt.title("Final Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig("final_packet_summary.png")
    print("[+] Final protocol chart saved as final_packet_summary.png")

save_final_chart()
