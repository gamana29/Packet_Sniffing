# packet_sniffer_visualized.py

from scapy.all import sniff, wrpcap
from collections import Counter
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from datetime import datetime
import threading

# ----------- CONFIG ------------
PACKET_LIMIT = 100
LIVE_GRAPH_INTERVAL = 1000  # in milliseconds
OUTPUT_PCAP = "captured_packets.pcap"
COMBINED_CHART = "packet_summary.png"
# -------------------------------

captured_packets = []
protocol_counter = Counter()

# Callback to update counter and print packet summary
def packet_callback(packet):
    captured_packets.append(packet)
    proto = packet.summary().split()[0]
    protocol_counter[proto] += 1
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {packet.summary()}")

# Sniffing in background
def start_sniffing(interface):
    print(f"\n[+] Sniffing {PACKET_LIMIT} packets on: {interface}")
    sniff(iface=interface, prn=packet_callback, count=PACKET_LIMIT, store=True)
    print("[+] Capture complete.")
    wrpcap(OUTPUT_PCAP, captured_packets)
    print(f"[+] Packets saved to {OUTPUT_PCAP}")

# Live bar chart setup
fig, ax = plt.subplots()
def animate(i):
    ax.clear()
    if protocol_counter:
        labels = list(protocol_counter.keys())
        values = list(protocol_counter.values())
        bars = ax.bar(labels, values, color='teal', edgecolor='black')
        ax.set_title("🔴 Live Protocol Usage", fontsize=14)
        ax.set_ylabel("Packet Count")
        ax.set_xlabel("Protocol")
        ax.tick_params(axis='x', rotation=45)
        ax.grid(True, linestyle='--', alpha=0.4)
        for bar in bars:
            yval = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, yval + 0.5, yval, ha='center', va='bottom', fontsize=9)
        plt.tight_layout()

# Final combined chart with bar + pie
def save_combined_charts():
    if not protocol_counter:
        return
    labels = list(protocol_counter.keys())
    values = list(protocol_counter.values())

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Bar Chart
    bars = ax1.bar(labels, values, color='skyblue', edgecolor='black')
    ax1.set_title("Protocol Distribution - Bar Chart", fontsize=13)
    ax1.set_xlabel("Protocol")
    ax1.set_ylabel("Packet Count")
    ax1.tick_params(axis='x', rotation=45)
    ax1.grid(True, linestyle='--', alpha=0.4)
    for bar in bars:
        yval = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2, yval + 0.5, yval, ha='center', va='bottom', fontsize=9)

    # Pie Chart
    ax2.pie(values, labels=labels, autopct='%1.1f%%', startangle=140, colors=plt.cm.Paired.colors)
    ax2.set_title("Protocol Distribution - Pie Chart", fontsize=13)

    plt.tight_layout()
    plt.savefig(COMBINED_CHART)
    print(f"[+] Combined chart saved as {COMBINED_CHART}")

# Main function
def main():
    interface = input("Enter network interface (e.g., Wi-Fi, eth0): ").strip()

    # Start background sniffing
    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.start()

    # Show live graph
    ani = animation.FuncAnimation(fig, animate, interval=LIVE_GRAPH_INTERVAL)
    plt.show()

    # Wait for sniffing to finish before generating charts
    sniff_thread.join()
    save_combined_charts()
    print("\n[✅] Done! Charts and PCAP saved.")

if __name__ == "__main__":
    main()
