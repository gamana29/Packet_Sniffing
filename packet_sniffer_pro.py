import csv
import threading
from datetime import datetime
from collections import Counter, defaultdict
from scapy.all import sniff, wrpcap, get_if_list
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib import gridspec
import matplotlib.ticker as mticker

# ------------------ CONFIG ------------------
PACKET_LIMIT = 70
LIVE_GRAPH_INTERVAL = 100
TIMESTAMP = datetime.now().strftime('%Y%m%d_%H%M%S')
PCAP_FILE = f"packets_{TIMESTAMP}.pcap"
CSV_FILE = f"summary_{TIMESTAMP}.csv"
IMG_FILE = f"summary_{TIMESTAMP}.png"

# ------------------ GLOBALS ------------------
captured_packets = []
protocol_counter = Counter()
protocol_over_time = defaultdict(list)
packet_times = []
time_series = []

selected_protocol = None
ip_filter = None

# ------------------ CALLBACK ------------------
def packet_callback(packet):
    summary = packet.summary()
    proto = summary.split()[0]

    if selected_protocol and selected_protocol.upper() != proto.upper():
        return
    if ip_filter and ip_filter not in summary:
        return

    now = datetime.now()
    timestamp = now.strftime('%H:%M:%S')
    captured_packets.append(packet)
    protocol_counter[proto] += 1
    protocol_over_time[proto].append((timestamp, protocol_counter[proto]))
    packet_times.append(now)
    time_series.append((now, proto))

    print(f"[{timestamp}] {summary}")

# ------------------ INTERFACE ------------------
def choose_interface():
    interfaces = get_if_list()
    print("Available Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}. {iface}")
    while True:
        try:
            idx = int(input("Select interface by number: "))
            return interfaces[idx]
        except (ValueError, IndexError):
            print("Invalid selection, try again.")

# ------------------ VISUALS ------------------
fig = plt.figure(figsize=(18, 10))
gs = gridspec.GridSpec(2, 3)
ax1 = fig.add_subplot(gs[0, 0])  # Bar
ax2 = fig.add_subplot(gs[0, 1])  # Pie
ax3 = fig.add_subplot(gs[0, 2])  # Line
ax4 = fig.add_subplot(gs[1, 0])  # Table
ax5 = fig.add_subplot(gs[1, 1])  # Histogram
ax6 = fig.add_subplot(gs[1, 2])  # Stacked bar

latest_packet_count = 0

def animate(i):
    global latest_packet_count
    ax1.clear(), ax2.clear(), ax3.clear(), ax4.clear(), ax5.clear(), ax6.clear()

    labels = list(protocol_counter.keys())
    values = list(protocol_counter.values())
    latest_packet_count = sum(values)

    if not labels:
        ax1.set_title("Waiting for packets...", fontsize=14)
        ax2.text(0.5, 0.5, "Waiting...", ha='center', va='center', fontsize=14)
        ax3.set_title("Trend Over Time")
        ax4.axis('off')
        ax5.set_title("Packet Arrival Histogram")
        ax6.set_title("Stacked Protocol Timeline")
        return

    # Bar
    bars = ax1.bar(labels, values, color='mediumorchid')
    ax1.set_title("Protocol Counts - Bar")
    for bar in bars:
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height(), f'{bar.get_height()}', ha='center', va='bottom')
    ax1.set_ylabel("Count")
    ax1.set_xlabel("Protocol")

    # Pie
    ax2.pie(values, labels=labels, autopct='%1.1f%%', startangle=180)
    ax2.set_title("Protocol Distribution - Pie")

    # Line
    for proto, points in protocol_over_time.items():
        x = [p[0] for p in points]
        y = [p[1] for p in points]
        ax3.plot(x, y, marker='o', label=proto)
    ax3.set_title("Protocol Trend Over Time")
    ax3.legend()
    ax3.tick_params(axis='x', rotation=45)

    # Table
    ax4.axis('tight')
    ax4.axis('off')
    top_data = sorted(protocol_counter.items(), key=lambda x: x[1], reverse=True)
    table_data = [["Protocol", "Count"]] + top_data
    ax4.table(cellText=table_data, loc='center')
    ax4.set_title("Top Protocols")

    # Histogram
    if packet_times:
        intervals = [(packet_times[i] - packet_times[0]).total_seconds() for i in range(len(packet_times))]
        ax5.hist(intervals, bins=15, color='skyblue', edgecolor='black')
        ax5.set_title("Packet Arrival Histogram")
        ax5.set_xlabel("Seconds since start")
        ax5.set_ylabel("Frequency")

    # Stacked bar
    proto_time_dict = defaultdict(lambda: defaultdict(int))
    for t, proto in time_series:
        second = t.strftime('%H:%M:%S')
        proto_time_dict[second][proto] += 1
    times = sorted(proto_time_dict.keys())
    protos = list(protocol_counter.keys())
    bottom = [0]*len(times)
    for proto in protos:
        counts = [proto_time_dict[t][proto] for t in times]
        ax6.bar(times, counts, bottom=bottom, label=proto)
        bottom = [sum(x) for x in zip(bottom, counts)]
    ax6.set_title("Stacked Protocol Timeline")
    ax6.set_xticks(times[::max(1, len(times)//5)])
    ax6.tick_params(axis='x', rotation=45)
    ax6.legend()

    fig.suptitle(f"📦 Ultimate Packet Sniffer Dashboard — Total Packets: {latest_packet_count}", fontsize=16)
    fig.tight_layout(rect=[0, 0.03, 1, 0.95])

# ------------------ SAVE ------------------
def save_summary():
    if not protocol_counter:
        print("[!] No packets to save.")
        return

    wrpcap(PCAP_FILE, captured_packets)
    with open(CSV_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Protocol", "Count"])
        writer.writerows(protocol_counter.items())

    animate(0)
    plt.savefig(IMG_FILE)

    print(f"[✔] Saved: {PCAP_FILE}, {CSV_FILE}, {IMG_FILE}")

# ------------------ MAIN ------------------
def start_sniffing(interface):
    print(f"[🔎] Sniffing {PACKET_LIMIT} packets on: {interface}")
    sniff(iface=interface, prn=packet_callback, count=PACKET_LIMIT, store=True)
    print("[✅] Capture complete.")

def main():
    global selected_protocol, ip_filter

    iface = choose_interface()
    selected_protocol = input("Filter by protocol? (TCP/UDP/ICMP or blank): ").strip() or None
    ip_filter = input("Filter by IP address? (e.g., 192.168.1.1 or blank): ").strip() or None

    sniff_thread = threading.Thread(target=start_sniffing, args=(iface,))
    sniff_thread.start()

    ani = animation.FuncAnimation(fig, animate, interval=LIVE_GRAPH_INTERVAL)
    plt.show()

    sniff_thread.join()
    save_summary()
    print("[🏁] All tasks completed.")

if __name__ == "__main__":
    main()