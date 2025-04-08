# 🕵️‍♂️ Packet_Sniffing  
## Python-Based Packet Sniffer & Visualizer

---

## 📖 Overview

This project is a high-performance **packet sniffer and visualizer** built using Python. It captures live network traffic and provides real-time, interactive visualizations of various protocol layers (Ethernet, IP, TCP/UDP, etc.), along with detailed packet structure insights.

---

## ✨ Features

- 📦 Live Packet Capture using `scapy` or `pyshark`
- 🔍 Protocol Dissection (Ethernet, IPv4, TCP/UDP, ARP, etc.)
- 📊 Interactive Visualization (traffic flows, protocol usage, port maps)
- 📁 PCAP File Import for offline analysis
- 📉 Real-Time Stats Dashboard
- 🧩 Modular Design — easy to extend with more protocol support
- 🧠 Optional Anomaly Detection using ML (extensible)

---

## 📌 Packet Structure

Here is an example of the layered structure of a captured packet:

[ Ethernet Header ]
  ├── Destination MAC Address
  ├── Source MAC Address
  └── EtherType

[ IP Header ]
  ├── Version & Header Length
  ├── Type of Service
  ├── Total Length
  ├── Identification, Flags, Fragment Offset
  ├── Time to Live (TTL)
  ├── Protocol (TCP/UDP/ICMP)
  ├── Header Checksum
  ├── Source IP Address
  └── Destination IP Address

[ TCP Header ]
  ├── Source Port
  ├── Destination Port
  ├── Sequence Number
  ├── Acknowledgment Number
  ├── Header Length & Flags
  ├── Window Size
  ├── Checksum
  └── Urgent Pointer

[ Payload (Data) ]


---

## 🛠️ Technologies Used

- 🐍 Python 3.8+
- 📡 [`Scapy`](https://scapy.net/) or [`PyShark`](https://github.com/KimiNewt/pyshark) — Packet capture
- 📈 [`Matplotlib`](https://matplotlib.org/), [`Plotly`](https://plotly.com/), [`Dash`](https://dash.plotly.com/) — Visualization
- 📋 [`Pandas`](https://pandas.pydata.org/) — Data handling
- 🌐 [`Flask`](https://flask.palletsprojects.com/) (optional) — Web dashboard

---

## 🚀 Getting Started

### 📦 Install Dependencies


pip install scapy pyshark pandas plotly dash matplotlib

------

## Run the Sniffer (Live Mode)

python main.py

-------

## Analyze PCAP File (Offline Mode)

python main.py --file sample.pcap

-------------

## 📊 Start the Visualizer

python visualizer.py --data output.json

------------

## 📁 Project Structure

packet-sniffer/
│
├── main.py               # Entry point: live capture & dispatcher
├── parser.py             # Protocol parsing and structure extraction
├── visualizer.py         # Real-time & post-analysis visualization
├── utils.py              # Helper functions
├── assets/               # Static files (images, CSS)
├── samples/              # Example PCAPs & output JSONs
├── requirements.txt      # Dependency list
└── README.md             # Project documentation

-----------------

## 📸 Screenshots

![image](https://github.com/user-attachments/assets/a2aa84b6-c641-4951-b6be-2ddfae98c1e8)
![image](https://github.com/user-attachments/assets/8c46fe08-02b8-43e0-8b73-95b31902f98f)
![image](https://github.com/user-attachments/assets/c44cae84-8070-4a09-acc6-b649c19b1152)
![image](https://github.com/user-attachments/assets/a5e78a32-8213-434e-a0b1-46db8a885754)
![image](https://github.com/user-attachments/assets/62701d02-6a62-4d86-89df-a13bcf18602a)

------------

## 💡 Future Improvements

DNS, HTTP, ICMP support

TCP session reassembly

Anomaly detection (e.g., via scikit-learn)

Export visualizations as PDF/PNG

Web dashboard integration (Flask/Dash)

----------

## 📜 License

MIT License
Free to use, modify, and distribute for personal or commercial use.

------------

## 👨‍💻 Author
Created with ❤️ by gamana29
