# 🔍 NetProbe — Network Packet Analyzer

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.4.5%2B-teal?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

**A lightweight, beginner-friendly CLI network packet analyzer built with Python and Scapy.**  
Capture, decode, and analyze live network traffic in real time — designed for students and learners.

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Output](#-sample-output) • [Contributing](#-contributing)

</div>

---

## 📌 What is NetProbe?

NetProbe bridges the gap between **networking theory** and **real-world observation**.

Most packet analyzers like Wireshark are powerful but overwhelming for beginners. NetProbe shows exactly what matters — decoded packet fields in clean, color-coded output — without the noise.

> *NetProbe is not a replacement for Wireshark — it is a stepping stone toward it.*

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔴 **Live Capture** | Sniffs real-time packets from any network interface |
| 🎨 **Color-Coded Output** | Each protocol gets a distinct terminal color |
| 🔍 **Field Decoder** | Extracts IPs, MACs, ports, TCP flags, ICMP type, DNS queries, payload preview |
| 📂 **Session Logging** | Saves all output to a timestamped `.txt` file in `/logs` |
| ⚙️ **Protocol Filter** | Focus on a single protocol: `tcp`, `udp`, `icmp`, `arp`, `dns` |
| 🎯 **IP Filter** | Capture only traffic to/from a specific IP address |
| 🖥️ **Easy CLI** | Simple flags — any student with Python basics can run it |

### Supported Protocols
```
TCP  ·  UDP  ·  ICMP  ·  ARP  ·  DNS
```

---

## 🛠️ Installation

### Prerequisites
- Python 3.9 or higher
- `sudo` / Administrator privileges (required for raw socket access)
- **Windows only:** Install [Npcap](https://npcap.com/) before running

### Step 1 — Clone the repository
```bash
git clone https://github.com/rohitkazal2003-rgb/netprobe.git
cd netprobe
```

### Step 2 — Install dependencies
```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install scapy colorama
```

### Step 3 — Run NetProbe
```bash
# Linux / macOS
sudo python netprobe.py --iface eth0

# Windows (run as Administrator)
python netprobe.py --iface Ethernet
```

---

## 🚀 Usage

```
usage: netprobe [-h] --iface IFACE [--filter {tcp,udp,icmp,arp,dns}]
                [--ip IP] [--count COUNT] [--log]
```

### CLI Options

| Flag | Short | Description | Example |
|---|---|---|---|
| `--iface` | `-i` | Network interface *(required)* | `eth0`, `wlan0`, `Ethernet` |
| `--filter` | `-f` | Protocol to capture | `tcp`, `udp`, `icmp`, `arp`, `dns` |
| `--ip` | | Filter by IP address | `192.168.1.5` |
| `--count` | `-c` | Packet limit (0 = unlimited) | `100` |
| `--log` | `-l` | Save session to log file | *(flag, no value)* |
| `--help` | `-h` | Show help message | |

### Example Commands

```bash
# Capture all traffic on eth0
sudo python netprobe.py --iface eth0

# Capture 100 TCP packets only, with logging
sudo python netprobe.py --iface eth0 --filter tcp --count 100 --log

# Capture all DNS queries
sudo python netprobe.py --iface wlan0 --filter dns

# Filter traffic to/from a specific IP
sudo python netprobe.py --iface eth0 --ip 192.168.1.5

# Unlimited capture with session log saved
sudo python netprobe.py --iface eth0 --log
```

---

## 📺 Sample Output

```
  _   _      _   ____            _
 | \ | | ___| |_|  _ \ _ __ ___| |__   ___
 |  \| |/ _ \ __| |_) | '__/ _ \ '_ \ / _ \
 | |\  |  __/ |_|  __/| | |  __/ |_) |  __/
 |_| \_|\___|\__|_|   |_|  \___|_.__/ \___|

  A Network Packet Analyzer  |  v1.0.0  |  Python + Scapy
  ─────────────────────────────────────────────────────────
  Interface : eth0
  Filter    : ALL PROTOCOLS
  Logging   : ON
  ─────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────────────────────────
[10:42:31.204]  Packet #1
[TCP]  192.168.1.12:54321  →  142.250.80.46:443
       Flags: SYN  |  Seq: 1042981723  |  Ack: 0
       Payload: (empty)

────────────────────────────────────────────────────────────────────────────────
[10:42:31.321]  Packet #2
[DNS]  Query  |  192.168.1.12  →  8.8.8.8
       Question: www.google.com.

────────────────────────────────────────────────────────────────────────────────
[10:42:33.501]  Packet #7
[ICMP] 192.168.1.12  →  8.8.8.8
       Echo Request (Ping)  |  Code: 0

────────────────────────────────────────────────────────────────────────────────
[10:42:34.002]  Packet #9
[ARP]  Request  |  192.168.1.12 (a4:c3:f0:12:34:56)  →  192.168.1.1 (00:00:00:00:00:00)
```
*(See [sample_output.txt](sample_output.txt) for full session output)*

---

## 📁 Project Structure

```
netprobe/
│
├── netprobe.py          # Main script — all logic here
├── requirements.txt     # Python dependencies
├── sample_output.txt    # Example terminal output
├── LICENSE              # MIT License
├── .gitignore           # Git ignore rules
└── README.md            # This file
│
└── logs/                # Auto-created on first --log run
    └── netprobe_YYYYMMDD_HHMMSS.txt
```

---

## ⚙️ How It Works

```
Network Interface (eth0 / wlan0)
        │
        ▼
[ Scapy sniff() ]  ──→  Raw packet interception (promiscuous mode)
        │
        ▼
[ Protocol Detection ]  ──→  TCP / UDP / ICMP / ARP / DNS
        │
        ▼
[ Field Extraction ]  ──→  IPs, MACs, ports, flags, payload
        │
        ▼
[ Filter Engine ]  ──→  Drop packets not matching --filter / --ip
        │
        ▼
[ Output + Logger ]  ──→  Terminal (color-coded) + .txt log file
```

> **NetProbe is passive** — it only observes traffic and never injects or modifies packets.

---

## 🔒 Ethical Use

This tool is built for **educational and authorized network monitoring only**.  
Only use NetProbe on networks you own or have explicit permission to monitor.  
Unauthorized packet capture may violate local laws and regulations.

---

## 🧪 Tested On

| OS | Python | Interface |
|---|---|---|
| Ubuntu 22.04 | 3.10 | eth0, wlan0 |
| macOS Ventura | 3.11 | en0 |
| Windows 11 | 3.9 | Ethernet (with Npcap) |

---

## 🛣️ Future Scope

- [ ] GUI dashboard with real-time protocol charts
- [ ] Export captures to `.pcap` (Wireshark-compatible)
- [ ] Anomaly detection and alerting
- [ ] Wi-Fi monitor mode
- [ ] IPv6 full support

---

## 🤝 Contributing

Pull requests are welcome!

```bash
# Fork → Clone → Create branch → Make changes → Open PR
git checkout -b feature/your-feature-name
```

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**Rohit**  
MCA | Apeejay Stya University  
[![GitHub](https://img.shields.io/badge/GitHub-rohitkazal2003--rgb-black?style=flat&logo=github)](https://github.com/rohitkazal2003-rgb)

---

<div align="center">
  <sub>Built with ❤️ using Python + Scapy | MCA Final Year Project</sub>
</div>
