# 🛡️ IP Conflict Scanner
Advanced Network Scanner with OS Fingerprinting & ARP Detection.

## 🚀 Features
- Detect IP conflicts across large networks  
- Multi-threaded ARP scanning  
- Auto network detection  
- Hostname + System ID  
- Advanced OS fingerprinting:  
  - TTL-based OS detection  
  - SMB port probe (Windows)  
  - SSH banner grab (Linux/macOS)  
  - MAC vendor lookup  
- Logging  
- Alert signal (ping)  
- Python 3.8–3.13 compatible  

## 📦 Installation

Install dependencies:

```bash
pip install -r requirements.txt
```

Run:

```bash
sudo python3 ip_conflict_scanner.py
```

## 🧪 Example Output
```
[OK] 192.168.56.101 | MAC: 08:00:27:AA:BB:CC | OS: Windows | Hostname: SERVER19
[CONFLICT] 192.168.56.103 | MACs: ... | OS: Windows (VM)
```

## 🖥️ System Requirements
Operating System:
- Kali Linux (recommended)
- Ubuntu 20.04+
- Debian
- Windows 10/11 (WSL supported)
- Windows Server 2016–2022
- macOS (limited OS detection support)

Python:
- Python 3.8 – 3.13

Permissions:
- Root or administrator privileges (sudo required for ARP scan)

Network Requirements:
- Active Ethernet/WiFi interface
- ARP scanning must be allowed on the network
- For WiFi scanning: client isolation must be disabled

Hardware:
- 2GB RAM minimum
- Dual-core CPU

## 📄 License
MIT License  
Free to use, modify, and distribute.

