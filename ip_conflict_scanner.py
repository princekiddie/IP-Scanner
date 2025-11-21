#!/usr/bin/env python3
"""
Advanced IP Conflict Scanner with OS Fingerprinting
---------------------------------------------------
Features:
- Auto-detect network interface + CIDR
- Threaded ARP scanning for large networks
- IP Conflict detection (same IP, multiple MACs)
- Hostname & System ID
- Advanced OS detection:
    * TTL fingerprinting
    * SMB port 445 open (Windows)
    * SSH port 22 banner (Linux/macOS)
    * MAC vendor detection
- Conflict alert (ping)
- Logging with timestamps
"""

from scapy.all import ARP, Ether, srp, conf
from collections import defaultdict
import netifaces
import ipaddress
import socket
import time
import threading
import subprocess
from datetime import datetime
import re

# =================== CONFIG ======================

MANUAL_NETWORK = None            # Example: "192.168.56.0/24"
THREAD_COUNT = 8                 # number of threads
SCAN_INTERVAL_SECONDS = 10       # rescan time
LOG_FILE = "ip_conflict_scanner.log"

# =================================================


def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    if LOG_FILE:
        try:
            with open(LOG_FILE, "a") as f:
                f.write(line + "\n")
        except:
            pass


# -----------------------------------------------------
# Network Auto Detection
# -----------------------------------------------------

def auto_detect_network():
    """Detect active network interface + subnet."""
    for iface in netifaces.interfaces():
        try:
            info = netifaces.ifaddresses(iface).get(netifaces.AF_INET)
            if not info:
                continue

            entry = info[0]
            ip = entry["addr"]
            mask = entry["netmask"]

            # Skip localhost
            if ip.startswith("127."):
                continue

            # Calculate CIDR prefix from netmask
            cidr = sum(bin(int(x)).count("1") for x in mask.split("."))
            network = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)

            return iface, network

        except:
            continue

    return None, None


# -----------------------------------------------------
# Hostname + System ID
# -----------------------------------------------------

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "UNKNOWN_HOST"


def get_system_id(ip, hostname):
    return hostname if hostname != "UNKNOWN_HOST" else f"SYSTEM_{ip.replace('.', '_')}"


# -----------------------------------------------------
# OS Detection Helpers
# -----------------------------------------------------

def get_ttl(ip):
    """Ping host and extract TTL."""
    try:
        output = subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", ip],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        match = re.search(r"ttl=(\d+)", output.lower())
        if match:
            return int(match.group(1))
    except:
        pass
    return None


def mac_vendor(mac):
    """MAC vendor fingerprint."""
    oui = mac.upper()[0:8].replace(":", "-")

    vendors = {
        "00-1C-42": "Parallels VM",
        "00-0C-29": "VMware VM",
        "00-50-56": "VMware VM",
        "08-00-27": "VirtualBox VM",
        "F8-FF-C2": "Intel Corp",
        "FC-A1-3E": "Apple Inc",
        "3C-5A-B4": "Microsoft",
    }

    return vendors.get(oui, "Unknown Vendor")


def check_port(ip, port):
    """Check if TCP port is open."""
    try:
        s = socket.create_connection((ip, port), timeout=1)
        s.close()
        return True
    except:
        return False


def ssh_banner(ip):
    """Grab SSH banner for Linux/macOS detection."""
    try:
        s = socket.create_connection((ip, 22), timeout=1)
        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        return banner
    except:
        return None


def detect_os(ip, mac):
    """Full OS fingerprint via TTL, port scan, banner, MAC."""
    ttl = get_ttl(ip)
    vendor = mac_vendor(mac)

    # SMB -> Windows
    if check_port(ip, 445):
        if "VMware" in vendor or "VirtualBox" in vendor:
            return "Windows (VM)"
        return "Windows"

    # SSH banner -> Linux/macOS
    banner = ssh_banner(ip)
    if banner:
        b = banner.lower()
        if "linux" in b:
            return "Linux"
        if "ubuntu" in b:
            return "Ubuntu Linux"
        if "debian" in b:
            return "Debian Linux"
        if "fedora" in b:
            return "Fedora Linux"
        if "darwin" in b or "mac" in b:
            return "macOS"
        return "SSH Device"

    # TTL fallback
    if ttl:
        if ttl >= 128:
            return "Windows"
        if ttl <= 64:
            return "Linux/Unix"
        if ttl == 255:
            return "Network Device"

    return "Unknown"


# -----------------------------------------------------
# ARP Scanning
# -----------------------------------------------------

def arp_scan(subnet):
    """ARP scan a subnet and return list of devices."""
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    try:
        answered = srp(packet, timeout=2, verbose=0)[0]
    except:
        return []

    return [{"ip": r.psrc, "mac": r.hwsrc.lower()} for _, r in answered]


def split_subnets(network):
    """Split large networks into /24 chunks."""
    if network.prefixlen < 24:
        return [str(sub) for sub in network.subnets(new_prefix=24)]
    return [str(network)]


def threaded_scan(subnets):
    """Threaded ARP scanning."""
    results = []
    lock = threading.Lock()

    def worker(chunk):
        for subnet in chunk:
            devices = arp_scan(subnet)
            with lock:
                results.extend(devices)

    chunks = [[] for _ in range(min(THREAD_COUNT, len(subnets)))]
    for i, subnet in enumerate(subnets):
        chunks[i % len(chunks)].append(subnet)

    threads = []
    for c in chunks:
        t = threading.Thread(target=worker, args=(c,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return results


# -----------------------------------------------------
# Scanner Logic
# -----------------------------------------------------

def send_signal_to_pc(ip):
    """Ping conflict device."""
    log(f"Sending alert ping to {ip}...")
    try:
        subprocess.run(["ping", "-c", "1", ip],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    except:
        pass


def run_one_scan():
    """Perform full scan cycle."""
    if MANUAL_NETWORK:
        network = ipaddress.ip_network(MANUAL_NETWORK, strict=False)
        iface = "manual"
    else:
        iface, network = auto_detect_network()
        if not iface:
            log("[ERROR] Could not auto detect network")
            return

    log(f"Using interface: {iface}")
    log(f"Scanning network: {network.with_prefixlen}")

    subnets = split_subnets(network)
    log(f"Split into {len(subnets)} subnet(s)")

    conf.verb = 0
    devices = threaded_scan(subnets)
    log(f"Detected {len(devices)} device(s)")

    # IP -> MACs mapping
    ip_map = defaultdict(set)
    for d in devices:
        ip_map[d["ip"]].add(d["mac"])

    conflicts = {ip: macs for ip, macs in ip_map.items() if len(macs) > 1}

    for ip, macs in ip_map.items():
        mac_list = ", ".join(macs)
        hostname = get_hostname(ip)
        system_id = get_system_id(ip, hostname)
        os_type = detect_os(ip, list(macs)[0])

        if ip in conflicts:
            log(f"[CONFLICT] {ip} | MACs: {mac_list} | Hostname: {hostname} | OS: {os_type} | ID: {system_id}")
            send_signal_to_pc(ip)
        else:
            log(f"[OK] {ip} | MAC: {mac_list} | Hostname: {hostname} | OS: {os_type} | ID: {system_id}")

    if conflicts:
        log(f"{len(conflicts)} conflict(s) detected")
    else:
        log("No conflicts detected")

    log("Scan complete.\n")


def main():
    log("===== Advanced IP Conflict Scanner Started =====")
    while True:
        run_one_scan()
        log(f"Next scan in {SCAN_INTERVAL_SECONDS} seconds...\n")
        time.sleep(SCAN_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
