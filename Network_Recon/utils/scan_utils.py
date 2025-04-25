# utils/scan_utils.py

import socket
import re
from utils.output_utils import print_status
from utils.constants import COMMON_PORTS, VERSION_PATTERNS

# Top 10 commonly used ports & their service names
COMMON_PORTS = {
    21:  "FTP",
    22:  "SSH",
    23:  "Telnet",
    25:  "SMTP",
    53:  "DNS",
    80:  "HTTP",
    110: "POP3",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB"
}

# Patterns to extract version info from banners
VERSION_PATTERNS = [
    (r"OpenSSH[_/](\S+)",            "SSH"),
    (r"Apache[/ ](\S+)",             "Apache"),
    (r"nginx[/ ](\S+)",              "Nginx"),
    (r"Microsoft-IIS[/ ](\S+)",      "IIS"),
    (r"FTP server.*?(\d+\.\d+)",     "FTP"),
    (r"MySQL\s+(\d+\.\d+\.\d+)",     "MySQL"),
    (r"PostgreSQL\s+(\d+\.\d+)",     "PostgreSQL")
]

def detect_version(banner: str) -> str:
    """
    Try to match known patterns in the banner to pull out a service name + version.
    """
    if not banner:
        return "Unknown"
    for pattern, name in VERSION_PATTERNS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            return f"{name} {m.group(1)}"
    return "Unknown"

def scan_top_ports(ip: str, timeout: float = 1.0):
    """
    Scans the COMMON_PORTS on the given IP.
    Returns a list of dicts: [{ port, service, banner, version }, ...]
    """
    open_ports = []
    print_status(f"🚀 Scanning top {len(COMMON_PORTS)} ports on {ip}...")

    for port, service in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Port is open — grab banner
                try:
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except:
                    banner = ""
                version = detect_version(banner)
                print_status(f"[+] {port}/tcp OPEN ({service}) — {version}")
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "banner":  banner or "No banner",
                    "version": version
                })
            sock.close()
        except Exception as e:
            print_status(f"[!] Error on port {port}: {e}")

    if not open_ports:
        print_status("[-] No common ports open.")
    return open_ports
