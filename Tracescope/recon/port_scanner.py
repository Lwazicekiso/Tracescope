import socket
import re

def detect_version(banner):
    if not banner:
        return "Unknown"

    patterns = [
        (r"OpenSSH[_/](\S+)", "SSH"),
        (r"Apache[/ ](\S+)", "Apache"),
        (r"nginx[/ ](\S+)", "Nginx"),
        (r"Microsoft-IIS[/ ](\S+)", "IIS"),
        (r"FTP server.*?(\d+\.\d+)", "FTP"),
        (r"MySQL\s+(\d+\.\d+\.\d+)", "MySQL"),
    ]

    for pattern, service in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            return f"{service} {match.group(1)}"
    return "Unknown"

def scan_ports(host, ports=range(1, 101)):
    open_ports = []
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            s.connect((host, port))
            try:
                banner = s.recv(1024).decode(errors="ignore").strip()
            except:
                banner = ""
            version_info = detect_version(banner)
            open_ports.append({
                "port": port,
                "banner": banner if banner else "No banner",
                "version": version_info
            })
            s.close()
        except:
            continue
    return open_ports
