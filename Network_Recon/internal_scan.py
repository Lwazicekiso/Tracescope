# internal_scan.py

import subprocess
import platform
import os
import json
from datetime import datetime

from utils.ip_utils     import get_local_ip, get_subnet
from utils.scan_utils   import scan_top_ports
from utils.output_utils import print_status
from cve_checker        import get_cves

def ping_host(ip: str, timeout: int = 1) -> bool:
    """
    Ping `ip` once. Returns True if host responds.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception as e:
        print_status(f"[!] Ping error for {ip}: {e}")
        return False

def save_internal_report(local_ip: str, subnet: str, hosts_data: list):
    """
    Builds and writes both JSON and TXT reports for the internal scan.
    """
    ts_iso = datetime.utcnow().isoformat() + "Z"
    report = {
        "scan_type":   "internal",
        "local_ip":    local_ip,
        "subnet":      subnet,
        "timestamp":   ts_iso,
        "live_hosts":  hosts_data
    }

    if not os.path.isdir("reports"):
        os.makedirs("reports")

    tag       = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix    = f"internal_{local_ip.replace('.', '_')}_{tag}"
    json_path = f"reports/{prefix}.json"
    txt_path  = f"reports/{prefix}.txt"

    # Save JSON
    with open(json_path, "w") as jf:
        json.dump(report, jf, indent=2)

    # Save TXT
    with open(txt_path, "w") as tf:
        tf.write(f"=== Internal Network Scan Report ===\n")
        tf.write(f"Scan Time : {ts_iso}\n")
        tf.write(f"Local IP  : {local_ip}\n")
        tf.write(f"Subnet    : {subnet}\n\n")
        if not hosts_data:
            tf.write("No live hosts detected on the subnet.\n")
        for host in hosts_data:
            tf.write(f"Host: {host['host']}\n")
            if host["open_ports"]:
                for p in host["open_ports"]:
                    tf.write(f"  • Port {p['port']} ({p.get('service','')}) — {p.get('version','')} \n")
                    if p.get("cves"):
                        for cve in p["cves"]:
                            tf.write(f"     - {cve['id']}: {cve['description']}\n")
            else:
                tf.write("  • No common open ports detected.\n")
            tf.write("\n")

    print_status(f"📝 Internal scan reports saved:\n   • {json_path}\n   • {txt_path}")

def run_internal_scan():
    print_status("🔍 Starting internal network scan…")

    # 1. Detect local IP & subnet
    try:
        local_ip = get_local_ip()
        print_status(f"[+] Detected local IP: {local_ip}")
        net = get_subnet(local_ip)
        subnet_str = str(net)
        print_status(f"[+] Scanning subnet: {subnet_str}")
    except Exception as e:
        print_status(f"[!] Network setup failed: {e}")
        return

    # 2. Ping-sweep + 3. Port-scan live hosts
    hosts_data = []
    for host in net.hosts():
        ip = str(host)
        print_status(f"→ Probing {ip} …")
        if not ping_host(ip):
            continue

        print_status(f"[+] Host is UP: {ip} — Scanning ports…")
        try:
            ports = scan_top_ports(ip)
            # integrate CVEs
            for p in ports:
                p["cves"] = get_cves(p["service"], p["version"])
            hosts_data.append({"host": ip, "open_ports": ports})
        except Exception as e:
            print_status(f"[!] Error scanning {ip}: {e}")
            hosts_data.append({"host": ip, "open_ports": []})

    # 4. Save report
    save_internal_report(local_ip, subnet_str, hosts_data)
