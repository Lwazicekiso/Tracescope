# modules/internal_scan.py

from modules.nmap_scanner import scan_target
from modules.cve_lookup     import get_cves
from utils.output_utils     import print_status
from utils.ip_utils         import select_interface, detect_subnet

def run_internal_scan():
    print_status("🔍 Starting internal network scan…")

    # 1. Choose interface
    iface, local_ip, netmask = select_interface()
    if not local_ip:
        print_status("❌ No interface selected. Aborting.")
        return None

    # 2. Calculate subnet
    network = detect_subnet(local_ip, netmask)
    if not network:
        print_status("❌ Failed to determine subnet. Aborting.")
        return None
    subnet_str = str(network)
    print_status(f"✅ Scanning subnet {subnet_str}")

    # 3. Nmap scan entire subnet
    try:
        hosts = scan_target(subnet_str)
        # 4. Inject CVEs
        for host in hosts:
            for port in host.get("ports", []):
                port["cves"] = get_cves(port.get("service"), port.get("version"))

        report = {
            "scan_type": "internal",
            "interface": iface,
            "local_ip": local_ip,
            "subnet": subnet_str,
            "hosts": hosts
        }

        print_status("📝 Internal scan complete.")
        return report

    except Exception as e:
        print_status(f"❌ Internal Nmap scan failed: {repr(e)}")
        return None
