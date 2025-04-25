# external_scan.py

import socket
import whois
import dns.resolver

from utils.output_utils import print_status, save_report
from utils.scan_utils import scan_top_ports
from cve_checker import get_cves         # ← import CVE lookup

def run_external_scan(domain):
    print_status(f"🔍 Starting external scan on {domain}...\n")

    report = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "open_ports": []
    }

    # WHOIS Lookup
    try:
        w = whois.whois(domain)
        report["whois"] = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers
        }
        print_status("✅ WHOIS lookup successful.")
    except Exception as e:
        print_status(f"[!] WHOIS failed: {e}")

    # DNS Records
    try:
        report["dns"] = {
            "A_records": [r.address       for r in dns.resolver.resolve(domain, "A",  raise_on_no_answer=False)],
            "MX_records":[str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, "MX", raise_on_no_answer=False)],
            "NS_records":[str(r.target).rstrip('.')   for r in dns.resolver.resolve(domain, "NS", raise_on_no_answer=False)],
        }
        print_status("✅ DNS records fetched.")
    except Exception as e:
        print_status(f"[!] DNS lookup failed: {e}")

    # Open Port Scan (Top 10 common ports)
    try:
        ip = socket.gethostbyname(domain)
        open_ports = scan_top_ports(ip)

        # ← integrate CVEs per port
        for p in open_ports:
            p["cves"] = get_cves(p["service"], p["version"])

        report["open_ports"] = open_ports
        print_status("✅ Port scan & CVE lookup complete.")
    except Exception as e:
        print_status(f"[!] Port scan failed: {e}")

    # Save Report (will include the new cves field)
    save_report(domain, report)
    print_status("📝 Report saved in /reports/ folder.\n")
