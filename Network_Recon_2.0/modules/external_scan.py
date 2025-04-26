# modules/external_scan.py

import socket
import whois
import dns.resolver

from modules.nmap_scanner import scan_target
from modules.cve_lookup     import get_cves
from utils.output_utils     import print_status

def run_external_scan(domain):
    print_status(f"🔍 Starting external scan on {domain}…")

    report = {
        "domain": domain,
        "whois": {},
        "dns": {},
        "hosts": []
    }

    # WHOIS
    try:
        w = whois.whois(domain)
        report["whois"] = {
            "domain_name":     str(w.domain_name)     if w.domain_name     else None,
            "registrar":       str(w.registrar)       if w.registrar       else None,
            "creation_date":   str(w.creation_date)   if w.creation_date   else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers":    w.name_servers         or []
        }
        print_status("✅ WHOIS lookup successful.")
    except Exception as e:
        print_status(f"❌ WHOIS lookup failed: {repr(e)}")

    # DNS
    try:
        a_records, mx_records, ns_records = [], [], []
        try:
            a_records  = [r.address for r in dns.resolver.resolve(domain, "A", raise_on_no_answer=False)]
        except: pass
        try:
            mx_records = [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(domain, "MX", raise_on_no_answer=False)]
        except: pass
        try:
            ns_records = [str(r.target).rstrip('.') for r in dns.resolver.resolve(domain, "NS", raise_on_no_answer=False)]
        except: pass

        report["dns"] = {
            "A_records":  a_records,
            "MX_records": mx_records,
            "NS_records": ns_records
        }
        print_status("✅ DNS records fetched.")
    except Exception as e:
        print_status(f"❌ DNS lookup failed: {repr(e)}")

    # Nmap scan
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        hosts = scan_target(",".join(ips))
        for host in hosts:
            for port in host.get("ports", []):
                port["cves"] = get_cves(port.get("service"), port.get("version"))
        report["hosts"] = hosts
        print_status("✅ Nmap scan & CVE lookup complete.")
    except Exception as e:
        print_status(f"❌ Nmap scan failed: {repr(e)}")

    print_status("📝 External scan complete.")
    return report
