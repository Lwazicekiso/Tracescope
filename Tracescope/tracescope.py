import argparse
from recon import whois_lookup, dns_lookup, port_scanner
from utils.reporter import export_report

def main():
    parser = argparse.ArgumentParser(description="TraceScope Recon Tool")
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    args = parser.parse_args()
    
    domain = args.domain
    print(f"\n[+] Starting TraceScope for {domain}...\n")

    whois_data = whois_lookup.lookup(domain)
    dns_data = dns_lookup.lookup_all(domain)
    ports = port_scanner.scan_ports(domain)

    report = {
        "domain": domain,
        "whois": whois_data,
        "dns": dns_data,
        "open_ports": ports
    }

    export_report(domain, report)
    print(f"\n[✔] Done! Report saved in 'reports/{domain}_report.*'\n")

if __name__ == "__main__":
    main()
