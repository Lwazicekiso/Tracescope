# modules/nmap_scanner.py

import nmap
import socket
import ipaddress
from utils.output_utils import print_status
from utils.concurrency import parallel_map

def _parse_ports(scan_data, host):
    """Parse nmap scan output into a list of port dicts."""
    ports = []
    if not scan_data or host not in scan_data.all_hosts():
        return ports

    for proto in ('tcp', 'udp'):
        if proto in scan_data[host]:
            for port_num, port_info in scan_data[host][proto].items():
                ports.append({
                    'port': port_num,
                    'protocol': proto,
                    'service': port_info.get('name'),
                    'product': port_info.get('product'),
                    'version': port_info.get('version'),
                    'ostype': None  # We handle OS separately
                })
    return ports

def _parse_os(scan_data, host):
    """Parse nmap OS detection output into a list of OS guesses."""
    os_list = []
    if not scan_data or host not in scan_data.all_hosts():
        return os_list

    osmatches = scan_data[host].get('osmatch', [])
    for match in osmatches:
        name = match.get('name')
        accuracy = match.get('accuracy')
        if name:
            os_list.append(f"{name}" + (f" ({accuracy}%)" if accuracy else ""))
    return os_list

def scan_host(host):
    """
    Scan a single host for service/version and OS.
    Returns dict: {'host':..., 'open_ports':[...], 'os':[...]}.
    """
    nm = nmap.PortScanner()
    print_status(f"🔍 Scanning host {host} (ports & OS)...")

    try:
        nm.scan(hosts=host, arguments='-sV -O --top-ports 100')
    except Exception as e:
        print_status(f"⚠️ Scan failed for {host}: {e}")
        return {
            'host': host,
            'open_ports': [],
            'os': []
        }

    ports = _parse_ports(nm, host)
    os_guesses = _parse_os(nm, host)

    return {
        'host': host,
        'open_ports': ports,
        'os': os_guesses
    }

def scan_network(network, max_workers=10):
    """
    Discover live hosts on 'network' (e.g. '192.168.1.0/24'), then scan each concurrently.
    Returns list of scan_host() dicts.
    """
    print_status(f"🔍 Discovering live hosts on {network}...")
    nm = nmap.PortScanner()

    hosts = []
    try:
        discovery = nm.scan(hosts=network, arguments='-sn')  # Ping scan
    except Exception as e:
        print_status(f"⚠️ Discovery scan failed: {e}")
        discovery = None

    if discovery:
        for host, data in discovery.get('scan', {}).items():
            if data.get('status', {}).get('state') == 'up':
                hosts.append(host)

    hosts = list(dict.fromkeys(hosts))
    print_status(f"✅ Found {len(hosts)} live host(s). Scanning with {max_workers} workers...")

    results = parallel_map(scan_host, hosts, max_workers=max_workers)
    return results

def scan_target(target):
    """
    Wrapper: if target contains '/', do network scan; else per-host scan.
    """
    if '/' in target:
        return scan_network(target)
    hosts = [h.strip() for h in target.split(',')]
    return parallel_map(scan_host, hosts, max_workers=len(hosts))

def get_local_network():
    """
    Auto-detect your local /24 network via a dummy socket.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(ip + '/24', strict=False)
        return str(net)
    except Exception:
        return None
