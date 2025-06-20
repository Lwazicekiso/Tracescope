# modules/nmap_scanner.py

import nmap
import socket
import ipaddress
from utils.output_utils import print_status
from utils.concurrency import parallel_map

# Scan mode configurations
SCAN_MODES = {
    'default': '-Pn -sV -O --top-ports 100',
    'stealth': '-Pn -sS -T2 --top-ports 50 --scan-delay 300ms',
    'aggressive': '-Pn -sV -sC -O --version-all -T4 --top-ports 1000',
    'vuln_scan': '-Pn -sV -sC --script vuln --top-ports 100',
    'comprehensive': '-Pn -sV -sC -O --script default,vuln,discovery --version-all --top-ports 1000'
}

def _parse_ports(scan_data, host):
    """Parse nmap scan output into a list of port dicts with enhanced information."""
    ports = []
    if not scan_data or host not in scan_data.all_hosts():
        return ports

    for proto in ('tcp', 'udp'):
        if proto in scan_data[host]:
            for port_num, port_info in scan_data[host][proto].items():
                port_dict = {
                    'port': port_num,
                    'protocol': proto,
                    'state': port_info.get('state', 'unknown'),
                    'service': port_info.get('name', 'unknown'),
                    'product': port_info.get('product', ''),
                    'version': port_info.get('version', ''),
                    'extrainfo': port_info.get('extrainfo', ''),
                    'conf': port_info.get('conf', ''),
                    'method': port_info.get('method', ''),
                    'cpe': port_info.get('cpe', ''),
                    'scripts': {},
                    'ostype': None  # We handle OS separately
                }
                
                # Parse NSE script results for vulnerability info
                if 'script' in port_info:
                    port_dict['scripts'] = port_info['script']
                
                ports.append(port_dict)
    return ports

def _parse_os(scan_data, host):
    """Parse nmap OS detection output into a list of OS guesses with enhanced details."""
    os_list = []
    if not scan_data or host not in scan_data.all_hosts():
        return os_list

    osmatches = scan_data[host].get('osmatch', [])
    for match in osmatches:
        name = match.get('name')
        accuracy = match.get('accuracy')
        line = match.get('line', '')
        if name:
            os_entry = {
                'name': name,
                'accuracy': accuracy,
                'line': line
            }
            os_list.append(os_entry)
    return os_list

def _parse_host_scripts(scan_data, host):
    """Parse host-level NSE script results."""
    host_scripts = {}
    if not scan_data or host not in scan_data.all_hosts():
        return host_scripts
    
    if 'hostscript' in scan_data[host]:
        for script in scan_data[host]['hostscript']:
            script_id = script.get('id', 'unknown')
            host_scripts[script_id] = script.get('output', '')
    
    return host_scripts

def _parse_vulnerabilities(scan_data, host):
    """Extract vulnerability information from NSE scripts."""
    vulnerabilities = []
    if not scan_data or host not in scan_data.all_hosts():
        return vulnerabilities
    
    # Check host-level vulnerability scripts
    if 'hostscript' in scan_data[host]:
        for script in scan_data[host]['hostscript']:
            if 'vuln' in script.get('id', '').lower():
                vulnerabilities.append({
                    'type': 'host',
                    'script': script.get('id', ''),
                    'output': script.get('output', '')
                })
    
    # Check port-level vulnerability scripts
    for proto in ('tcp', 'udp'):
        if proto in scan_data[host]:
            for port_num, port_info in scan_data[host][proto].items():
                if 'script' in port_info:
                    for script_name, script_output in port_info['script'].items():
                        if 'vuln' in script_name.lower() or 'cve' in script_name.lower():
                            vulnerabilities.append({
                                'type': 'port',
                                'port': port_num,
                                'protocol': proto,
                                'script': script_name,
                                'output': script_output
                            })
    
    return vulnerabilities

def scan_host(host, scan_mode='default', custom_args=None):
    """
    Scan a single host for service/version, OS, and vulnerabilities.
    Returns dict: {'host':..., 'open_ports':[...], 'ports':[...], 'os':[...], 'vulnerabilities':[...], etc}.
    
    Args:
        host: Target host IP or hostname
        scan_mode: One of 'default', 'stealth', 'aggressive', 'vuln_scan', 'comprehensive'
        custom_args: Custom nmap arguments (overrides scan_mode if provided)
    """
    nm = nmap.PortScanner()
    
    # Determine scan arguments
    if custom_args:
        scan_args = custom_args
        mode_desc = "custom"
    else:
        scan_args = SCAN_MODES.get(scan_mode, SCAN_MODES['default'])
        mode_desc = scan_mode
    
    print_status(f"🔍 Scanning host {host} ({mode_desc} mode)...")

    try:
        nm.scan(hosts=host, arguments=scan_args)
    except Exception as e:
        print_status(f"⚠️ Scan failed for {host}: {e}")
        return {
            'host': host,
            'status': 'error',
            'error': str(e),
            'open_ports': [],  # Legacy compatibility
            'ports': [],       # Enhanced port info
            'os': [],
            'host_scripts': {},
            'vulnerabilities': [],
            'scan_mode': mode_desc
        }

    # Parse all scan results
    ports = _parse_ports(nm, host)
    os_guesses = _parse_os(nm, host)
    host_scripts = _parse_host_scripts(nm, host)
    vulnerabilities = _parse_vulnerabilities(nm, host)
    
    # Get host status and additional info
    host_status = 'unknown'
    hostname = ''
    mac_address = ''
    vendor = ''
    
    if host in nm.all_hosts():
        host_data = nm[host]
        host_status = host_data.get('status', {}).get('state', 'unknown')
        
        # Get hostname info
        hostnames = host_data.get('hostnames', [])
        if hostnames:
            hostname = hostnames[0].get('name', '')
        
        # Get MAC address info  
        addresses = host_data.get('addresses', {})
        if 'mac' in addresses:
            mac_address = addresses['mac']
        if 'vendor' in host_data:
            vendor = list(host_data['vendor'].values())[0] if host_data['vendor'] else ''

    result = {
        'host': host,
        'hostname': hostname,
        'status': host_status,
        'mac_address': mac_address,
        'vendor': vendor,
        'open_ports': ports,      # Legacy compatibility - keep this for existing code
        'ports': ports,           # Enhanced - same data but clearer naming
        'os': os_guesses,
        'host_scripts': host_scripts,
        'vulnerabilities': vulnerabilities,
        'scan_mode': mode_desc,
        'scan_args': scan_args
    }

    return result

def scan_network(network, max_workers=10, scan_mode='default', custom_args=None):
    """
    Discover live hosts on 'network' (e.g. '192.168.1.0/24'), then scan each concurrently.
    Returns list of scan_host() dicts.
    
    Args:
        network: Network CIDR (e.g., '192.168.1.0/24')
        max_workers: Number of concurrent scanning threads
        scan_mode: Scan mode to use for each host
        custom_args: Custom nmap arguments for host scanning
    """
    print_status(f"🔍 Discovering live hosts on {network}...")
    nm = nmap.PortScanner()

    hosts = []
    try:
        # Use different discovery methods based on scan mode
        if scan_mode == 'stealth':
            discovery_args = '-sn -T2'  # Stealthier ping scan
        else:
            discovery_args = '-sn'      # Standard ping scan
            
        discovery = nm.scan(hosts=network, arguments=discovery_args)
    except Exception as e:
        print_status(f"⚠️ Discovery scan failed: {e}")
        discovery = None

    if discovery:
        for host, data in discovery.get('scan', {}).items():
            if data.get('status', {}).get('state') == 'up':
                hosts.append(host)

    hosts = list(dict.fromkeys(hosts))  # Remove duplicates
    print_status(f"✅ Found {len(hosts)} live host(s). Scanning with {max_workers} workers...")

    # Create a wrapper function that passes scan_mode and custom_args
    def scan_host_wrapper(host):
        return scan_host(host, scan_mode=scan_mode, custom_args=custom_args)

    results = parallel_map(scan_host_wrapper, hosts, max_workers=max_workers)
    return results

def scan_target(target, scan_mode='default', custom_args=None, max_workers=10):
    """
    Wrapper: if target contains '/', do network scan; else per-host scan.
    
    Args:
        target: Single host, comma-separated hosts, or CIDR network
        scan_mode: Scan mode to use
        custom_args: Custom nmap arguments
        max_workers: Max concurrent workers for network scans
    """
    if '/' in target:
        return scan_network(target, max_workers=max_workers, scan_mode=scan_mode, custom_args=custom_args)
    
    hosts = [h.strip() for h in target.split(',')]
    
    # Create wrapper function for parallel execution
    def scan_host_wrapper(host):
        return scan_host(host, scan_mode=scan_mode, custom_args=custom_args)
    
    return parallel_map(scan_host_wrapper, hosts, max_workers=min(len(hosts), max_workers))

def stealth_scan_target(target, max_workers=5):
    """
    Convenience function for stealth scanning.
    Uses slower, more evasive techniques.
    """
    return scan_target(target, scan_mode='stealth', max_workers=max_workers)

def vulnerability_scan_target(target, max_workers=5):
    """
    Convenience function for vulnerability scanning.
    Focuses on finding known vulnerabilities.
    """
    return scan_target(target, scan_mode='vuln_scan', max_workers=max_workers)

def comprehensive_scan_target(target, max_workers=3):
    """
    Convenience function for comprehensive scanning.
    Uses all available NSE scripts and techniques.
    """
    return scan_target(target, scan_mode='comprehensive', max_workers=max_workers)

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

def get_available_scan_modes():
    """
    Returns list of available scan modes and their descriptions.
    """
    return {
        'default': 'Standard service and OS detection scan',
        'stealth': 'Slow, evasive scan to avoid detection',
        'aggressive': 'Fast, comprehensive scan with all techniques',
        'vuln_scan': 'Vulnerability-focused scan using NSE vuln scripts',
        'comprehensive': 'Complete scan with all scripts and techniques'
    }