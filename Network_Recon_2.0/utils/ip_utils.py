# utils/ip_utils.py

import psutil
import ipaddress

def list_interfaces():
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == 'AF_INET':
                ip      = addr.address
                netmask = addr.netmask
                if ip and not ip.startswith(('127.', '0.')):
                    interfaces[iface] = {'ip': ip, 'netmask': netmask}
    return interfaces

def select_interface():
    interfaces = list_interfaces()
    if not interfaces:
        raise RuntimeError("No network interfaces found.")
    # Auto-select if only one
    if len(interfaces) == 1:
        iface, info = next(iter(interfaces.items()))
        print(f"Auto-selected interface: {iface} with IP {info['ip']}")
        return iface, info['ip'], info['netmask']
    # Otherwise prompt
    print("Available network interfaces:")
    for idx, (iface, info) in enumerate(interfaces.items(), start=1):
        print(f"  [{idx}] {iface} — {info['ip']}")
    choice = None
    while choice not in range(1, len(interfaces) + 1):
        try:
            choice = int(input("Select interface by number: "))
        except ValueError:
            pass
    sel_iface = list(interfaces.keys())[choice - 1]
    info = interfaces[sel_iface]
    return sel_iface, info['ip'], info['netmask']

def detect_subnet(ip, netmask=None):
    try:
        if netmask and netmask != '255.255.255.255':
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        else:
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        return network
    except Exception as e:
        raise ValueError(f"Error calculating subnet: {repr(e)}")
