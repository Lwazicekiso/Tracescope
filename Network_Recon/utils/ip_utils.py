# utils/ip_utils.py

import socket
import ipaddress

def get_local_ip():
    """
    Determines the local IP address by opening a UDP socket to a public server.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # The address doesn’t need to be reachable; it’s just for the socket to pick the right interface.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def get_subnet(ip=None, netmask=None):
    """
    Returns an ipaddress.IPv4Network object for the local subnet.
    - If ip is None, auto-detects local IP.
    - If netmask provided (e.g. '255.255.255.0' or '24'), uses it; otherwise defaults to /24.
    """
    if ip is None:
        ip = get_local_ip()

    # Normalize netmask
    if netmask:
        # allow '255.255.255.0' or '24'
        if '/' not in netmask and '.' in netmask:
            net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        else:
            net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    else:
        # assume /24 if nothing else
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)

    return net
