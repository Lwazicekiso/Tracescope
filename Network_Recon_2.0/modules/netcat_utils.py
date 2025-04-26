import socket

def grab_banner(host, port, payload=None):
    """
    Perform basic TCP banner grabbing on a given host and port.
    - host: IP or domain of the target.
    - port: TCP port number (int).
    - payload: Optional string or bytes to send after connecting (e.g., "GET / HTTP/1.0\r\n\r\n").
    Returns a dictionary with host, port, banner (response string), and error (if any).
    """
    print(f"[+] Connecting to {host}:{port}")
    banner = None
    error = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((host, port))
        if payload:
            # Ensure payload is bytes
            if isinstance(payload, str):
                payload = payload.encode()
            print(f"[+] Sending payload to {host}:{port}")
            s.sendall(payload)
        try:
            resp = s.recv(4096)
            if resp:
                # Decode bytes to string if possible
                try:
                    banner = resp.decode('utf-8', errors='ignore')
                except:
                    banner = str(resp)
        except socket.timeout:
            print("[-] Socket receive timed out.")
        s.close()
    except socket.timeout:
        error = "Connection timed out"
        print(f"[-] Connection to {host}:{port} timed out")
    except Exception as e:
        error = str(e)
        print(f"[-] Connection error: {e}")
    return {"host": host, "port": port, "banner": banner, "error": error}
