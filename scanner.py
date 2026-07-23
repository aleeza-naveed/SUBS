#!/usr/bin/env python3
"""
Port scanner with banner grabbing.
"""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import TOP_PORTS

def scan_port(host, port):
    """Attempt to connect to a port and grab a service banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        if result == 0:
            banner = ""
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode(errors='replace').strip().replace('\n', ' ')[:80]
            except (socket.timeout, socket.error, UnicodeDecodeError):
                banner = "Service listening (no banner grabbed)"
            sock.close()
            return (port, banner)
        sock.close()
    except (socket.error, OSError):
        pass
    return None

def scan_ports_parallel(host):
    """Scan top ports using threads for speed."""
    open_ports = {}
    print(f"[*] SUBS scanning top ports on {host}...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, host, p): p for p in TOP_PORTS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                port, banner = result
                open_ports[port] = banner
    print(f"[+] SUBS found {len(open_ports)} open ports.")
    return open_ports
