#!/usr/bin/env python3
"""
Utility functions: DNS resolution, favicon hashing.
"""
import asyncio
import socket
import requests
import hashlib
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

async def dns_resolves(host, loop):
    """
    Quick DNS pre-check to avoid wasting time on dead subdomains.
    Returns True if the host resolves to at least one IP address.
    """
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=3)
        return True
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return False

def get_favicon_hash(domain):
    """Download favicon over HTTPS, fallback to HTTP, and return MD5 hash."""
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{domain}/favicon.ico", timeout=5, verify=False)
            if resp.status_code == 200 and resp.content:
                return hashlib.md5(resp.content).hexdigest()[:8]
        except:
            continue
    return "N/A"
