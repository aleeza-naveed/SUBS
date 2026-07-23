#!/usr/bin/env python3
"""
Configuration module - loads API keys and constants.
"""
import os
import sys
import getpass

# ==================== VIEWDNS API KEY ====================
def get_viewdns_api_key():
    """Prompt for ViewDNS API key (hidden input)."""
    print("[!] ViewDNS.info API key required to discover subdomains.")
    print("[!] Get a free key at: https://viewdns.info/signup/")
    print("[!] After signing up, go to the 'API' tab to generate your key.")
    print("[!] Your key will be hidden as you type.")
    key = ""
    try:
        key = getpass.getpass("[?] Enter your ViewDNS API key: ").strip()
    except Exception:
        print("[!] Hidden input unavailable. Using visible input.")
        key = input("[?] Enter your ViewDNS API key: ").strip()
    if not key:
        print("[-] No API key provided.")
        retry = input("[?] Try again? (y/n): ").strip().lower()
        if retry == 'y':
            return get_viewdns_api_key()
        else:
            print("[-] Exiting.")
            sys.exit(1)
    print(f"[+] API key accepted (length: {len(key)} characters).")
    return key

VIEWDNS_API_KEY = get_viewdns_api_key()

# ==================== NVD API KEY ====================
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
if NVD_API_KEY:
    print("[+] NVD API key loaded from environment.")
else:
    print("[!] NVD API key not set. Using public rate-limited API (5 req/30s).")
    print("[!] Get a free key at: https://nvd.nist.gov/developers/request-an-api-key")

# ==================== CONSTANTS ====================
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
             993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

HEADER_EXPLANATIONS = {
    'Strict-Transport-Security': "Forces browsers to use HTTPS only. Prevents SSL stripping and man-in-the-middle attacks.",
    'X-Frame-Options': "Prevents clickjacking attacks where a malicious site embeds your page in an invisible frame.",
    'X-Content-Type-Options': "Prevents MIME-sniffing attacks where browsers execute malicious files disguised as harmless types.",
    'Content-Security-Policy': "Prevents Cross-Site Scripting (XSS) by controlling which resources the browser can load.",
    'Referrer-Policy': "Prevents leakage of sensitive URL paths (e.g., /admin/dashboard) to external sites.",
    'Cross-Origin-Opener-Policy': "Prevents cross-origin attacks like Spectre by isolating your page from other windows.",
    'Cross-Origin-Embedder-Policy': "Prevents cross-origin data leakage by restricting embedded resources.",
    'Cross-Origin-Resource-Policy': "Controls which websites can load your resources, preventing side-channel attacks."
}
