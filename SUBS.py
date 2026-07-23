#!/usr/bin/env python3
"""
SUBS - Attack Surface Mapper
Main entry point - orchestrates all modules.
"""
import asyncio
import sys
import aiohttp

from subdomain import find_subdomains
from header_checker import check_http_headers
from report import generate_html_report

async def run_assessment(domain):
    """Orchestrate the entire vulnerability assessment."""
    print(f"[*] SUBS starting assessment for: {domain}")

    # Phase 1: Discover subdomains
    subdomains = find_subdomains(domain)
    if not subdomains:
        print("[-] SUBS found no subdomains. Exiting.")
        return

    # Prioritize and limit to top 20
    if len(subdomains) > 20:
        original_count = len(subdomains)
        priority_keywords = ['admin', 'api', 'dev', 'test', 'stage', 'portal', 'vpn', 'remote', 'backup']
        def priority_score(sub):
            sub_lower = sub.lower()
            for i, kw in enumerate(priority_keywords):
                if kw in sub_lower:
                    return i
            return 999
        subdomains.sort(key=priority_score)
        subdomains = subdomains[:20]
        print(f"[*] Truncated to top 20 prioritized subdomains (discovered {original_count} total).")
    else:
        print(f"[*] Scanning all {len(subdomains)} subdomains.")

    # Phase 2: Scan each subdomain
    print("[*] SUBS scanning assets asynchronously...")
    sem = asyncio.Semaphore(15)
    async with aiohttp.ClientSession() as session:
        tasks = [check_http_headers(session, sub, sem) for sub in subdomains]
        results = await asyncio.gather(*tasks)

    # Phase 3: Generate report
    generate_html_report(results, domain)
    print("[+] SUBS finished! Open the HTML report in your browser.")

# ==================== ENTRY POINT ====================
if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ███████╗██╗   ██╗██████╗ ███████╗                         ║
    ║   ██╔════╝██║   ██║██╔══██╗██╔════╝                         ║
    ║   ███████╗██║   ██║██████╔╝███████╗                         ║
    ║   ╚════██║██║   ██║██╔══██╗╚════██║                         ║
    ║   ███████║╚██████╔╝██████╔╝███████║                         ║
    ║   ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝                         ║
    ║                                                              ║
    ║   SUBS - Attack Surface Mapper & Vulnerability Assessor      ║
    ║   EDUCATIONAL USE ONLY - UNAUTHORIZED USE IS ILLEGAL        ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    sys.stdout.flush()

    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    else:
        TARGET = input("[?] Enter target domain (e.g., example.com): ").strip()
        if not TARGET:
            print("[-] No target provided. Exiting.")
            sys.exit(1)

    print(f"[*] Target set to: {TARGET}")
    asyncio.run(run_assessment(TARGET))
