#!/usr/bin/env python3
"""
Async HTTP header scanner with DNS pre-check, CDN detection, and CVE correlation.
"""
import asyncio
import aiohttp
import re
from concurrent.futures import ThreadPoolExecutor

from config import HEADER_EXPLANATIONS, TOP_PORTS
from utils import dns_resolves
from scanner import scan_ports_parallel
from ssl_checker import check_ssl
from cve_lookup import query_nvd
from cdn_detector import detect_cdn

# Dedicated executor for blocking calls
BLOCKING_EXECUTOR = ThreadPoolExecutor(max_workers=30)

async def check_http_headers(session, sub, sem):
    """Check for OWASP critical security headers with proper async, DNS pre-check, and CDN detection."""
    async with sem:
        result = {
            'sub': sub,
            'status': 'Error',
            'headers': {},
            'ssl_info': None,
            'open_ports': {},
            'cves': [],
            'final_url': sub,
            'http_version': None,
            'server_header': None,
            'cdn': None,
            'raw_headers': {}
        }
        loop = asyncio.get_running_loop()

        # ---- DNS PRE-CHECK ----
        if not await dns_resolves(sub, loop):
            result['status'] = 'Unreachable (DNS)'
            return result

        # HTTP/HTTPS phase
        try:
            url = f"https://{sub}"
            async with session.get(url, timeout=8, ssl=False, allow_redirects=True) as resp:
                result['status'] = resp.status
                result['final_url'] = str(resp.url)
                result['server_header'] = resp.headers.get('Server')
                result['raw_headers'] = dict(resp.headers)
                if hasattr(resp, 'version') and resp.version:
                    major, minor = resp.version
                    result['http_version'] = f"HTTP/{major}.{minor}"
                else:
                    result['http_version'] = "Unknown"
                critical = [
                    'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options',
                    'Content-Security-Policy', 'Referrer-Policy', 'Cross-Origin-Opener-Policy',
                    'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy'
                ]
                for h in critical:
                    if h in resp.headers:
                        result['headers'][h] = resp.headers[h]
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            try:
                url = f"http://{sub}"
                async with session.get(url, timeout=5, allow_redirects=True) as resp:
                    result['status'] = resp.status
                    result['final_url'] = str(resp.url)
                    result['headers']['NOTE'] = 'HTTP (insecure) only'
                    result['server_header'] = resp.headers.get('Server')
                    result['raw_headers'] = dict(resp.headers)
                    if hasattr(resp, 'version') and resp.version:
                        major, minor = resp.version
                        result['http_version'] = f"HTTP/{major}.{minor}"
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                result['status'] = 'Unreachable'
                return result

        # Detect CDN/edge before anything else uses server_header for CVE lookups
        result['cdn'] = detect_cdn(result['server_header'], result['raw_headers'])

        if 'https' in result.get('final_url', ''):
            result['ssl_info'] = await loop.run_in_executor(BLOCKING_EXECUTOR, check_ssl, sub)

        result['open_ports'] = await loop.run_in_executor(BLOCKING_EXECUTOR, scan_ports_parallel, sub)

        # ---- CVE extraction (skip CDN Server headers) ----
        cve_sources = []
        if result['server_header'] and not result['cdn']:
            m = re.match(r'([A-Za-z0-9\-_.]+)/([0-9][0-9A-Za-z.\-]*)', result['server_header'])
            if m:
                cve_sources.append((m.group(1).lower(), m.group(2)))

        for port, banner in result['open_ports'].items():
            if port in (80, 443, 8080, 8443):
                continue
            m = re.match(r'([A-Za-z0-9\-_.]+)[/\s]+([0-9][0-9A-Za-z.\-]*)', banner)
            if m:
                software, version = m.group(1).lower(), m.group(2)
                if software not in ['http', 'service', 'head']:
                    cve_sources.append((software, version))

        seen = set()
        for software, version in cve_sources:
            key = f"{software}_{version}"
            if key in seen:
                continue
            seen.add(key)
            cves = await loop.run_in_executor(BLOCKING_EXECUTOR, query_nvd, software, version)
            if cves and isinstance(cves, list) and not (len(cves) == 1 and 'error' in cves[0]):
                result['cves'].extend(cves)
                result['cves'] = result['cves'][:15]

        return result
