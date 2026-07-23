#!/usr/bin/env python3
"""
CDN detection module.
"""
CDN_SIGNATURES = {
    'cloudflare': 'Cloudflare',
    'akamai': 'Akamai',
    'akamaighost': 'Akamai',
    'fastly': 'Fastly',
    'cloudfront': 'Amazon CloudFront',
    'sucuri': 'Sucuri',
    'incapsula': 'Imperva Incapsula',
    'imperva': 'Imperva',
    'x-sucuri-id': 'Sucuri',
}

def detect_cdn(server_header, all_headers=None):
    """
    Best-effort CDN/edge detection from the Server header and,
    as a fallback, other CDN-specific headers that show up even
    when Server is blank or generic.
    """
    if server_header:
        s = server_header.lower()
        for sig, name in CDN_SIGNATURES.items():
            if sig in s:
                return name

    if all_headers:
        headers_lower = {k.lower(): v for k, v in all_headers.items()}
        if 'cf-ray' in headers_lower or 'cf-cache-status' in headers_lower:
            return 'Cloudflare'
        if 'x-amz-cf-id' in headers_lower:
            return 'Amazon CloudFront'
        if 'x-akamai-transformed' in headers_lower:
            return 'Akamai'
        if 'x-sucuri-id' in headers_lower or 'x-sucuri-cache' in headers_lower:
            return 'Sucuri'

    return None
