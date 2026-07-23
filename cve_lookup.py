#!/usr/bin/env python3
"""
NVD CVE lookup with caching and rate-limit handling.
"""
import time
import requests
from config import NVD_API_KEY

CVE_CACHE = {}

def query_nvd(service_name, version):
    """Query the NVD with API key, exponential backoff, no cache on failure."""
    cache_key = f"{service_name}_{version}"
    if cache_key in CVE_CACHE:
        cached = CVE_CACHE[cache_key]
        if isinstance(cached, list) and not (len(cached) == 1 and 'error' in cached[0]):
            return cached

    query = f"{service_name} {version}"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=15&sortBy=pubDate&sortOrder=desc"
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    findings = []

    for attempt in range(3):
        try:
            sleep_time = 0.6 if NVD_API_KEY else 6.0
            time.sleep(sleep_time)
            resp = requests.get(url, headers=headers, timeout=10)

            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', 10))
                print(f"[!] NVD rate limit hit. Retrying in {retry_after}s...")
                time.sleep(retry_after)
                continue

            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get('vulnerabilities', [])[:15]:
                    cve_data = vuln.get('cve', {})
                    cve_id = cve_data.get('id', 'N/A')
                    metrics = cve_data.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                    score = cvss_v3.get('baseScore', 'N/A')
                    desc_list = cve_data.get('descriptions', [])
                    desc = next((d.get('value', '')[:150] + "..."
                                 for d in desc_list if d.get('lang') == 'en'), "No description")
                    findings.append({
                        "cve_id": cve_id,
                        "score": score,
                        "description": desc
                    })
                break
            else:
                print(f"[-] NVD API error: {resp.status_code}")
        except Exception as e:
            print(f"[-] NVD API exception: {e}")
            if attempt == 2:
                return [{"error": f"NVD API failed: {str(e)}"}]
    else:
        return [{"error": "NVD API max retries exceeded"}]

    CVE_CACHE[cache_key] = findings
    return findings
