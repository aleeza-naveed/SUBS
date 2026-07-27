# ⬡ SUBS - ATTACK SURFACE MAPPER

> **Modular Attack Surface Mapper and Vulnerability Assessment Tool with CVE Correlation and HTML Reporting.**


##  DISCLAIMER!

**This tool is for EDUCATIONAL and AUTHORIZED testing only.**  
Unauthorized use against systems you do not own is **ILLEGAL**. Always obtain explicit written permission before scanning any system.

---

##  LICENSE

**EDUCATIONAL USE ONLY** — Not for commercial use without explicit permission.

---

##  FEATURES
| Feature | Description |
| :--- | :--- |
| **Subdomain Discovery** | ViewDNS.info API integration with DNS pre-check to eliminate dead hosts |
| **Asynchronous Scanning** | 15 concurrent scans with async/await for maximum speed |
|  **Port Scanning** | Top 20 TCP ports with banner grabbing (2-second timeout) |
| **Security Headers** | Checks 8 critical OWASP headers with plain-English explanations |
| **SSL/TLS Audit** | Certificate expiry validation and **true** TLS 1.0 detection |
| **CVE Correlation** | NVD API integration with caching, retry logic, and rate-limit handling |
| **CDN Detection** | Identifies Cloudflare, Akamai, Fastly, CloudFront, Sucuri, Imperva |
| **Risk Scoring** | CVE count × 3 + Missing Headers + Weak TLS (5 pts) + Sensitive Ports (×2) |
| **Priority Labels** | **Critical** / **High** / **Medium** / **Low** based on risk score |
| **HTML Report** | Timestamped, self-contained, color-coded dashboard |


---

## Project Structure

```
SUBS/
├── SUBS.py              # Main entry point (orchestrator)
├── config.py            # API key loading & constants
├── subdomain.py         # ViewDNS subdomain discovery
├── scanner.py           # Port scanning & banner grabbing
├── ssl_checker.py       # SSL/TLS auditing
├── cve_lookup.py        # NVD CVE queries with caching
├── header_checker.py    # Async HTTP header scanning
├── cdn_detector.py      # CDN identification
├── utils.py             # DNS pre-check & favicon hashing
├── report.py            # HTML report generator
└── requirements.txt     # Python dependencies
```

---

## INSTALLATION

```bash
# Clone the repository
git clone https://github.com/aleeza-naveed/SUBS.git
cd SUBS

# Install dependencies
pip install -r requirements.txt

#if the above command doesn't work use
sudo apt install python3-aiohttp python3-requests python3-urllib3
```

---

##  CONFIGURATION

### ViewDNS API Key (**Required**)
1. Sign up at [viewdns.info](https://viewdns.info/signup/)
2. Go to the **API** tab in your dashboard
3. Generate your API key
4. The tool will prompt you for this key at runtime

### NVD API Key (**Optional but recommended**)
To avoid rate limits, set an NVD API key as an environment variable:
```bash
export NVD_API_KEY="your_nvd_key_here"
```
Get a free key from [NVD](https://nvd.nist.gov/developers/request-an-api-key).

---

##  Usage

```bash
python3 SUBS.py example.com
```

### Interactive Mode
```bash
python3 SUBS.py
# You will be prompted to enter the target domain
```


## ⚙️ How It Works

1. **Subdomain Discovery** → Queries ViewDNS.info API for all subdomains
2. **DNS Pre-Check** → Filters dead hosts in under 1 second
3. **Async Scanning** → 15 subdomains scanned concurrently
4. **Port Scanning** → Top 20 ports with banner grabbing
5. **SSL Audit** → Certificate expiry + TLS 1.0 detection
6. **Header Analysis** → 8 OWASP security headers with explanations
7. **CVE Correlation** → NVD API lookups with caching
8. **CDN Detection** → Identifies edge services
9. **Risk Scoring** → Combined scoring for prioritization
10. **HTML Report** → Timestamped, self-contained dashboard

---
The Exact Flow for a Single Subdomain
1. **DNS Pre-check**
2. **HTTP/HTTPS Request** → Grabs Server header (8s max).
3. **Port Scan** → Scans 20 ports, grabs banners (2s max).
4. **CVE LookUp** → Extracts Apache/2.4.49 from the banner and queries the NVD API.
5. **Store CVEs** → Attaches the list to result['cves'].
6. **Return the result to the main orchestrator**.


---

##  Risk Scoring

| Factor | Points |
| :--- | :--- |
| **CVE Count** | × 3 per CVE |
| **Missing Headers** | 1 per missing header |
| **Weak TLS 1.0** | +5 if supported |
| **Sensitive Ports** | × 2 per port (21, 23, 139, 445, 3306, 3389, 5900) |


| Risk Score | Priority |
| :--- | :--- |
| 15+ | 🔴 Critical |
| 8–14 | 🟠 High |
| 3–7 | 🟡 Medium |
| 0–2 | 🟢 Low |
---

**Made with 🐍 Python and ☕ Caffeine**
