#!/usr/bin/env python3
"""
HTML report generator.
"""
import datetime
from config import HEADER_EXPLANATIONS
from utils import get_favicon_hash

def generate_html_report(all_results, domain):
    """
    Create a beautiful, self-contained HTML dashboard.
    Filename includes a timestamp to prevent overwrites.
    """
    safe_domain = domain.replace('.', '_')
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{safe_domain}_subs_report_{timestamp}.html"

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>SUBS Report - {domain}</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {{ background: #f0f2f5; padding: 20px; }}
            .container {{ max-width: 1600px; }}
            .header-badge {{ background: #1a1a2e; color: white; padding: 25px; border-radius: 12px; margin-bottom: 30px; text-align: center; }}
            .asset-card {{
                margin-bottom: 25px;
                border-radius: 10px;
                background: white;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
                border-left: 6px solid #6c757d;
                transition: transform 0.1s ease;
                height: 100%;
            }}
            .asset-card:hover {{ transform: translateY(-3px); box-shadow: 0 8px 20px rgba(0,0,0,0.12); }}
            .card-critical {{ border-left-color: #dc3545; }}
            .card-high {{ border-left-color: #fd7e14; }}
            .card-medium {{ border-left-color: #ffc107; }}
            .card-low {{ border-left-color: #198754; }}
            .card-unreachable {{ border-left-color: #adb5bd; opacity: 0.85; }}

            .card-header-custom {{
                padding: 12px 20px;
                background: #f8f9fa;
                border-bottom: 1px solid #e9ecef;
                border-radius: 10px 10px 0 0 !important;
                display: flex;
                justify-content: space-between;
                align-items: center;
                flex-wrap: wrap;
            }}
            .card-body-custom {{ padding: 20px; }}

            .priority-badge {{
                padding: 4px 12px;
                border-radius: 20px;
                font-weight: bold;
                font-size: 0.8rem;
                color: white;
            }}
            .badge-critical {{ background: #dc3545; }}
            .badge-high {{ background: #fd7e14; }}
            .badge-medium {{ background: #ffc107; color: black; }}
            .badge-low {{ background: #198754; }}
            .badge-na {{ background: #6c757d; }}

            .section-title {{
                font-weight: 600;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                color: #495057;
                margin-bottom: 8px;
                border-bottom: 1px solid #dee2e6;
                padding-bottom: 4px;
            }}
            .port-list {{
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                margin-bottom: 10px;
            }}
            .port-item {{
                background: #e9ecef;
                padding: 4px 12px;
                border-radius: 15px;
                font-size: 0.85rem;
                font-family: monospace;
                border: 1px solid #ced4da;
            }}
            .port-banner {{
                color: #495057;
                font-size: 0.8rem;
                font-style: italic;
            }}
            .header-present {{
                background: #d4edda;
                color: #155724;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 0.8rem;
                margin: 2px;
                display: inline-block;
                border: 1px solid #c3e6cb;
            }}
            .header-missing {{
                background: #f8d7da;
                color: #721c24;
                padding: 3px 10px;
                border-radius: 12px;
                font-size: 0.8rem;
                margin: 2px;
                display: inline-block;
                border: 1px solid #f5c6cb;
            }}
            .header-explanation {{
                background: #fff3cd;
                color: #856404;
                padding: 4px 10px;
                border-radius: 8px;
                font-size: 0.8rem;
                margin: 4px 0 8px 2px;
                display: block;
                border-left: 3px solid #856404;
            }}
            .cve-item {{
                background: #fff3cd;
                border-left: 4px solid #856404;
                padding: 8px 12px;
                margin-bottom: 6px;
                border-radius: 4px;
                font-size: 0.9rem;
            }}
            .cve-id {{ color: #721c24; font-weight: bold; }}
            .subdomain-host {{ font-size: 1.1rem; font-weight: 600; color: #1a1a2e; word-break: break-all; }}
            .status-code {{
                font-weight: 500;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.8rem;
            }}
            .status-success {{ background: #d4edda; color: #155724; }}
            .status-redirect {{ background: #cce5ff; color: #004085; }}
            .status-error {{ background: #f8d7da; color: #721c24; }}
            .status-unreachable {{ background: #e2e3e5; color: #383d41; }}
            .sensitive-badge {{ background: #dc3545; color: white; padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; display: inline-block; margin-top: 4px; }}
            .cdn-badge {{ background: #0dcaf0; color: #000; padding: 4px 10px; border-radius: 12px; font-size: 0.8rem; display: inline-block; margin-top: 4px; font-weight: 600; }}
            .advisory-box {{
                background: #fff3cd;
                border-left: 4px solid #856404;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 0.85rem;
                color: #856404;
                margin-top: 8px;
            }}
        </style>
    </head>
    <body>
    <div class="container">
        <div class="header-badge">
            <h1 style="font-family: monospace; letter-spacing: 3px;">⬡ SUBS - Attack Surface Mapper</h1>
            <h4 class="mt-2">Target: <code>{domain}</code> | Assets Discovered: <span class="badge bg-primary">{len(all_results)}</span></h4>
            <p class="mb-0"><i>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</i></p>
            <p class="mt-2"><span class="badge bg-danger">EDUCATIONAL USE ONLY - AUTHORIZED TESTING REQUIRED</span></p>
        </div>

        <div class="row">
    """

    for item in all_results:
        sub = item.get('sub', 'Unknown')
        status = item.get('status', 'N/A')
        headers = item.get('headers', {})
        ssl_data = item.get('ssl_info', None)
        ports = item.get('open_ports', {})
        cves = item.get('cves', [])
        http_version = item.get('http_version', 'N/A')
        cdn = item.get('cdn', None)
        cve_count = len(cves)

        # ----- ENHANCED RISK SCORING -----
        critical_list = [
            'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options',
            'Content-Security-Policy', 'Referrer-Policy', 'Cross-Origin-Opener-Policy',
            'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy'
        ]
        present_names = [h for h in critical_list if h in headers]
        missing_count = 8 - len(present_names) if status not in ['Unreachable', 'Unreachable (DNS)'] else 0

        weak_tls_flag = bool(ssl_data and isinstance(ssl_data, dict) and ssl_data.get('weak_tls'))

        risky_ports = {21, 23, 139, 445, 3306, 3389, 5900}
        exposed_risky_ports = [p for p in ports.keys() if p in risky_ports]
        risky_port_penalty = len(exposed_risky_ports) * 2

        risk_score = (cve_count * 3) + missing_count + (5 if weak_tls_flag else 0) + risky_port_penalty

        # ----- PRIORITY LOGIC (Critical / High / Medium / Low) -----
        is_unreachable = status in ['Unreachable', 'Unreachable (DNS)']
        if is_unreachable:
            card_class = "card-unreachable"
            priority_label = "N/A"
            priority_badge_class = "badge-na"
            status_class = "status-unreachable"
        else:
            if str(status).startswith('2'):
                status_class = "status-success"
            elif str(status).startswith('3'):
                status_class = "status-redirect"
            else:
                status_class = "status-error"

            if risk_score >= 15:
                priority_label = "Critical"
                priority_badge_class = "badge-critical"
                card_class = "card-critical"
            elif risk_score >= 8:
                priority_label = "High"
                priority_badge_class = "badge-high"
                card_class = "card-high"
            elif risk_score >= 3:
                priority_label = "Medium"
                priority_badge_class = "badge-medium"
                card_class = "card-medium"
            else:
                priority_label = "Low"
                priority_badge_class = "badge-low"
                card_class = "card-low"

        # ---- UNREACHABLE ADVISORY ----
        unreachable_advisory = ""
        if is_unreachable:
            unreachable_advisory = f'''
            <div class="advisory-box">
                <strong>ⓘ Advisory:</strong> This host could not be reached during the assessment.
                If you believe this asset should be accessible, please verify network connectivity,
                DNS resolution, and firewall rules that may be restricting access.
            </div>
            '''

        # ---- RENDER SENSITIVE PORTS ----
        sensitive_html = ""
        if exposed_risky_ports:
            port_badges = ", ".join(str(p) for p in sorted(exposed_risky_ports))
            sensitive_html = f'''
            <div class="mt-2">
                <span class="sensitive-badge">⚠️ Sensitive ports exposed: {port_badges}</span>
            </div>
            '''

        # ---- RENDER CDN NOTICE ----
        cdn_notice_html = ""
        if cdn:
            cdn_notice_html = f'''
            <div class="mb-2">
                <span class="cdn-badge">🛡️ Behind {cdn}</span>
                <span class="text-muted" style="font-size:0.78rem;"> — TLS/port/banner findings below reflect the {cdn} edge, not necessarily the origin server</span>
            </div>
            '''

        # ---- SSL BADGE ----
        ssl_badge_html = ""
        tls_warning_html = ""
        if is_unreachable:
            ssl_badge_html = '<span class="badge bg-secondary">Host Unreachable</span>'
        elif ssl_data and isinstance(ssl_data, dict):
            if 'error' in ssl_data:
                ssl_badge_html = f'<span class="badge bg-warning text-dark">SSL Error</span>'
            elif ssl_data.get('expired', False):
                ssl_badge_html = '<span class="badge bg-danger">SSL Expired!</span>'
            else:
                ssl_badge_html = f'<span class="badge bg-success">SSL Valid ({ssl_data.get("expiry_days", "N/A")} days left)</span>'
            if ssl_data.get('weak_tls'):
                tls_warning_html = '<span class="badge bg-danger ms-2">TLS 1.0 Supported (VULNERABLE)</span>'
        else:
            ssl_badge_html = '<span class="badge bg-secondary">No HTTPS</span>'

        # ---- FAVICON HASH ----
        fav_hash = get_favicon_hash(sub)

        # ---- OPEN PORTS ----
        ports_html = ""
        if ports:
            ports_html = '<div class="port-list">'
            for p, banner in ports.items():
                ports_html += f'<span class="port-item"><b>{p}</b> <span class="port-banner">({banner[:60]})</span></span>'
            ports_html += '</div>'
        else:
            ports_html = '<span class="text-muted">No open ports detected in top 20 scan.</span>'

        # ---- SECURITY HEADERS ----
        present_headers = {h: headers[h] for h in present_names}
        missing_names = [h for h in critical_list if h not in present_names]

        headers_html = ""
        if is_unreachable:
            headers_html = '<span class="text-muted">Host unreachable, headers not checked.</span>'
        else:
            if present_names:
                headers_html += '<div><b>Present:</b> '
                for h in present_names:
                    headers_html += f'<span class="header-present">{h}: {present_headers[h][:60]}</span>'
                headers_html += '</div>'
            if missing_names:
                headers_html += '<div class="mt-1"><b>Missing:</b> '
                for h in missing_names:
                    explanation = HEADER_EXPLANATIONS.get(h, "Security header missing.")
                    headers_html += f'''
                    <span class="header-missing">{h}</span>
                    <span class="header-explanation">⚠️ {explanation}</span>
                    '''
                headers_html += '</div>'
            if not present_names and not missing_names:
                headers_html = '<span class="text-muted">No standard headers checked.</span>'

        # ---- CVEs (with CDN-aware messaging) ----
        cves_html = ""
        if cves:
            for cve in cves[:15]:
                cves_html += f'''
                <div class="cve-item">
                    <span class="cve-id">{cve.get('cve_id', 'N/A')}</span>
                    <span class="badge bg-danger ms-2">CVSS: {cve.get('score', 'N/A')}</span>
                    <br><small>{cve.get('description', '')}</small>
                </div>
                '''
            cves_html += f'<small class="text-muted">(Showing {min(15, len(cves))} of {len(cves)} total CVEs, newest first)</small>'
        elif cdn:
            cves_html = f'<span class="text-muted">CVE lookup skipped — {cdn} edge has no version-bearing Server header to match against.</span>'
        else:
            cves_html = '<span class="text-success">✓ No known CVEs detected from banners.</span>'

        # ---- HTTP VERSION ----
        http_version_html = ""
        if not is_unreachable and http_version != 'N/A':
            if http_version == "HTTP/1.0":
                http_version_html = f'<span class="badge bg-danger">{http_version} (Obsolete/Insecure)</span>'
            else:
                http_version_html = f'<span class="badge bg-secondary">{http_version}</span>'

        # ---- BUILD CARD ----
        html += f'''
        <div class="col-xl-4 col-lg-6 col-md-6 col-sm-12">
            <div class="asset-card {card_class}">
                <div class="card-header-custom">
                    <span class="subdomain-host">{sub}</span>
                    <div>
                        <span class="status-code {status_class}">{status}</span>
                        <span class="priority-badge {priority_badge_class} ms-1">{priority_label}</span>
                    </div>
                </div>
                <div class="card-body-custom">
                    {cdn_notice_html}
                    {unreachable_advisory}
                    <div class="mb-2">
                        <b>Protocol:</b> {http_version_html}
                    </div>
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span>{ssl_badge_html} {tls_warning_html}</span>
                        <span><b>Favicon Hash:</b> <code>{fav_hash}</code></span>
                    </div>
                    <div class="section-title">🔌 Open Ports & Banners</div>
                    {ports_html}
                    {sensitive_html}
                    <div class="section-title mt-3">🛡️ Security Headers ({len(present_names)} present / {len(missing_names)} missing)</div>
                    {headers_html}
                    <div class="section-title mt-3">📦 CVEs Detected ({cve_count} total)</div>
                    {cves_html}
                </div>
            </div>
        </div>
        '''

    html += """
        </div>
    </div>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] ✅ SUBS HTML Report generated: {filename}")
