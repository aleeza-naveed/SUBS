#!/usr/bin/env python3
"""
SSL/TLS certificate auditor.
"""
import ssl
import socket
import datetime

def check_ssl(host):
    """Check SSL certificate expiry and weak TLS versions."""
    findings = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.datetime.now()).days
                findings['expiry_days'] = days_left
                findings['expired'] = days_left < 0
                findings['subject'] = cert.get('subject', [])
                findings['negotiated_protocol'] = ssock.version()

                weak_tls = []
                try:
                    ctx10 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx10.check_hostname = False
                    ctx10.verify_mode = ssl.CERT_NONE
                    ctx10.minimum_version = ssl.TLSVersion.TLSv1
                    ctx10.maximum_version = ssl.TLSVersion.TLSv1
                    with socket.create_connection((host, 443), timeout=3) as s:
                        with ctx10.wrap_socket(s, server_hostname=host) as ss:
                            if ss.version() == "TLSv1":
                                weak_tls.append("TLS 1.0 supported (VULNERABLE)")
                except (ssl.SSLError, OSError):
                    pass
                findings['weak_tls'] = weak_tls
                return findings
    except Exception as e:
        return {"error": f"SSL Check failed: {str(e)}"}
