from datetime import datetime, timezone
import socket
import ssl

FREE_DV_ISSUERS = {"Let's Encrypt", 'ZeroSSL', 'cPanel, Inc.', 'Certum'}


def deep_audit_ssl(hostname: str, matched_brand: str | None, findings: list) -> dict:
    """
    Performs deep SSL certificate inspection:
    - Calculates certificate age in hours (flags certs < 24h old).
    - Detects automated free DV certificates on high-value brand lures.
    - Inspects Subject Alternative Names (SANs).
    """
    if not hostname:
        return {'sslActive': False, 'error': 'No hostname provided'}

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    cert = None
    try:
        with socket.create_connection((hostname, 443), timeout=2.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:
        return {'sslActive': False, 'error': str(exc)}

    if not cert:
        return {'sslActive': False, 'error': 'No certificate received'}

    # 1. Parse notBefore & compute age in hours
    not_before_str = cert.get('notBefore')
    age_hours = None
    is_very_recent = False
    if not_before_str:
        try:
            not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - not_before).total_seconds() / 3600.0
            if age_hours < 24.0:
                is_very_recent = True
                findings.append({
                    'type': 'VERY_RECENT_SSL_CERT',
                    'flagged': True,
                    'explanation': (
                        f"SSL certificate was issued only {age_hours:.1f} hours ago. "
                        'Phishing sites frequently generate fresh certificates right before sending attack lures.'
                    ),
                })
        except Exception:
            pass

    # 2. Issuer check
    issuer_dict = {}
    for rdn in cert.get('issuer', []):
        for item in rdn:
            if isinstance(item, (tuple, list)):
                if len(item) == 2 and isinstance(item[0], str):
                    issuer_dict[item[0]] = item[1]
                elif len(item) == 1 and isinstance(item[0], (tuple, list)) and len(item[0]) == 2:
                    issuer_dict[item[0][0]] = item[0][1]

    org_name = issuer_dict.get('organizationName', '')
    is_free_dv = any(f in org_name for f in FREE_DV_ISSUERS)

    if matched_brand and is_free_dv:
        findings.append({
            'type': 'FREE_SSL_ON_BRAND_LURE',
            'flagged': True,
            'explanation': (
                f"The site impersonates brand '{matched_brand}' but uses a free Domain-Validated ({org_name}) "
                'certificate. Legitimate enterprise platforms do not use free automated certificates.'
            ),
        })

    # 3. SAN Analysis
    san_entries = [entry[1] for entry in cert.get('subjectAltName', []) if entry[0] == 'DNS']

    return {
        'sslActive': True,
        'certAgeHours': round(age_hours, 1) if age_hours is not None else None,
        'isVeryRecent': is_very_recent,
        'issuerOrg': org_name,
        'isFreeDv': is_free_dv,
        'sanCount': len(san_entries),
        'subjectAltNames': san_entries[:10],
    }
