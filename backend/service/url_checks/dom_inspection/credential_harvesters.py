import re
from bs4 import BeautifulSoup

SENSITIVE_INPUT_PATTERNS = {
    'SSN': re.compile(r'(?:ssn|social[-_]?sec|tax[-_]?id|national[-_]?id|sin[-_]?num)', re.IGNORECASE),
    'CARD_NUMBER': re.compile(r'(?:card[-_]?num|cc[-_]?num|credit[-_]?card|pan[-_]?number)', re.IGNORECASE),
    'CVV': re.compile(r'(?:cvv|cvc|security[-_]?code|card[-_]?code|cid)', re.IGNORECASE),
    'EXPIRY': re.compile(r'(?:exp[-_]?date|card[-_]?exp|cc[-_]?exp|exp[-_]?month)', re.IGNORECASE),
    'OTP_2FA': re.compile(r'(?:otp|2fa|verification[-_]?code|sms[-_]?code|auth[-_]?code|one[-_]?time)', re.IGNORECASE),
    'PIN': re.compile(r'(?:atm[-_]?pin|card[-_]?pin|pin[-_]?code|secret[-_]?pin)', re.IGNORECASE),
    'MAIDEN_NAME': re.compile(r'(?:mother[-_]?maiden|maiden[-_]?name|birth[-_]?place)', re.IGNORECASE),
}


def audit_credential_harvesters(
    soup: BeautifulSoup,
    page_url: str,
    registered_domain: str,
    findings: list,
) -> dict:
    """
    Audits input fields for sensitive credential/identity markers and unencrypted logins.
    """
    is_http = page_url.lower().startswith('http://')
    has_password = bool(soup.find('input', attrs={'type': re.compile(r'^password$', re.I)}))

    # 1. Unencrypted password guard
    if is_http and has_password:
        findings.append({
            'type': 'INSECURE_HTTP_CREDENTIAL_FORM',
            'flagged': True,
            'explanation': 'The login form transmits passwords over unencrypted HTTP, leaving credentials vulnerable to interception.',
        })

    # 2. Sensitive identity pattern scan
    detected_sensitive_types: list[str] = []
    all_inputs = soup.find_all(['input', 'select', 'textarea'])
    for tag in all_inputs:
        attrs_combined = (
            f"{tag.get('name', '')} {tag.get('id', '')} "
            f"{tag.get('placeholder', '')} {tag.get('autocomplete', '')}"
        )
        for cat_name, pattern in SENSITIVE_INPUT_PATTERNS.items():
            if pattern.search(attrs_combined):
                if cat_name not in detected_sensitive_types:
                    detected_sensitive_types.append(cat_name)

    # Flag excessive identity harvesting
    if (
        len(detected_sensitive_types) >= 2
        or ('SSN' in detected_sensitive_types)
        or ('PIN' in detected_sensitive_types)
    ):
        findings.append({
            'type': 'EXCESSIVE_IDENTITY_HARVESTING',
            'flagged': True,
            'explanation': (
                f"The page requests high-risk personal credentials ({', '.join(detected_sensitive_types)}). "
                'Unverified domains requesting this information are typical of credential harvesting and identity theft campaigns.'
            ),
        })

    # Flag OTP / 2FA interceptors
    if 'OTP_2FA' in detected_sensitive_types:
        findings.append({
            'type': 'REALTIME_OTP_HARVESTING_LURE',
            'flagged': True,
            'explanation': (
                'The page solicits one-time authentication codes (2FA/OTP), characteristic '
                'of real-time phishing proxies that hijack active multi-factor login sessions.'
            ),
        })

    return {
        'isHttpLogin': is_http and has_password,
        'hasPasswordInput': has_password,
        'sensitiveInputsFound': detected_sensitive_types,
    }


def audit_clickjacking_overlays(soup: BeautifulSoup, findings: list) -> dict:
    """
    Inspects inline styles and DOM attributes for transparent clickjacking overlays.
    """
    overlays_found = []
    candidates = soup.find_all(['div', 'iframe', 'a', 'span'], style=True)

    for el in candidates:
        style_str = el.get('style', '').lower().replace(' ', '')

        # Check for near-zero opacity
        is_transparent = (
            ('opacity:0' in style_str)
            or ('opacity:0.0' in style_str)
            or ('filter:alpha(opacity=0)' in style_str)
        )
        # Check for elevated z-index
        has_high_z = bool(re.search(r'z-index:\s*(?:[1-9]\d{3,}|999)', style_str))
        # Check for fixed or absolute positioning
        is_fixed = ('position:fixed' in style_str) or ('position:absolute' in style_str)

        if is_transparent and (has_high_z or is_fixed):
            overlays_found.append({
                'tag': el.name,
                'id': el.get('id'),
                'class': el.get('class'),
                'style': el.get('style')[:100],
            })

    if overlays_found:
        findings.append({
            'type': 'CLICKJACKING_OVERLAY_TRAP',
            'flagged': True,
            'explanation': (
                f'Detected {len(overlays_found)} transparent overlay container(s) with '
                'elevated z-index/fixed positioning, a signature indicator of clickjacking UI redressing attacks.'
            ),
        })

    return {
        'hasClickjackingOverlays': len(overlays_found) > 0,
        'overlayCount': len(overlays_found),
        'overlays': overlays_found[:5],
    }
