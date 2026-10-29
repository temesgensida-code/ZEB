"""
sandbox_preview.py — Static sandbox URL safety analyser.

All analysis is purely passive (HTTP GET + HTML parsing). No JavaScript is
executed, no files are written to disk, and no system calls are made, making
this module safe to run inside a restricted sandbox environment.

New checks added on top of the original:
  • SSL/TLS certificate validation (expiry, hostname mismatch, self-signed)
  • HTTP security-header audit (CSP, HSTS, X-Frame-Options, …)
  • Redirect-chain analysis (cross-scheme downgrades, too many hops)
  • Hidden iframe / invisible overlay detection
  • Meta-refresh redirect detection
  • Homograph / punycode domain attack detection
  • URL path entropy scoring (high-entropy paths signal generated URLs)
  • Data-URI abuse in scripts and iframes
  • Risk score aggregation (0–100) returned alongside raw findings
"""

from __future__ import annotations

import math
import re
import socket
import ssl
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
import tldextract
from bs4 import BeautifulSoup

from .common import detect_typosquatting_brand, is_ip_host, is_ip_like_host
from .constants import (
    EXFILTRATION_SINK_PATTERNS,
    SANDBOX_HTML_LIMIT,
    SANDBOX_KEYWORDS,
    SUSPICIOUS_SCRIPT_PATTERNS,
    SUSPICIOUS_TLDS,
)
from .dom_inspection import dom_inspection_manager

# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

# Maximum number of redirect hops before we flag the chain as suspicious.
_MAX_SAFE_REDIRECTS = 3

# SSL certificate expiry warning window (days).
_CERT_EXPIRY_WARNING_DAYS = 14

# Minimum entropy (bits/char) that we consider "high-entropy" for a URL path.
_HIGH_ENTROPY_THRESHOLD = 3.8

# Minimum path length before entropy is evaluated (very short paths are noisy).
_MIN_ENTROPY_PATH_LEN = 12

# Risk weights assigned to each finding type (summed → clamped to 0-100).
_RISK_WEIGHTS: dict[str, int] = {
    'SANDBOX_PREVIEW_UNAVAILABLE':        0,
    'SANDBOX_NON_HTML_CONTENT':           5,
    'SANDBOX_PHISHING_KEYWORDS':         20,
    'SANDBOX_FAKE_LOGIN_FORM_SIGNAL':    25,
    'SANDBOX_SUSPICIOUS_SCRIPT_SIGNAL':  20,
    'SANDBOX_SSL_ISSUE':                 20,
    'SANDBOX_WEAK_SECURITY_HEADERS':      8,
    'SANDBOX_SUSPICIOUS_REDIRECT_CHAIN': 15,
    'SANDBOX_HIDDEN_IFRAME':             20,
    'SANDBOX_META_REFRESH_REDIRECT':     15,
    'SANDBOX_HOMOGRAPH_DOMAIN':          25,
    'SANDBOX_HIGH_ENTROPY_URL':          10,
    'SANDBOX_DATA_URI_ABUSE':            20,
    'EXFILTRATION_SINK_DETECTED':        50,
    'CROSS_ORIGIN_CREDENTIAL_FORM':      35,
    'RAW_IP_FORM_ACTION':                25,
    'INSECURE_HTTP_CREDENTIAL_FORM':     35,
    'EXCESSIVE_IDENTITY_HARVESTING':     30,
    'REALTIME_OTP_HARVESTING_LURE':      25,
    'CLICKJACKING_OVERLAY_TRAP':         25,
    'WEB3_BLIND_SIGN_DRAINER':           40,
    'WEB3_NFT_APPROVAL_DRAINER':         35,
    'WEB3_PERMIT2_ALLOWANCE_DRAINER':    35,
    'DANGEROUS_EXECUTABLE_DOWNLOAD':     40,
    'DOUBLE_EXTENSION_DECEPTION':        45,
    'AUTOMATED_DRIVE_BY_DOWNLOAD':       30,
}

# Security response headers we expect on trustworthy sites.
_EXPECTED_SECURITY_HEADERS = [
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
]


# ---------------------------------------------------------------------------
# Helper utilities (all pure / side-effect-free)
# ---------------------------------------------------------------------------

def _shannon_entropy(text: str) -> float:
    """Return the Shannon entropy (bits per character) of *text*."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_punycode_or_homograph(hostname: str) -> bool:
    """
    Return True if *hostname* contains punycode labels (xn--…) or mixed
    Unicode scripts that are a common technique in homograph attacks.
    """
    labels = hostname.split('.')
    for label in labels:
        # Direct punycode encoding
        if label.lower().startswith('xn--'):
            return True
        # Mixed scripts within a single label (e.g. Latin + Cyrillic)
        try:
            scripts = {unicodedata.name(ch, '').split()[0]
                       for ch in label if not ch.isascii()}
        except Exception:
            scripts = set()
        if len(scripts) > 1:
            return True
    return False


def _check_ssl_certificate(hostname: str, port: int = 443) -> list[dict]:
    """
    Perform a passive TLS handshake to inspect the certificate.
    Returns a list of issue dicts (empty if the cert looks fine).
    No data is sent beyond the handshake; the connection is closed immediately.
    """
    issues: list[dict] = []
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        issues.append({'issue': 'certificate_verification_failed', 'detail': str(exc)})
        return issues
    except ssl.SSLError as exc:
        issues.append({'issue': 'ssl_error', 'detail': str(exc)})
        return issues
    except OSError:
        # Port unreachable or timeout — not necessarily malicious; skip SSL check.
        return issues

    # Check expiry
    not_after_str = cert.get('notAfter', '')
    if not_after_str:
        try:
            not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z').replace(
                tzinfo=timezone.utc
            )
            days_left = (not_after - datetime.now(timezone.utc)).days
            if days_left < 0:
                issues.append({'issue': 'certificate_expired', 'detail': f'expired {-days_left} day(s) ago'})
            elif days_left < _CERT_EXPIRY_WARNING_DAYS:
                issues.append({
                    'issue': 'certificate_expiring_soon',
                    'detail': f'expires in {days_left} day(s)',
                })
        except ValueError:
            pass  # Unrecognised date format — skip

    return issues


def _analyse_redirect_chain(response: requests.Response) -> list[dict]:
    """
    Inspect the redirect history attached to a *requests.Response* object.
    Returns a list of suspicious hop descriptors.
    """
    issues: list[dict] = []
    history = list(response.history) + [response]

    if len(response.history) > _MAX_SAFE_REDIRECTS:
        issues.append({
            'issue': 'excessive_redirects',
            'detail': f'{len(response.history)} redirect(s) before final destination',
        })

    for i in range(len(history) - 1):
        from_url = history[i].url
        to_url = history[i + 1].url
        from_scheme = urlparse(from_url).scheme
        to_scheme = urlparse(to_url).scheme
        if from_scheme == 'https' and to_scheme == 'http':
            issues.append({
                'issue': 'https_to_http_downgrade',
                'detail': f'redirect from {from_url!r} downgrades to plain HTTP',
            })

    return issues


def _analyse_security_headers(headers: requests.structures.CaseInsensitiveDict) -> list[str]:
    """Return a list of missing (expected) security response headers."""
    lower_keys = {k.lower() for k in headers}
    return [h for h in _EXPECTED_SECURITY_HEADERS if h not in lower_keys]


def _detect_hidden_iframes(soup: BeautifulSoup) -> list[dict]:
    """
    Find iframes that are hidden via inline style, zero dimensions,
    or display:none — a common technique for invisible tracking/redirect frames.
    """
    hidden: list[dict] = []
    for iframe in soup.find_all('iframe'):
        src = (iframe.get('src') or '').strip()
        reasons: list[str] = []

        style = (iframe.get('style') or '').lower().replace(' ', '')
        if 'display:none' in style or 'visibility:hidden' in style:
            reasons.append('iframe hidden via CSS display/visibility')

        width = iframe.get('width', '')
        height = iframe.get('height', '')
        try:
            if int(width) == 0 or int(height) == 0:
                reasons.append('iframe has zero pixel dimensions')
        except (ValueError, TypeError):
            pass

        if reasons:
            hidden.append({'src': src or 'no-src', 'reasons': reasons})
    return hidden


def _detect_meta_refresh(soup: BeautifulSoup) -> list[str]:
    """Return a list of URLs that meta-refresh tags would redirect to."""
    targets: list[str] = []
    for meta in soup.find_all('meta'):
        http_equiv = (meta.get('http-equiv') or '').strip().lower()
        if http_equiv != 'refresh':
            continue
        content = (meta.get('content') or '')
        match = re.search(r'url\s*=\s*["\']?([^"\'\s>]+)', content, re.IGNORECASE)
        if match:
            targets.append(match.group(1))
    return targets


def _detect_data_uri_abuse(soup: BeautifulSoup) -> list[dict]:
    """
    Detect data: URIs in script src or iframe src attributes — a way to
    embed executable code without an external fetch.
    """
    abuses: list[dict] = []
    for tag in soup.find_all(['script', 'iframe']):
        src = (tag.get('src') or '').strip()
        if src.lower().startswith('data:'):
            abuses.append({'tag': tag.name, 'snippet': src[:80]})
    return abuses


def _url_path_entropy(url: str) -> float | None:
    """
    Return the Shannon entropy of the URL path+query, or None if the path is
    too short to be meaningful.
    """
    parsed = urlparse(url)
    path_and_query = (parsed.path or '') + (parsed.query or '')
    stripped = re.sub(r'[/?=&\-_.]', '', path_and_query)
    if len(stripped) < _MIN_ENTROPY_PATH_LEN:
        return None
    return _shannon_entropy(stripped)


def audit_dom_forms(soup: BeautifulSoup, page_url: str, findings: list) -> dict:
    """
    Audits all HTML <form> tags for credential harvesting, cross-origin targets,
    and exfiltration sinks (Telegram, Discord, Google Forms, Formspree, etc.).
    """
    parsed_page = urlparse(page_url)
    page_host = (parsed_page.hostname or '').lower()
    page_registered = tldextract.extract(page_host).registered_domain.lower() if page_host else ''

    audited_forms: list[dict] = []
    exfiltration_sinks: list[dict] = []

    for form in soup.find_all('form'):
        method = (form.get('method') or 'GET').upper()
        action_raw = (form.get('action') or '').strip()
        action_url = urljoin(page_url, action_raw) if action_raw else page_url
        action_parsed = urlparse(action_url)
        action_host = (action_parsed.hostname or '').lower()
        action_registered = tldextract.extract(action_host).registered_domain.lower() if action_host else ''

        inputs = form.find_all(['input', 'textarea', 'select'])
        has_password = any((inp.get('type') or '').lower() == 'password' for inp in inputs)
        sensitive_fields: list[str] = []

        for inp in inputs:
            inp_type = (inp.get('type') or '').lower()
            inp_name = (inp.get('name') or '').lower()
            inp_id = (inp.get('id') or '').lower()
            field_ident = f"{inp_name} {inp_id}"

            if inp_type == 'password':
                sensitive_fields.append('password')
            elif any(k in field_ident for k in ('cvv', 'cvc', 'card', 'creditcard', 'expir')):
                sensitive_fields.append('payment_card')
            elif any(k in field_ident for k in ('ssn', 'socialsecurity', 'social_security')):
                sensitive_fields.append('ssn')
            elif any(k in field_ident for k in ('pin', 'passcode', 'otp', '2fa', 'token')):
                sensitive_fields.append('otp_pin')

        is_cross_origin = bool(page_registered and action_registered and page_registered != action_registered)
        is_raw_ip = is_ip_host(action_host) or is_ip_like_host(action_host)
        is_sink = False
        sink_type = None

        # Check exfiltration sink patterns
        for pattern, label in EXFILTRATION_SINK_PATTERNS:
            if re.search(pattern, action_url, re.IGNORECASE):
                is_sink = True
                sink_type = label
                break

        form_meta = {
            'action': action_url,
            'method': method,
            'hasPasswordField': has_password,
            'sensitiveFields': list(set(sensitive_fields)),
            'isCrossOrigin': is_cross_origin,
            'isRawIp': is_raw_ip,
            'isExfiltrationSink': is_sink,
            'sinkType': sink_type,
        }
        audited_forms.append(form_meta)

        if is_sink:
            exfiltration_sinks.append(form_meta)
            findings.append({
                'type': 'EXFILTRATION_SINK_DETECTED',
                'flagged': True,
                'explanation': (
                    f"CRITICAL: Form submits data directly to known exfiltration sink '{sink_type}' "
                    f"at '{action_url}'. Attackers use this to silently exfiltrate stolen credentials."
                ),
            })

        if is_raw_ip:
            findings.append({
                'type': 'RAW_IP_FORM_ACTION',
                'flagged': True,
                'explanation': f"Form submits data to a raw IP address '{action_host}', bypassing DNS domain controls.",
            })

        if is_cross_origin and (has_password or sensitive_fields):
            findings.append({
                'type': 'CROSS_ORIGIN_CREDENTIAL_FORM',
                'flagged': True,
                'explanation': (
                    f"Form collecting credentials submits across origins from '{page_host}' to '{action_host}'. "
                    'Legitimate platforms almost never submit user passwords to foreign external domains.'
                ),
            })

    # External assets extraction
    external_assets: list[str] = []
    external_domains: set[str] = set()

    for tag in soup.find_all(['script', 'iframe', 'a', 'link', 'img']):
        src = tag.get('src') or tag.get('href') or ''
        if src and not src.startswith(('data:', 'javascript:', '#')):
            full_asset = urljoin(page_url, src)
            h = (urlparse(full_asset).hostname or '').lower()
            if h and page_registered:
                asset_reg = tldextract.extract(h).registered_domain.lower()
                if asset_reg and asset_reg != page_registered:
                    external_assets.append(full_asset)
                    external_domains.add(asset_reg)

    return {
        'forms': audited_forms,
        'exfiltrationSinks': exfiltration_sinks,
        'externalAssetCount': len(external_assets),
        'externalAssetDomains': sorted(list(external_domains)),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_sandbox_preview(preview_url: str, findings: list) -> dict:
    """
    Fetch *preview_url* passively and run a battery of static safety checks.

    Parameters
    ----------
    preview_url : str
        The URL to inspect.
    findings : list
        Mutable list; finding dicts are appended in-place so callers can
        accumulate findings across multiple checks.

    Returns
    -------
    dict
        Keys:
          available          – bool, whether the URL was reachable
          htmlAnalyzed       – bool, whether HTML analysis ran
          fetchedUrl         – str | None, final URL after redirects
          redirectChain      – list[str], all URLs visited
          matchedKeywords    – list[str]
          fakeLoginForms     – list[dict]
          suspiciousScripts  – list[dict]
          hiddenIframes      – list[dict]          [NEW]
          metaRefreshUrls    – list[str]           [NEW]
          dataUriAbuses      – list[dict]          [NEW]
          sslIssues          – list[dict]          [NEW]
          missingSecHeaders  – list[str]           [NEW]
          redirectIssues     – list[dict]          [NEW]
          urlEntropyScore    – float | None        [NEW]
          riskScore          – int (0–100)         [NEW]
    """

    # ------------------------------------------------------------------
    # 1. Pre-flight: URL-level checks that need no network request
    # ------------------------------------------------------------------
    parsed_input = urlparse(preview_url)
    input_host = (parsed_input.hostname or '').lower()

    homograph_flag = False
    if input_host and _is_punycode_or_homograph(input_host):
        homograph_flag = True
        findings.append({
            'type': 'SANDBOX_HOMOGRAPH_DOMAIN',
            'flagged': True,
            'explanation': (
                f"The domain '{input_host}' uses punycode or mixed Unicode scripts, "
                'a technique commonly used in homograph phishing attacks.'
            ),
        })

    url_entropy = _url_path_entropy(preview_url)
    high_entropy_flag = url_entropy is not None and url_entropy >= _HIGH_ENTROPY_THRESHOLD
    if high_entropy_flag:
        findings.append({
            'type': 'SANDBOX_HIGH_ENTROPY_URL',
            'flagged': True,
            'explanation': (
                f'URL path has a high entropy score ({url_entropy:.2f} bits/char), '
                'which is typical of randomly generated phishing or tracking URLs.'
            ),
        })

    # ------------------------------------------------------------------
    # 2. SSL certificate check (passive TLS handshake only)
    # ------------------------------------------------------------------
    ssl_issues: list[dict] = []
    if input_host and parsed_input.scheme == 'https':
        port = parsed_input.port or 443
        ssl_issues = _check_ssl_certificate(input_host, port)
        if ssl_issues:
            findings.append({
                'type': 'SANDBOX_SSL_ISSUE',
                'flagged': True,
                'explanation': (
                    'SSL/TLS certificate problems were detected: '
                    + '; '.join(i['issue'] for i in ssl_issues) + '.'
                ),
            })

    # ------------------------------------------------------------------
    # 3. Fetch the page
    # ------------------------------------------------------------------
    try:
        response = requests.get(
            preview_url,
            allow_redirects=True,
            timeout=12,
            headers={
                'User-Agent': 'zeb-url-checker-sandbox/1.0',
                'Accept': 'text/html,application/xhtml+xml',
            },
        )
    except requests.RequestException as exc:
        findings.append({
            'type': 'SANDBOX_PREVIEW_UNAVAILABLE',
            'flagged': False,
            'explanation': (
                f'Sandbox HTML preview could not be fetched ({type(exc).__name__}). '
                'No JavaScript was executed during this attempt.'
            ),
        })
        risk_score = _compute_risk_score(findings)
        return {
            'available': False,
            'htmlAnalyzed': False,
            'fetchedUrl': None,
            'redirectChain': [],
            'matchedKeywords': [],
            'fakeLoginForms': [],
            'suspiciousScripts': [],
            'hiddenIframes': [],
            'metaRefreshUrls': [],
            'dataUriAbuses': [],
            'sslIssues': ssl_issues,
            'missingSecHeaders': [],
            'redirectIssues': [],
            'urlEntropyScore': url_entropy,
            'riskScore': risk_score,
            'linkXRay': {
                'forms': [],
                'externalAssetCount': 0,
                'hiddenIframesCount': 0,
                'exfiltrationSinksDetected': [],
            },
            'payloadInspection': {
                'credentialHarvester': {
                    'isHttpLogin': False,
                    'hasPasswordInput': False,
                    'sensitiveInputsFound': [],
                },
                'clickjacking': {
                    'hasClickjackingOverlays': False,
                    'overlayCount': 0,
                    'overlays': [],
                },
                'web3Drainer': {
                    'hasWeb3DrainerSignatures': False,
                    'detectedSignatures': [],
                },
                'driveByDownload': {
                    'isExecutableDownload': False,
                    'isDoubleExtension': False,
                    'downloadFilename': None,
                    'contentType': '',
                    'autoDownloadAnchors': [],
                },
            },
        }

    # ------------------------------------------------------------------
    # 4. Redirect chain analysis
    # ------------------------------------------------------------------
    redirect_chain = [r.url for r in response.history] + [response.url]
    redirect_issues = _analyse_redirect_chain(response)
    if redirect_issues:
        findings.append({
            'type': 'SANDBOX_SUSPICIOUS_REDIRECT_CHAIN',
            'flagged': True,
            'explanation': (
                'The URL redirect chain raised concerns: '
                + '; '.join(i['issue'] for i in redirect_issues) + '.'
            ),
        })

    # ------------------------------------------------------------------
    # 5. Security headers audit
    # ------------------------------------------------------------------
    missing_sec_headers = _analyse_security_headers(response.headers)
    # Only flag if more than half the expected headers are absent (reduces noise
    # for simple static sites that omit some optional headers).
    if len(missing_sec_headers) > len(_EXPECTED_SECURITY_HEADERS) // 2:
        findings.append({
            'type': 'SANDBOX_WEAK_SECURITY_HEADERS',
            'flagged': True,
            'explanation': (
                'The server response is missing several important security headers: '
                + ', '.join(missing_sec_headers) + '.'
            ),
        })

    # ------------------------------------------------------------------
    # 6. HTML content-type guard
    # ------------------------------------------------------------------
    content_type = (response.headers.get('Content-Type') or response.headers.get('content-type') or '').lower()
    if 'html' not in content_type:
        findings.append({
            'type': 'SANDBOX_NON_HTML_CONTENT',
            'flagged': False,
            'explanation': (
                'Final destination did not return HTML content, '
                'so form/script/keyword analysis was skipped.'
            ),
        })
        risk_score = _compute_risk_score(findings)
        return {
            'available': True,
            'htmlAnalyzed': False,
            'fetchedUrl': response.url,
            'redirectChain': redirect_chain,
            'matchedKeywords': [],
            'fakeLoginForms': [],
            'suspiciousScripts': [],
            'hiddenIframes': [],
            'metaRefreshUrls': [],
            'dataUriAbuses': [],
            'sslIssues': ssl_issues,
            'missingSecHeaders': missing_sec_headers,
            'redirectIssues': redirect_issues,
            'urlEntropyScore': url_entropy,
            'riskScore': risk_score,
            'linkXRay': {
                'forms': [],
                'externalAssetCount': 0,
                'hiddenIframesCount': 0,
                'exfiltrationSinksDetected': [],
            },
            'payloadInspection': {
                'credentialHarvester': {
                    'isHttpLogin': False,
                    'hasPasswordInput': False,
                    'sensitiveInputsFound': [],
                },
                'clickjacking': {
                    'hasClickjackingOverlays': False,
                    'overlayCount': 0,
                    'overlays': [],
                },
                'web3Drainer': {
                    'hasWeb3DrainerSignatures': False,
                    'detectedSignatures': [],
                },
                'driveByDownload': {
                    'isExecutableDownload': False,
                    'isDoubleExtension': False,
                    'downloadFilename': None,
                    'contentType': '',
                    'autoDownloadAnchors': [],
                },
            },
        }

    # ------------------------------------------------------------------
    # 7. Parse HTML
    # ------------------------------------------------------------------
    html = response.text[:SANDBOX_HTML_LIMIT]
    soup = BeautifulSoup(html, 'html.parser')
    page_text = soup.get_text(' ', strip=True).lower()
    page_host = (urlparse(response.url).hostname or '').lower()
    page_registered = tldextract.extract(page_host).registered_domain.lower() if page_host else ''

    # ------------------------------------------------------------------
    # 8. Phishing keyword scan
    # ------------------------------------------------------------------
    matched_keywords = [kw for kw in SANDBOX_KEYWORDS if kw in page_text]
    if matched_keywords:
        findings.append({
            'type': 'SANDBOX_PHISHING_KEYWORDS',
            'flagged': True,
            'explanation': (
                'Page content includes high-pressure phishing wording '
                f"({', '.join(matched_keywords[:3])})."
            ),
        })

    # ------------------------------------------------------------------
    # 9. Form Action & Link X-Ray Audit (Sub-Pillar 1.3)
    # ------------------------------------------------------------------
    dom_audit = audit_dom_forms(soup, response.url, findings)
    fake_login_forms: list[dict] = []

    for form in soup.find_all('form'):
        inputs = form.find_all('input')
        has_password = any((inp.get('type') or '').lower() == 'password' for inp in inputs)
        if not has_password:
            continue

        action_raw = (form.get('action') or '').strip()
        action_url = urljoin(response.url, action_raw) if action_raw else response.url
        action_parsed = urlparse(action_url)
        action_host = (action_parsed.hostname or '').lower()

        reasons: list[str] = []

        if action_parsed.scheme == 'http':
            reasons.append('submits credentials over insecure HTTP')

        if page_host and action_host and page_host != action_host:
            reasons.append('submits credentials to a different domain')

        if action_raw.lower().startswith('data:'):
            reasons.append('form action is a data: URI — credentials would be captured inline')

        autocomplete = (form.get('autocomplete') or '').lower()
        if autocomplete == 'off':
            reasons.append('autocomplete disabled on credential form (hides from password managers)')

        form_text = form.get_text(' ', strip=True).lower()
        if any(kw in form_text for kw in SANDBOX_KEYWORDS):
            reasons.append('uses urgent verification language near credential fields')

        # Check for exfiltration sinks
        for pattern, label in EXFILTRATION_SINK_PATTERNS:
            if re.search(pattern, action_url, re.IGNORECASE):
                reasons.append(f"exfiltrates credentials to known sink '{label}'")
                break

        if reasons:
            fake_login_forms.append({'actionUrl': action_url, 'reasons': reasons})

    if fake_login_forms and not any(f.get('type') == 'EXFILTRATION_SINK_DETECTED' for f in findings):
        findings.append({
            'type': 'SANDBOX_FAKE_LOGIN_FORM_SIGNAL',
            'flagged': True,
            'explanation': (
                'Sandbox preview found suspicious login form behaviour, '
                'such as cross-domain or insecure credential submission.'
            ),
        })

    # ------------------------------------------------------------------
    # 10. Suspicious script analysis (enhanced)
    # ------------------------------------------------------------------
    suspicious_scripts: list[dict] = []
    for script in soup.find_all('script'):
        reasons: list[str] = []
        src = (script.get('src') or '').strip()

        if src:
            # NEW: data: URI in script src
            if src.lower().startswith('data:'):
                reasons.append('script src is a data: URI — executable code embedded without network fetch')
            else:
                script_url = urljoin(response.url, src)
                hostname = (urlparse(script_url).hostname or '').lower()
                if hostname:
                    extracted = tldextract.extract(hostname)
                    if is_ip_host(hostname) or is_ip_like_host(hostname):
                        reasons.append('script loaded from an IP-based host')
                    if extracted.suffix and extracted.suffix.split('.')[-1] in SUSPICIOUS_TLDS:
                        reasons.append('script source uses a suspicious top-level domain')
                    brand = detect_typosquatting_brand(extracted.domain.lower())
                    if brand:
                        reasons.append(f"script host resembles typo of '{brand}'")
                    # NEW: check script host for homograph/punycode
                    if _is_punycode_or_homograph(hostname):
                        reasons.append('script host uses punycode/homograph encoding')
                    # NEW: SRI missing for cross-origin scripts
                    script_host_root = f"{extracted.domain}.{extracted.suffix}"
                    page_extracted = tldextract.extract(page_host)
                    page_host_root = f"{page_extracted.domain}.{page_extracted.suffix}"
                    if script_host_root != page_host_root and not script.get('integrity'):
                        reasons.append('cross-origin script loaded without Subresource Integrity (SRI) check')
        else:
            inline_code = script.get_text(' ', strip=True)
            if inline_code:
                inline_lower = inline_code.lower()
                for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
                    if re.search(pattern, inline_lower):
                        reasons.append('inline script contains obfuscation-like JavaScript pattern')
                        break
                # NEW: high-entropy inline string detection (Base64 blobs, encoded payloads)
                long_strings = re.findall(r'["\']([A-Za-z0-9+/=]{60,})["\']', inline_code)
                if long_strings:
                    avg_entropy = sum(_shannon_entropy(s) for s in long_strings) / len(long_strings)
                    if avg_entropy >= _HIGH_ENTROPY_THRESHOLD:
                        reasons.append(
                            'inline script contains long high-entropy string(s) — possible encoded payload'
                        )

        if reasons:
            suspicious_scripts.append({'source': src or 'inline', 'reasons': reasons})

    if suspicious_scripts:
        findings.append({
            'type': 'SANDBOX_SUSPICIOUS_SCRIPT_SIGNAL',
            'flagged': True,
            'explanation': (
                'Sandbox preview found suspicious script patterns or script sources '
                'commonly associated with obfuscation or malicious redirects.'
            ),
        })

    # ------------------------------------------------------------------
    # 11. Hidden iframe detection  [NEW]
    # ------------------------------------------------------------------
    hidden_iframes = _detect_hidden_iframes(soup)
    if hidden_iframes:
        findings.append({
            'type': 'SANDBOX_HIDDEN_IFRAME',
            'flagged': True,
            'explanation': (
                f'Found {len(hidden_iframes)} hidden iframe(s) — commonly used for '
                'invisible redirects, clickjacking overlays, or credential harvesting.'
            ),
        })

    # ------------------------------------------------------------------
    # 12. Meta-refresh redirect detection  [NEW]
    # ------------------------------------------------------------------
    meta_refresh_urls = _detect_meta_refresh(soup)
    if meta_refresh_urls:
        findings.append({
            'type': 'SANDBOX_META_REFRESH_REDIRECT',
            'flagged': True,
            'explanation': (
                f'Page uses meta-refresh to redirect to: '
                + ', '.join(meta_refresh_urls[:3])
                + '. This technique is used to silently forward victims.'
            ),
        })

    # ------------------------------------------------------------------
    # 13. Data-URI abuse detection  [NEW]
    # ------------------------------------------------------------------
    data_uri_abuses = _detect_data_uri_abuse(soup)
    if data_uri_abuses:
        findings.append({
            'type': 'SANDBOX_DATA_URI_ABUSE',
            'flagged': True,
            'explanation': (
                f'Found {len(data_uri_abuses)} script/iframe element(s) using data: URIs '
                'to embed executable or framed content without an external resource fetch.'
            ),
        })

    # ------------------------------------------------------------------
    # 14. Deep DOM & Payload Inspection (Pillar 5)
    # ------------------------------------------------------------------
    payload_inspection = dom_inspection_manager.evaluate(
        soup=soup,
        response_headers=dict(response.headers) if response else {},
        page_url=response.url,
        registered_domain=page_registered,
        findings=findings,
    )

    # ------------------------------------------------------------------
    # 15. Aggregate risk score
    # ------------------------------------------------------------------
    risk_score = _compute_risk_score(findings)

    return {
        'available': True,
        'htmlAnalyzed': True,
        'fetchedUrl': response.url,
        'redirectChain': redirect_chain,
        'matchedKeywords': matched_keywords,
        'fakeLoginForms': fake_login_forms,
        'suspiciousScripts': suspicious_scripts,
        'hiddenIframes': hidden_iframes,
        'metaRefreshUrls': meta_refresh_urls,
        'dataUriAbuses': data_uri_abuses,
        'sslIssues': ssl_issues,
        'missingSecHeaders': missing_sec_headers,
        'redirectIssues': redirect_issues,
        'urlEntropyScore': url_entropy,
        'riskScore': risk_score,
        'linkXRay': {
            'forms': dom_audit['forms'],
            'externalAssetCount': dom_audit['externalAssetCount'],
            'hiddenIframesCount': len(hidden_iframes),
            'exfiltrationSinksDetected': dom_audit['exfiltrationSinks'],
        },
        'payloadInspection': payload_inspection,
    }


# ---------------------------------------------------------------------------
# Risk score helper
# ---------------------------------------------------------------------------

def _compute_risk_score(findings: list[dict]) -> int:
    """
    Sum the weights of all *flagged* findings and clamp the result to [0, 100].
    """
    total = sum(
        _RISK_WEIGHTS.get(f['type'], 0)
        for f in findings
        if f.get('flagged')
    )
    return min(total, 100)
