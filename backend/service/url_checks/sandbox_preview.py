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
    SANDBOX_HTML_LIMIT,
    SANDBOX_KEYWORDS,
    SUSPICIOUS_SCRIPT_PATTERNS,
    SUSPICIOUS_TLDS,
)

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
    # Strip common low-entropy separators before measuring
    stripped = re.sub(r'[/?=&\-_.]', '', path_and_query)
    if len(stripped) < _MIN_ENTROPY_PATH_LEN:
        return None
    return _shannon_entropy(stripped)


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
    content_type = response.headers.get('Content-Type', '').lower()
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
        }

    # ------------------------------------------------------------------
    # 7. Parse HTML
    # ------------------------------------------------------------------
    html = response.text[:SANDBOX_HTML_LIMIT]
    soup = BeautifulSoup(html, 'html.parser')
    page_text = soup.get_text(' ', strip=True).lower()
    page_host = (urlparse(response.url).hostname or '').lower()

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
    # 9. Fake login form detection (enhanced)
    # ------------------------------------------------------------------
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

        # NEW: action points to a data: URI
        if action_raw.lower().startswith('data:'):
            reasons.append('form action is a data: URI — credentials would be captured inline')

        # NEW: autocomplete disabled (hides from password managers — phishing signal)
        autocomplete = (form.get('autocomplete') or '').lower()
        if autocomplete == 'off':
            reasons.append('autocomplete disabled on credential form (hides from password managers)')

        form_text = form.get_text(' ', strip=True).lower()
        if any(kw in form_text for kw in SANDBOX_KEYWORDS):
            reasons.append('uses urgent verification language near credential fields')

        if reasons:
            fake_login_forms.append({'actionUrl': action_url, 'reasons': reasons})

    if fake_login_forms:
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
    # 14. Aggregate risk score
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
