import re
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


def analyze_sandbox_preview(preview_url: str, findings: list) -> dict:
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
    except requests.RequestException:
        findings.append(
            {
                'type': 'SANDBOX_PREVIEW_UNAVAILABLE',
                'flagged': False,
                'explanation': (
                    'Sandbox HTML preview could not be fetched. '
                    'No JavaScript was executed during this attempt.'
                ),
            }
        )
        return {
            'available': False,
            'htmlAnalyzed': False,
            'fetchedUrl': None,
            'matchedKeywords': [],
            'fakeLoginForms': [],
            'suspiciousScripts': [],
        }

    content_type = response.headers.get('Content-Type', '').lower()
    if 'html' not in content_type:
        findings.append(
            {
                'type': 'SANDBOX_NON_HTML_CONTENT',
                'flagged': False,
                'explanation': (
                    'Final destination did not return HTML content, '
                    'so form/script/keyword analysis was skipped.'
                ),
            }
        )
        return {
            'available': True,
            'htmlAnalyzed': False,
            'fetchedUrl': response.url,
            'matchedKeywords': [],
            'fakeLoginForms': [],
            'suspiciousScripts': [],
        }

    html = response.text[:SANDBOX_HTML_LIMIT]
    soup = BeautifulSoup(html, 'html.parser')
    page_text = soup.get_text(' ', strip=True).lower()
    matched_keywords = [keyword for keyword in SANDBOX_KEYWORDS if keyword in page_text]

    fake_login_forms = []
    page_host = (urlparse(response.url).hostname or '').lower()
    for form in soup.find_all('form'):
        inputs = form.find_all('input')
        has_password = any((item.get('type') or '').lower() == 'password' for item in inputs)
        if not has_password:
            continue

        action_raw = (form.get('action') or '').strip()
        action_url = urljoin(response.url, action_raw) if action_raw else response.url
        action_parsed = urlparse(action_url)
        action_host = (action_parsed.hostname or '').lower()

        reasons = []
        if action_parsed.scheme == 'http':
            reasons.append('submits credentials over insecure HTTP')
        if page_host and action_host and page_host != action_host:
            reasons.append('submits credentials to a different domain')

        form_text = form.get_text(' ', strip=True).lower()
        if any(keyword in form_text for keyword in SANDBOX_KEYWORDS):
            reasons.append('uses urgent verification language near credential fields')

        if reasons:
            fake_login_forms.append(
                {
                    'actionUrl': action_url,
                    'reasons': reasons,
                }
            )

    suspicious_scripts = []
    for script in soup.find_all('script'):
        reasons = []
        src = (script.get('src') or '').strip()

        if src:
            script_url = urljoin(response.url, src)
            hostname = (urlparse(script_url).hostname or '').lower()
            if hostname:
                extracted = tldextract.extract(hostname)
                if is_ip_host(hostname) or is_ip_like_host(hostname):
                    reasons.append('script is loaded from an IP-based host')
                if extracted.suffix and extracted.suffix.split('.')[-1] in SUSPICIOUS_TLDS:
                    reasons.append('script source uses suspicious top-level domain')
                brand = detect_typosquatting_brand(extracted.domain.lower())
                if brand:
                    reasons.append(f"script host resembles typo of '{brand}'")
        else:
            inline_code = script.get_text(' ', strip=True).lower()
            if inline_code:
                for pattern in SUSPICIOUS_SCRIPT_PATTERNS:
                    if re.search(pattern, inline_code):
                        reasons.append('inline script contains obfuscation-like JavaScript pattern')
                        break

        if reasons:
            suspicious_scripts.append(
                {
                    'source': src or 'inline',
                    'reasons': reasons,
                }
            )

    if matched_keywords:
        findings.append(
            {
                'type': 'SANDBOX_PHISHING_KEYWORDS',
                'flagged': True,
                'explanation': (
                    'Page content includes high-pressure phishing wording '
                    f"({', '.join(matched_keywords[:3])})."
                ),
            }
        )

    if fake_login_forms:
        findings.append(
            {
                'type': 'SANDBOX_FAKE_LOGIN_FORM_SIGNAL',
                'flagged': True,
                'explanation': (
                    'Sandbox preview found suspicious login form behavior, '
                    'such as cross-domain or insecure credential submission.'
                ),
            }
        )

    if suspicious_scripts:
        findings.append(
            {
                'type': 'SANDBOX_SUSPICIOUS_SCRIPT_SIGNAL',
                'flagged': True,
                'explanation': (
                    'Sandbox preview found suspicious script patterns or script sources '
                    'commonly associated with obfuscation or malicious redirects.'
                ),
            }
        )

    return {
        'available': True,
        'htmlAnalyzed': True,
        'fetchedUrl': response.url,
        'matchedKeywords': matched_keywords,
        'fakeLoginForms': fake_login_forms,
        'suspiciousScripts': suspicious_scripts,
    }
