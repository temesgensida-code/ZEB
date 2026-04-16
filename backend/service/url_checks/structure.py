from urllib.parse import urlparse

import tldextract

from .common import detect_typosquatting_brand, is_ip_host, is_ip_like_host
from .constants import SUSPICIOUS_TLDS
from .domain_age import analyze_domain_age
from .redirect_chain import analyze_redirect_chain
from .sandbox_preview import analyze_sandbox_preview


def analyze_url_structure(target_url: str) -> dict:
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or '').lower()

    tld = ''
    registered_domain = ''
    registered_domain_full = ''
    if hostname:
        extracted = tldextract.extract(hostname)
        tld = extracted.suffix.lower()
        registered_domain = extracted.domain.lower()
        registered_domain_full = extracted.registered_domain.lower()

    has_ip_host = (is_ip_host(hostname) or is_ip_like_host(hostname)) if hostname else False
    is_suspicious_tld = tld.split('.')[-1] in SUSPICIOUS_TLDS if tld else False

    typosquatting_match = detect_typosquatting_brand(registered_domain)
    has_typosquatting_signal = typosquatting_match is not None

    findings = []
    if has_ip_host:
        findings.append(
            {
                'type': 'IP_BASED_URL',
                'flagged': True,
                'explanation': (
                    'The URL uses an IP address instead of a readable domain name. '
                    'Attackers often do this to hide identity and quickly rotate hosts.'
                ),
            }
        )

    if is_suspicious_tld:
        findings.append(
            {
                'type': 'SUSPICIOUS_TLD',
                'flagged': True,
                'explanation': (
                    f"The top-level domain '.{tld.split('.')[-1]}' is frequently abused "
                    'in phishing and scam campaigns due to low registration friction.'
                ),
            }
        )

    if has_typosquatting_signal:
        findings.append(
            {
                'type': 'TYPOSQUATTING_SIGNAL',
                'flagged': True,
                'explanation': (
                    f"The domain looks like a typo variant of '{typosquatting_match}' "
                    'for example letter substitution like faceb00k, '
                    'which is a common credential-harvesting trick.'
                ),
            }
        )

    domain_age = analyze_domain_age(registered_domain_full, findings)
    redirect_analysis = analyze_redirect_chain(target_url, registered_domain_full, findings)
    sandbox_preview = analyze_sandbox_preview(
        redirect_analysis['finalUrl'] or target_url,
        findings,
    )

    if not findings:
        findings.append(
            {
                'type': 'NO_STRONG_STRUCTURE_SIGNALS',
                'flagged': False,
                'explanation': (
                    'No strong URL structure red flags were detected, '
                    'but this still does not prove the destination is safe.'
                ),
            }
        )

    return {
        'isIpBased': has_ip_host,
        'hasSuspiciousTld': is_suspicious_tld,
        'hasTyposquattingSignal': has_typosquatting_signal,
        'hasNewDomainRisk': bool(domain_age['isNewDomain']),
        'hasRedirectRisk': bool(
            redirect_analysis['tooManyRedirects']
            or len(redirect_analysis['suspiciousRedirectHops']) > 0
        ),
        'hasSandboxContentRisk': bool(
            len(sandbox_preview['matchedKeywords']) > 0
            or len(sandbox_preview['fakeLoginForms']) > 0
            or len(sandbox_preview['suspiciousScripts']) > 0
        ),
        'hostname': hostname,
        'tld': tld,
        'registeredDomain': registered_domain,
        'registeredDomainFull': registered_domain_full,
        'domainAge': domain_age,
        'redirectAnalysis': redirect_analysis,
        'sandboxPreview': sandbox_preview,
        'findings': findings,
    }
