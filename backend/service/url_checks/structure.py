import logging
import unicodedata
from urllib.parse import urlparse

import idna
import tldextract

logger = logging.getLogger(__name__)

from .common import (
    decode_obfuscated_ip,
    detect_typosquatting_brand,
    extract_and_audit_userinfo,
    is_ip_host,
    is_ip_like_host,
)
from .constants import BRAND_KEYWORDS, HOMOGRAPH_CONFUSABLES, SUSPICIOUS_TLDS
from .domain_age import analyze_domain_age
from .dynamic_sandbox import dynamic_sandbox_manager
from .infrastructure import infrastructure_manager
from .redirect_chain import analyze_redirect_chain
from .sandbox_preview import analyze_sandbox_preview


def _get_script(char: str) -> str:
    """Classify Unicode script family from character name."""
    name = unicodedata.name(char, '')
    if name.startswith('CYRILLIC'):
        return 'Cyrillic'
    if name.startswith('GREEK'):
        return 'Greek'
    if name.startswith('LATIN'):
        return 'Latin'
    if name.startswith('ARABIC'):
        return 'Arabic'
    if name.startswith('HEBREW'):
        return 'Hebrew'
    if name.startswith('DEVANAGARI'):
        return 'Devanagari'
    return 'Common'


def analyze_idn_homographs(hostname: str) -> dict:
    """
    Performs Unicode TR39 script audit, extracts positional confusable glyphs,
    and returns dual Unicode/Punycode representations.
    """
    if not hostname:
        return {
            'isIdn': False,
            'punycode': '',
            'unicode': '',
            'hasMixedScript': False,
            'scriptHistogram': {},
            'confusableGlyphs': [],
            'skeleton': '',
        }

    raw = hostname.lower()
    is_idn = False
    try:
        if raw.startswith('xn--') or '.xn--' in raw:
            unicode_host = idna.decode(raw)
            punycode_host = raw
            is_idn = True
        elif any(ord(c) > 127 for c in raw):
            unicode_host = raw
            punycode_host = idna.encode(raw).decode('ascii')
            is_idn = True
        else:
            unicode_host = raw
            punycode_host = raw
    except Exception:
        unicode_host = raw
        punycode_host = raw

    script_counts: dict[str, int] = {}
    confusable_glyphs: list[dict] = []
    skeleton_chars: list[str] = []

    for idx, ch in enumerate(unicode_host):
        script = _get_script(ch)
        if script != 'Common':
            script_counts[script] = script_counts.get(script, 0) + 1

        if ch in HOMOGRAPH_CONFUSABLES:
            ascii_equiv = HOMOGRAPH_CONFUSABLES[ch]
            skeleton_chars.append(ascii_equiv)
            confusable_glyphs.append({
                'index': idx,
                'char': ch,
                'codepoint': f"U+{ord(ch):04X}",
                'script': script,
                'asciiReplacement': ascii_equiv,
            })
        else:
            skeleton_chars.append(ch)

    skeleton = "".join(skeleton_chars)
    distinct_scripts = set(script_counts.keys())
    has_mixed_script = len(distinct_scripts) >= 2

    return {
        'isIdn': is_idn,
        'punycode': punycode_host,
        'unicode': unicode_host,
        'hasMixedScript': has_mixed_script,
        'scriptHistogram': script_counts,
        'confusableGlyphs': confusable_glyphs,
        'skeleton': skeleton,
    }


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

    # De-obfuscation: Check for alternative numeric IP encodings
    decoded_ip, ip_obf_type = decode_obfuscated_ip(hostname) if hostname else (None, None)
    is_obfuscated_ip = ip_obf_type is not None

    # De-obfuscation: Check for deceptive RFC 3986 userinfo (user:pass@host)
    userinfo_data = extract_and_audit_userinfo(target_url)

    # De-obfuscation: IDN homograph and Unicode confusable audit
    idn_analysis = analyze_idn_homographs(hostname) if hostname else {}

    findings = []

    if userinfo_data.get('flagged'):
        findings.append(
            {
                'type': 'USERINFO_DECEPTION_ATTACK',
                'flagged': True,
                'explanation': userinfo_data['explanation'],
            }
        )

    if is_obfuscated_ip:
        findings.append(
            {
                'type': 'OBFUSCATED_IP_ADDRESS',
                'flagged': True,
                'explanation': (
                    f"The URL hostname '{hostname}' is an obfuscated {ip_obf_type} representation "
                    f"of IP address {decoded_ip}. Attackers use alternate IP encodings to bypass filters."
                ),
            }
        )
    elif has_ip_host:
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

    if idn_analysis.get('hasMixedScript'):
        scripts_joined = ', '.join(idn_analysis['scriptHistogram'].keys())
        findings.append(
            {
                'type': 'MIXED_SCRIPT_HOMOGRAPH',
                'flagged': True,
                'explanation': (
                    f"Internationalized Domain Name spoofing detected: Domain uses mixed Unicode scripts "
                    f"({scripts_joined}) containing confusable look-alike characters "
                    f"rendered as '{idn_analysis['unicode']}' (Punycode: {idn_analysis['punycode']})."
                ),
            }
        )
    elif idn_analysis.get('isIdn') and (
        idn_analysis.get('confusableGlyphs')
        or any(b in idn_analysis.get('skeleton', '') for b in BRAND_KEYWORDS)
    ):
        findings.append(
            {
                'type': 'WHOLE_SCRIPT_HOMOGRAPH',
                'flagged': True,
                'explanation': (
                    f"Unicode homograph detected: Host displays look-alike characters mapping to ASCII skeleton "
                    f"'{idn_analysis['skeleton']}' (Punycode: {idn_analysis['punycode']})."
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
    try:
        sandbox_preview = analyze_sandbox_preview(
            redirect_analysis['finalUrl'] or target_url,
            findings,
        )
    except Exception as exc:
        logger.exception("Failed to analyze sandbox preview: %s", exc)
        sandbox_preview = {
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
            'sslIssues': [],
            'missingSecHeaders': [],
            'redirectIssues': [],
            'urlEntropyScore': 0.0,
            'riskScore': 0,
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
    infra_analysis = infrastructure_manager.evaluate(
        hostname=hostname,
        registered_domain=registered_domain_full,
        resolved_ip=decoded_ip if is_obfuscated_ip else None,
        matched_brand=typosquatting_match,
        findings=findings,
    )
    dynamic_sandbox = dynamic_sandbox_manager.evaluate(
        target_url=target_url,
        registered_domain=registered_domain_full,
        findings=findings,
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
        'idnAnalysis': idn_analysis,
        'userinfoAnalysis': userinfo_data,
        'ipObfuscation': {
            'isObfuscated': is_obfuscated_ip,
            'format': ip_obf_type,
            'decodedIp': decoded_ip,
        },
        'infrastructure': infra_analysis,
        'dynamicSandbox': dynamic_sandbox,
        'findings': findings,
    }
