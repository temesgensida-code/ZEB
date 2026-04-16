from urllib.parse import urlparse

import requests
import tldextract

from .common import detect_typosquatting_brand, is_ip_host, is_ip_like_host
from .constants import REDIRECT_COUNT_THRESHOLD, SUSPICIOUS_TLDS


def analyze_redirect_chain(target_url: str, original_domain: str, findings: list) -> dict:
    try:
        response = requests.get(
            target_url,
            allow_redirects=True,
            timeout=10,
            headers={'User-Agent': 'zeb-url-checker/1.0'},
        )
    except requests.TooManyRedirects:
        findings.append(
            {
                'type': 'TOO_MANY_REDIRECTS',
                'flagged': True,
                'explanation': (
                    'The URL triggered too many redirects. Excessive redirect loops can '
                    'obfuscate the final destination and are a common phishing red flag.'
                ),
            }
        )
        return {
            'available': True,
            'redirectCount': None,
            'tooManyRedirects': True,
            'finalUrl': None,
            'suspiciousRedirectHops': [],
        }
    except requests.RequestException:
        findings.append(
            {
                'type': 'REDIRECT_CHECK_UNAVAILABLE',
                'flagged': False,
                'explanation': (
                    'Redirect chain could not be verified due to a network or connection issue.'
                ),
            }
        )
        return {
            'available': False,
            'redirectCount': None,
            'tooManyRedirects': None,
            'finalUrl': None,
            'suspiciousRedirectHops': [],
        }

    history_urls = [item.url for item in response.history]
    chain_urls = history_urls + [response.url]
    redirect_count = len(response.history)
    too_many_redirects = redirect_count > REDIRECT_COUNT_THRESHOLD

    if too_many_redirects:
        findings.append(
            {
                'type': 'TOO_MANY_REDIRECTS',
                'flagged': True,
                'explanation': (
                    f'The URL performed {redirect_count} redirects. Long redirect chains '
                    'can hide the real destination and increase phishing risk.'
                ),
            }
        )

    suspicious_hops = []
    for hop_url in chain_urls[1:]:
        hostname = (urlparse(hop_url).hostname or '').lower()
        if not hostname:
            continue

        extracted = tldextract.extract(hostname)
        hop_registered_domain = extracted.registered_domain.lower()
        hop_tld = extracted.suffix.lower()

        reasons = []
        if is_ip_host(hostname) or is_ip_like_host(hostname):
            reasons.append('redirects to an IP-based host')

        if hop_tld and hop_tld.split('.')[-1] in SUSPICIOUS_TLDS:
            reasons.append(f"uses suspicious TLD '.{hop_tld.split('.')[-1]}'")

        typosquatting_brand = detect_typosquatting_brand(extracted.domain.lower())
        if typosquatting_brand:
            reasons.append(f"resembles typo of brand '{typosquatting_brand}'")

        if original_domain and hop_registered_domain and hop_registered_domain != original_domain:
            reasons.append(
                f"changes destination domain from '{original_domain}' to '{hop_registered_domain}'"
            )

        if reasons:
            suspicious_hops.append(
                {
                    'url': hop_url,
                    'hostname': hostname,
                    'reasons': reasons,
                }
            )

    if suspicious_hops:
        hop_hosts = ', '.join(item['hostname'] for item in suspicious_hops[:3])
        findings.append(
            {
                'type': 'SUSPICIOUS_REDIRECT_CHAIN',
                'flagged': True,
                'explanation': (
                    f'Redirect chain includes suspicious intermediate domains ({hop_hosts}). '
                    'Redirecting through unrelated or suspicious domains is a phishing red flag.'
                ),
            }
        )

    return {
        'available': True,
        'redirectCount': redirect_count,
        'tooManyRedirects': too_many_redirects,
        'finalUrl': response.url,
        'suspiciousRedirectHops': suspicious_hops,
    }
