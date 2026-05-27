"""
redirect_chain.py — Redirect chain safety analyser.

Improvements over v1:
  • Scheme downgrade detection  — flags any HTTPS → HTTP hop in the chain
  • Open-redirect parameter scan — detects ?redirect=… / ?next=… style abuse
                                   at every hop, not just the final URL
  • URL shortener detection     — flags hops through known shortener domains
                                   so the real destination can be surfaced
  • Final-URL categorisation    — labels the landing page as login/payment/
                                   download/etc. based on path keywords
  • Per-hop detail              — each hop now records its HTTP status code
                                   and whether it was a cross-origin jump
  • Improved error reporting    — separate handling for timeout vs DNS failure
                                   vs connection error
  • is_dangerous_scheme guard   — rejects javascript:/data: before fetching
"""

from __future__ import annotations

from urllib.parse import urlparse

import requests
import tldextract

from .common import (
    detect_open_redirect_param,
    detect_typosquatting_brand,
    is_dangerous_scheme,
    is_ip_host,
    is_ip_like_host,
)
from .constants import (
    REDIRECT_COUNT_THRESHOLD,
    SUSPICIOUS_PATH_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _registered_domain(hostname: str) -> str:
    """Return the eTLD+1 of *hostname*, lower-cased."""
    return tldextract.extract(hostname).registered_domain.lower()


def _classify_final_url(url: str) -> list[str]:
    """
    Return a list of category labels that describe what the final URL appears
    to be (e.g. ['login_page', 'payment_page']).  Used to surface intent to
    the caller without fetching the page body.
    """
    path = urlparse(url).path.lower()
    labels: list[str] = []
    for keyword in SUSPICIOUS_PATH_KEYWORDS:
        if keyword in path:
            labels.append(keyword.replace('-', '_').replace(' ', '_'))
    return labels


def _hop_detail(
    hop_url: str,
    status_code: int | None,
    original_domain: str,
    prev_hostname: str,
) -> dict | None:
    """
    Analyse a single redirect hop and return a detail dict if any suspicious
    signals are found, or None if the hop looks clean.
    """
    parsed   = urlparse(hop_url)
    hostname = (parsed.hostname or '').lower()
    if not hostname:
        return None

    extracted        = tldextract.extract(hostname)
    registered       = extracted.registered_domain.lower()
    tld              = (extracted.suffix or '').lower()
    domain_label     = extracted.domain.lower()

    reasons: list[str] = []

    # IP-based destination
    if is_ip_host(hostname) or is_ip_like_host(hostname):
        reasons.append('redirects to an IP-based host')

    # Suspicious TLD
    effective_tld = tld.split('.')[-1] if tld else ''
    if effective_tld and effective_tld in SUSPICIOUS_TLDS:
        reasons.append(f"uses suspicious TLD '.{effective_tld}'")

    # Typosquatting
    brand = detect_typosquatting_brand(domain_label)
    if brand:
        reasons.append(f"domain resembles typo of brand '{brand}'")

    # Cross-origin jump from original domain
    if original_domain and registered and registered != original_domain:
        reasons.append(
            f"changes destination from '{original_domain}' to '{registered}'"
        )

    # Cross-origin jump from the immediately preceding hop
    if prev_hostname and hostname != prev_hostname:
        prev_registered = _registered_domain(prev_hostname)
        if registered and registered != prev_registered:
            reasons.append(
                f"cross-origin hop from '{prev_registered}' to '{registered}'"
            )

    # URL shortener in the chain (hides final destination)
    if registered in URL_SHORTENERS or hostname in URL_SHORTENERS:
        reasons.append(f"passes through known URL shortener '{hostname}'")

    # Open-redirect parameter abuse
    open_redirect_params = detect_open_redirect_param(hop_url)
    if open_redirect_params:
        reasons.append(
            'contains open-redirect query parameter(s): '
            + ', '.join(open_redirect_params)
        )

    # Non-200 intermediate status that still redirected (unusual)
    if status_code is not None and status_code not in (301, 302, 303, 307, 308):
        reasons.append(
            f'unexpected HTTP status {status_code} used for redirect'
        )

    if not reasons:
        return None

    return {
        'url':        hop_url,
        'hostname':   hostname,
        'statusCode': status_code,
        'reasons':    reasons,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_redirect_chain(
    target_url: str,
    original_domain: str,
    findings: list,
) -> dict:
    """
    Follow all redirects from *target_url* and analyse each hop for safety.

    Parameters
    ----------
    target_url : str
        The URL to resolve.
    original_domain : str
        The eTLD+1 of the original/submitted URL (used to detect unexpected
        domain changes mid-chain).
    findings : list
        Mutable list; finding dicts are appended in-place.

    Returns
    -------
    dict
        Keys:
          available              – bool
          redirectCount          – int | None
          tooManyRedirects       – bool | None
          finalUrl               – str | None
          finalUrlCategories     – list[str]   [NEW] path-keyword labels
          schemeDowngrades       – list[str]   [NEW] hops where HTTPS→HTTP
          shortenerHops          – list[str]   [NEW] shortener hostnames seen
          openRedirectParams     – list[str]   [NEW] suspicious params found
          suspiciousRedirectHops – list[dict]  enhanced with statusCode
    """

    # ------------------------------------------------------------------
    # Guard: reject dangerous schemes before making any network request.
    # ------------------------------------------------------------------
    if is_dangerous_scheme(target_url):
        findings.append({
            'type': 'DANGEROUS_SCHEME',
            'flagged': True,
            'explanation': (
                f"URL uses a non-HTTP scheme ('{urlparse(target_url).scheme}') "
                'that cannot be safely followed.'
            ),
        })
        return {
            'available': False,
            'redirectCount': None,
            'tooManyRedirects': None,
            'finalUrl': None,
            'finalUrlCategories': [],
            'schemeDowngrades': [],
            'shortenerHops': [],
            'openRedirectParams': [],
            'suspiciousRedirectHops': [],
        }

    # ------------------------------------------------------------------
    # Fetch with redirect following.
    # ------------------------------------------------------------------
    try:
        response = requests.get(
            target_url,
            allow_redirects=True,
            timeout=10,
            headers={'User-Agent': 'zeb-url-checker/1.0'},
        )
    except requests.TooManyRedirects:
        findings.append({
            'type': 'TOO_MANY_REDIRECTS',
            'flagged': True,
            'explanation': (
                'The URL triggered too many redirects. Excessive redirect loops '
                'obfuscate the final destination and are a common phishing red flag.'
            ),
        })
        return {
            'available': True,
            'redirectCount': None,
            'tooManyRedirects': True,
            'finalUrl': None,
            'finalUrlCategories': [],
            'schemeDowngrades': [],
            'shortenerHops': [],
            'openRedirectParams': [],
            'suspiciousRedirectHops': [],
        }
    except requests.exceptions.Timeout:
        findings.append({
            'type': 'REDIRECT_CHECK_TIMEOUT',
            'flagged': False,
            'explanation': 'Redirect chain check timed out — destination may be slow or unreachable.',
        })
        return {
            'available': False,
            'redirectCount': None,
            'tooManyRedirects': None,
            'finalUrl': None,
            'finalUrlCategories': [],
            'schemeDowngrades': [],
            'shortenerHops': [],
            'openRedirectParams': [],
            'suspiciousRedirectHops': [],
        }
    except requests.exceptions.ConnectionError:
        findings.append({
            'type': 'REDIRECT_CHECK_DNS_FAILURE',
            'flagged': False,
            'explanation': 'DNS resolution or connection failed — the domain may not exist.',
        })
        return {
            'available': False,
            'redirectCount': None,
            'tooManyRedirects': None,
            'finalUrl': None,
            'finalUrlCategories': [],
            'schemeDowngrades': [],
            'shortenerHops': [],
            'openRedirectParams': [],
            'suspiciousRedirectHops': [],
        }
    except requests.RequestException as exc:
        findings.append({
            'type': 'REDIRECT_CHECK_UNAVAILABLE',
            'flagged': False,
            'explanation': (
                f'Redirect chain could not be verified ({type(exc).__name__}).'
            ),
        })
        return {
            'available': False,
            'redirectCount': None,
            'tooManyRedirects': None,
            'finalUrl': None,
            'finalUrlCategories': [],
            'schemeDowngrades': [],
            'shortenerHops': [],
            'openRedirectParams': [],
            'suspiciousRedirectHops': [],
        }

    # ------------------------------------------------------------------
    # Build the full chain: history hops + final response.
    # ------------------------------------------------------------------
    history        = list(response.history)
    redirect_count = len(history)
    too_many       = redirect_count > REDIRECT_COUNT_THRESHOLD

    # Pair each hop URL with its HTTP status code.
    hop_pairs: list[tuple[str, int | None]] = [
        (r.url, r.status_code) for r in history
    ]
    hop_pairs.append((response.url, response.status_code))

    all_urls = [url for url, _ in hop_pairs]

    if too_many:
        findings.append({
            'type': 'TOO_MANY_REDIRECTS',
            'flagged': True,
            'explanation': (
                f'The URL performed {redirect_count} redirect(s). Long chains '
                'can hide the real destination and increase phishing risk.'
            ),
        })

    # ------------------------------------------------------------------
    # Scheme downgrade detection (HTTPS → HTTP at any hop).
    # ------------------------------------------------------------------
    scheme_downgrades: list[str] = []
    for i in range(len(all_urls) - 1):
        from_scheme = urlparse(all_urls[i]).scheme.lower()
        to_scheme   = urlparse(all_urls[i + 1]).scheme.lower()
        if from_scheme == 'https' and to_scheme == 'http':
            downgrade_url = all_urls[i + 1]
            scheme_downgrades.append(downgrade_url)

    if scheme_downgrades:
        findings.append({
            'type': 'HTTPS_TO_HTTP_DOWNGRADE',
            'flagged': True,
            'explanation': (
                'One or more redirects downgraded from HTTPS to plain HTTP, '
                'exposing credentials and session tokens to interception. '
                f'Affected hop(s): {", ".join(scheme_downgrades[:3])}'
            ),
        })

    # ------------------------------------------------------------------
    # Aggregate open-redirect params across all hops.
    # ------------------------------------------------------------------
    all_open_redirect_params: list[str] = []
    for url, _ in hop_pairs:
        params = detect_open_redirect_param(url)
        all_open_redirect_params.extend(p for p in params if p not in all_open_redirect_params)

    if all_open_redirect_params:
        findings.append({
            'type': 'OPEN_REDIRECT_PARAMETER',
            'flagged': True,
            'explanation': (
                'One or more URLs in the redirect chain contain query parameters '
                'commonly exploited in open-redirect attacks: '
                + ', '.join(all_open_redirect_params) + '.'
            ),
        })

    # ------------------------------------------------------------------
    # Per-hop suspicious signal analysis (skip the first / origin URL).
    # ------------------------------------------------------------------
    suspicious_hops: list[dict] = []
    shortener_hops:  list[str]  = []

    prev_hostname = (urlparse(all_urls[0]).hostname or '').lower()

    for hop_url, status_code in hop_pairs[1:]:
        detail = _hop_detail(hop_url, status_code, original_domain, prev_hostname)
        if detail:
            suspicious_hops.append(detail)
            # Track shortener hops separately for easy surfacing.
            hop_host = detail['hostname']
            if hop_host in URL_SHORTENERS or _registered_domain(hop_host) in URL_SHORTENERS:
                shortener_hops.append(hop_host)
        prev_hostname = (urlparse(hop_url).hostname or '').lower()

    if suspicious_hops:
        hop_hosts = ', '.join(item['hostname'] for item in suspicious_hops[:3])
        findings.append({
            'type': 'SUSPICIOUS_REDIRECT_CHAIN',
            'flagged': True,
            'explanation': (
                f'Redirect chain includes suspicious intermediate domains ({hop_hosts}). '
                'Redirecting through unrelated or suspicious domains is a phishing red flag.'
            ),
        })

    # ------------------------------------------------------------------
    # Classify the final URL by path keywords.
    # ------------------------------------------------------------------
    final_url_categories = _classify_final_url(response.url)
    if final_url_categories:
        findings.append({
            'type': 'SUSPICIOUS_FINAL_URL_PATH',
            'flagged': True,
            'explanation': (
                'The final redirect destination URL contains path keywords associated '
                'with credential-harvesting pages: '
                + ', '.join(final_url_categories) + '.'
            ),
        })

    return {
        'available':              True,
        'redirectCount':          redirect_count,
        'tooManyRedirects':       too_many,
        'finalUrl':               response.url,
        'finalUrlCategories':     final_url_categories,
        'schemeDowngrades':       scheme_downgrades,
        'shortenerHops':          shortener_hops,
        'openRedirectParams':     all_open_redirect_params,
        'suspiciousRedirectHops': suspicious_hops,
    }
