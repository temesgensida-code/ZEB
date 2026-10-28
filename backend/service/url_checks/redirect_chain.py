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

import base64
import re
import socket
from ipaddress import ip_address, ip_network
from urllib.parse import parse_qsl, unquote, urljoin, urlparse

import requests
import tldextract

from .common import (
    decode_obfuscated_ip,
    detect_open_redirect_param,
    detect_typosquatting_brand,
    is_dangerous_scheme,
    is_ip_host,
    is_ip_like_host,
)
from .constants import (
    OPEN_REDIRECT_PARAMS,
    REDIRECT_COUNT_THRESHOLD,
    SUSPICIOUS_PATH_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)

# ---------------------------------------------------------------------------
# SSRF Guarded IP Subnets (RFC 1918, RFC 3927, Loopback, Cloud Metadata)
# ---------------------------------------------------------------------------
_BLOCKED_SSRF_NETWORKS = [
    ip_network('127.0.0.0/8'),
    ip_network('10.0.0.0/8'),
    ip_network('172.16.0.0/12'),
    ip_network('192.168.0.0/16'),
    ip_network('169.254.0.0/16'),
    ip_network('0.0.0.0/8'),
    ip_network('::1/128'),
    ip_network('fc00::/7'),
    ip_network('fe80::/10'),
]


def is_blocked_ssrf_ip(ip_str: str) -> bool:
    """Return True if ip_str falls within private, loopback, or cloud-metadata CIDRs."""
    if not ip_str:
        return False
    try:
        ip = ip_address(ip_str)
        return any(ip in net for net in _BLOCKED_SSRF_NETWORKS)
    except ValueError:
        return False


def resolve_host_ip(hostname: str) -> str | None:
    """Resolve hostname to primary IPv4/IPv6 address via getaddrinfo."""
    if not hostname:
        return None
    # Check if host is already an obfuscated IP
    decoded_ip, _ = decode_obfuscated_ip(hostname)
    if decoded_ip:
        return decoded_ip
    try:
        info = socket.getaddrinfo(hostname, None)
        if info and info[0] and info[0][4]:
            return str(info[0][4][0])
    except Exception:
        pass
    return None


def unpack_nested_url_parameters(url: str, max_depth: int = 5) -> tuple[str, list[dict]]:
    """
    Recursively inspects query parameters for nested destination URLs.
    Supports percent-encoding (up to 3 levels), Base64 (standard/URL-safe), and Hex.
    Returns (terminal_url, unpacked_trail).
    """
    current_url = url
    unpacked_trail: list[dict] = []

    for _ in range(max_depth):
        try:
            parsed = urlparse(current_url)
        except Exception:
            break

        if not parsed.query:
            break

        params = parse_qsl(parsed.query, keep_blank_values=True)
        found_nested = False

        for key, val in params:
            val_clean = val.strip()
            if not val_clean:
                continue

            # Check candidate key
            is_candidate_key = key.lower() in OPEN_REDIRECT_PARAMS

            # Trial 1: Percent decode (up to 3 passes)
            decoded_val = val_clean
            for _pass in range(3):
                new_decoded = unquote(decoded_val)
                if new_decoded == decoded_val:
                    break
                decoded_val = new_decoded

            if decoded_val.lower().startswith(('http://', 'https://')):
                unpacked_trail.append({
                    'param': key,
                    'encoding': 'PERCENT_ENCODED',
                    'extractedUrl': decoded_val,
                })
                current_url = decoded_val
                found_nested = True
                break

            # Trial 2: Base64 decode
            clean_b64 = val_clean.strip('=\n\r\t ')
            if len(clean_b64) >= 12 and re.fullmatch(r'[A-Za-z0-9_\-]+', clean_b64):
                padded = clean_b64 + '=' * ((4 - len(clean_b64) % 4) % 4)
                try:
                    raw_bytes = base64.urlsafe_b64decode(padded.encode('ascii'))
                    decoded_text = raw_bytes.decode('utf-8', errors='ignore').strip()
                    if decoded_text.lower().startswith(('http://', 'https://')):
                        unpacked_trail.append({
                            'param': key,
                            'encoding': 'BASE64',
                            'extractedUrl': decoded_text,
                        })
                        current_url = decoded_text
                        found_nested = True
                        break
                except Exception:
                    pass

            # Trial 3: Hex decode (e.g. 68747470... or \x68\x74\x74\x70...)
            hex_cand = val_clean.replace(r'\x', '').replace('%', '')
            if len(hex_cand) >= 16 and len(hex_cand) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', hex_cand):
                try:
                    raw_bytes = bytes.fromhex(hex_cand)
                    decoded_text = raw_bytes.decode('utf-8', errors='ignore').strip()
                    if decoded_text.lower().startswith(('http://', 'https://')):
                        unpacked_trail.append({
                            'param': key,
                            'encoding': 'HEX',
                            'extractedUrl': decoded_text,
                        })
                        current_url = decoded_text
                        found_nested = True
                        break
                except Exception:
                    pass

        if not found_nested:
            break

    return current_url, unpacked_trail

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
            'passedThroughShortener': False,
            'hopCount': 0,
            'hops': [],
            'openRedirectParams': [],
            'suspiciousRedirectHops': [],
        }

    # ------------------------------------------------------------------
    # Step 1: Recursive Parameter Unrolling (Sub-Pillar 1.1)
    # ------------------------------------------------------------------
    unrolled_url, unrolled_trail = unpack_nested_url_parameters(target_url)
    if unrolled_url != target_url:
        findings.append({
            'type': 'NESTED_PARAMETER_UNROLLED',
            'flagged': True,
            'explanation': (
                f"Extracted embedded target URL from query parameter: '{unrolled_url}'. "
                'Attackers often wrap malicious destinations in trusted open-redirect params.'
            ),
        })

    # ------------------------------------------------------------------
    # Step 2: Step-by-Step Network Traversal with SSRF Guard & Loop Trap
    # ------------------------------------------------------------------
    visited_urls: set[str] = set()
    hops_data: list[dict] = []
    current_url: str = unrolled_url
    ssrf_blocked: bool = False
    loop_detected: bool = False
    too_many: bool = False
    final_body_snippet: str = ""

    MAX_HOPS = 10

    for hop_index in range(MAX_HOPS + 1):
        if not current_url:
            break

        # Check dangerous scheme
        if is_dangerous_scheme(current_url):
            findings.append({
                'type': 'DANGEROUS_SCHEME',
                'flagged': True,
                'explanation': f"Redirect hopped to a dangerous scheme: '{urlparse(current_url).scheme}'.",
            })
            break

        parsed = urlparse(current_url)
        host = (parsed.hostname or '').lower()

        # SSRF Guard: resolve host to IP and verify not blocked
        resolved_ip = resolve_host_ip(host)
        if resolved_ip and is_blocked_ssrf_ip(resolved_ip):
            ssrf_blocked = True
            findings.append({
                'type': 'SSRF_ATTEMPT_BLOCKED',
                'flagged': True,
                'explanation': (
                    f"SSRF Protection Activated: Destination host '{host}' resolves to "
                    f"restricted private/internal IP address '{resolved_ip}'. Request was aborted."
                ),
            })
            hops_data.append({
                'url': current_url,
                'statusCode': None,
                'ip': resolved_ip,
                'hopType': 'SSRF_BLOCKED',
                'isShortener': False,
            })
            break

        # Cycle / loop detection
        if current_url in visited_urls:
            loop_detected = True
            findings.append({
                'type': 'REDIRECT_LOOP_DETECTED',
                'flagged': True,
                'explanation': f"Redirect cycle detected: URL '{current_url}' reappeared in redirect chain.",
            })
            break
        visited_urls.add(current_url)

        # Check hop limit
        if hop_index >= MAX_HOPS:
            too_many = True
            findings.append({
                'type': 'TOO_MANY_REDIRECTS',
                'flagged': True,
                'explanation': (
                    f'The URL exceeded {MAX_HOPS} redirects. Excessive redirect chains '
                    'obfuscate the final destination and are a common phishing red flag.'
                ),
            })
            break

        is_short = host in URL_SHORTENERS or _registered_domain(host) in URL_SHORTENERS

        try:
            resp = requests.get(
                current_url,
                allow_redirects=False,
                timeout=3.0,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'},
                stream=True,
            )
        except requests.exceptions.Timeout:
            findings.append({
                'type': 'REDIRECT_CHECK_TIMEOUT',
                'flagged': False,
                'explanation': 'Redirect chain check timed out — destination may be slow or unreachable.',
            })
            hops_data.append({
                'url': current_url,
                'statusCode': None,
                'ip': resolved_ip,
                'hopType': 'TIMEOUT',
                'isShortener': is_short,
            })
            break
        except requests.exceptions.ConnectionError:
            findings.append({
                'type': 'REDIRECT_CHECK_DNS_FAILURE',
                'flagged': False,
                'explanation': 'DNS resolution or connection failed — the domain may not exist.',
            })
            hops_data.append({
                'url': current_url,
                'statusCode': None,
                'ip': resolved_ip,
                'hopType': 'DNS_FAILURE',
                'isShortener': is_short,
            })
            break
        except requests.RequestException as exc:
            findings.append({
                'type': 'REDIRECT_CHECK_UNAVAILABLE',
                'flagged': False,
                'explanation': f'Redirect chain could not be verified ({type(exc).__name__}).',
            })
            hops_data.append({
                'url': current_url,
                'statusCode': None,
                'ip': resolved_ip,
                'hopType': 'UNAVAILABLE',
                'isShortener': is_short,
            })
            break

        status_code = resp.status_code

        # Read first 64KB for inspection
        body_chunk = ""
        try:
            if hasattr(resp, 'raw') and hasattr(resp.raw, 'read'):
                raw_bytes = resp.raw.read(65536)
                body_chunk = raw_bytes.decode('utf-8', errors='ignore') if isinstance(raw_bytes, bytes) else str(raw_bytes)
            elif hasattr(resp, 'text'):
                body_chunk = resp.text[:65536]
            elif hasattr(resp, 'content'):
                body_chunk = resp.content[:65536].decode('utf-8', errors='ignore')
            final_body_snippet = body_chunk
        except Exception:
            pass

        # Determine next destination hop
        next_url: str | None = None
        hop_type = 'TERMINAL'

        # 1. HTTP 3xx Location header
        if 300 <= status_code < 400 and 'Location' in resp.headers:
            loc = resp.headers['Location'].strip()
            next_url = urljoin(current_url, loc)
            hop_type = 'SHORTENER' if is_short else 'HTTP_3XX'

        # 2. HTTP Refresh header
        elif 'Refresh' in resp.headers:
            ref_val = resp.headers['Refresh']
            match = re.search(r'url\s*=\s*([^;,\s]+)', ref_val, re.I)
            if match:
                cand = match.group(1).strip("'\"")
                next_url = urljoin(current_url, cand)
                hop_type = 'HTTP_REFRESH'

        # 3. HTML Meta Refresh
        elif body_chunk:
            meta_match = re.search(r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?[0-9]+;\s*url=([^"\'\s>]+)', body_chunk, re.I)
            if meta_match:
                cand = meta_match.group(1).strip("'\"")
                next_url = urljoin(current_url, cand)
                hop_type = 'META_REFRESH'
            else:
                # 4. Inline JS redirect (window.location / location.replace)
                js_match = re.search(r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\'\s]+)["\']|location\.replace\s*\(\s*["\']([^"\'\s]+)["\']\)', body_chunk, re.I)
                if js_match:
                    cand = (js_match.group(1) or js_match.group(2) or '').strip()
                    if cand and not cand.startswith(('javascript:', '#')):
                        next_url = urljoin(current_url, cand)
                        hop_type = 'JS_REDIRECT'

        hops_data.append({
            'url': current_url,
            'statusCode': status_code,
            'ip': resolved_ip,
            'hopType': hop_type,
            'isShortener': is_short,
        })

        if next_url and next_url != current_url:
            current_url = next_url
        else:
            break

    # If no network hops were made (e.g. fatal failure)
    if not hops_data:
        return {
            'available': False,
            'redirectCount': None,
            'hopCount': 0,
            'tooManyRedirects': None,
            'finalUrl': target_url,
            'finalUrlCategories': [],
            'schemeDowngrades': [],
            'shortenerHops': [],
            'passedThroughShortener': False,
            'openRedirectParams': [],
            'suspiciousRedirectHops': [],
            'hops': [],
            'unrolledParameters': unrolled_trail,
            'ssrfBlocked': ssrf_blocked,
            'loopDetected': loop_detected,
            'bodySnippet': "",
        }

    all_urls = [h['url'] for h in hops_data]
    final_url = all_urls[-1]
    redirect_count = max(0, len(hops_data) - 1)
    if redirect_count > REDIRECT_COUNT_THRESHOLD:
        too_many = True

    # ------------------------------------------------------------------
    # Scheme downgrade detection (HTTPS → HTTP at any hop).
    # ------------------------------------------------------------------
    scheme_downgrades: list[str] = []
    for i in range(len(all_urls) - 1):
        from_scheme = urlparse(all_urls[i]).scheme.lower()
        to_scheme = urlparse(all_urls[i + 1]).scheme.lower()
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
    for u in all_urls:
        params = detect_open_redirect_param(u)
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
    # Per-hop suspicious signal analysis (skip origin URL).
    # ------------------------------------------------------------------
    suspicious_hops: list[dict] = []
    shortener_hops: list[str] = []
    prev_hostname = (urlparse(all_urls[0]).hostname or '').lower()

    for h in hops_data[1:]:
        hop_url = h['url']
        s_code = h['statusCode']
        detail = _hop_detail(hop_url, s_code, original_domain, prev_hostname)
        if detail:
            suspicious_hops.append(detail)
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
    final_url_categories = _classify_final_url(final_url)
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

    # Build rich hops list for UI display
    rich_hops: list[dict] = []
    prev_h = (urlparse(all_urls[0]).hostname or '').lower()
    for idx, h in enumerate(hops_data):
        hop_url = h['url']
        s_code = h['statusCode']
        hop_host = (urlparse(hop_url).hostname or '').lower()
        prev_scheme = urlparse(all_urls[idx - 1]).scheme.lower() if idx > 0 else ''
        curr_scheme = urlparse(hop_url).scheme.lower()
        is_short = h.get('isShortener', False)
        is_cross = prev_h and hop_host and hop_host != prev_h
        is_down = prev_scheme == 'https' and curr_scheme == 'http'
        susp = any(d.get('hostname') == hop_host for d in suspicious_hops)
        rich_hops.append({
            'hopNumber': idx + 1,
            'url': hop_url,
            'statusCode': s_code,
            'hopType': h.get('hopType', 'TERMINAL'),
            'ip': h.get('ip'),
            'isShortener': is_short,
            'crossOrigin': is_cross,
            'schemeDowngrade': is_down,
            'suspicious': susp,
        })
        prev_h = hop_host

    return {
        'available': True,
        'redirectCount': redirect_count,
        'hopCount': redirect_count,
        'tooManyRedirects': too_many,
        'finalUrl': final_url,
        'finalUrlCategories': final_url_categories,
        'schemeDowngrades': scheme_downgrades,
        'shortenerHops': shortener_hops,
        'passedThroughShortener': len(shortener_hops) > 0,
        'openRedirectParams': all_open_redirect_params,
        'suspiciousRedirectHops': suspicious_hops,
        'hops': rich_hops,
        'unrolledParameters': unrolled_trail,
        'ssrfBlocked': ssrf_blocked,
        'loopDetected': loop_detected,
        'bodySnippet': final_body_snippet,
    }
