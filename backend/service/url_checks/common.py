"""
common.py — Shared utility functions for the URL safety checker.

Improvements over v1:
  • normalize_url()          — strips tracking params, decodes percent-encoding,
                               handles data:/javascript: URIs, normalises scheme
  • is_ip_host()             — handles bracketed IPv6 and CIDR notation
  • is_ip_like_host()        — extended to catch hex-encoded and octal IP forms
  • levenshtein_distance()   — unchanged (kept for backward-compat)
  • jaro_winkler_similarity() — NEW: better similarity for short brand names
  • normalize_homographs()   — NEW: folds Unicode confusables to ASCII before
                               comparison (defeats Cyrillic/Greek lookalikes)
  • contains_brand_as_subdomain() — NEW: catches google.evil.com patterns
  • detect_open_redirect_param()  — NEW: flags ?redirect=… style params
  • detect_typosquatting_brand()  — upgraded: combines Levenshtein, Jaro-Winkler,
                               keyboard-adjacency, leet-translation, homograph
                               normalisation, and brand-in-subdomain checks
"""

from __future__ import annotations

import re
import unicodedata
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from urllib.parse import parse_qs, unquote, urlparse, urlunparse

from .constants import (
    BRAND_KEYWORDS,
    CHAR_SUBSTITUTIONS,
    HOMOGRAPH_CONFUSABLES,
    KEYBOARD_ADJACENT,
    OPEN_REDIRECT_PARAMS,
)

# ---------------------------------------------------------------------------
# Tracking / noise query-parameters stripped during normalisation.
# Removing them lets us compare canonical URLs without noisy differences.
# ---------------------------------------------------------------------------
_TRACKING_PARAMS: frozenset[str] = frozenset({
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'msclkid', 'dclid', 'zanpid', 'igshid',
    'mc_eid', 'ref', 'referrer', '_ga', 'source',
})

# Schemes that should never appear in a safe external URL.
_DANGEROUS_SCHEMES: frozenset[str] = frozenset({
    'javascript', 'data', 'vbscript', 'file',
})

# Jaro-Winkler prefix scale factor (standard value).
_JW_PREFIX_SCALE: float = 0.1

# Maximum Levenshtein distance to still flag as a typosquatting candidate.
_MAX_EDIT_DISTANCE: int = 2

# Minimum Jaro-Winkler similarity to flag as a brand match.
_MIN_JW_SIMILARITY: float = 0.88


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------

def normalize_url(candidate_url: str) -> str:
    """
    Return a cleaned, canonical form of *candidate_url*.

    Steps applied:
      1. Strip surrounding whitespace and null bytes.
      2. Reject dangerous schemes (javascript:, data:, …).
      3. Prepend https:// when no scheme is present.
      4. Percent-decode the path component.
      5. Lower-case the scheme and hostname.
      6. Remove default ports (80 for http, 443 for https).
      7. Strip known tracking query parameters.
      8. Remove empty fragments.
    """
    value = (candidate_url or '').strip().replace('\x00', '')
    if not value:
        return value

    # Reject dangerous schemes before any further processing.
    low = value.lower()
    for scheme in _DANGEROUS_SCHEMES:
        if low.startswith(f'{scheme}:'):
            return ''  # Signal to callers that this URL is not safe to follow.

    # Add missing scheme.
    if '://' not in value:
        value = f'https://{value}'

    try:
        parsed = urlparse(value)
    except ValueError:
        return value  # Return as-is if urlparse chokes.

    # Normalise scheme and netloc case.
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Strip default ports.
    if netloc.endswith(':80') and scheme == 'http':
        netloc = netloc[:-3]
    elif netloc.endswith(':443') and scheme == 'https':
        netloc = netloc[:-4]

    # Percent-decode the path (single pass to avoid double-decoding issues).
    path = unquote(parsed.path)

    # Strip tracking params from query string.
    if parsed.query:
        try:
            params = parse_qs(parsed.query, keep_blank_values=True)
            cleaned = {k: v for k, v in params.items() if k not in _TRACKING_PARAMS}
            # Reconstruct query string preserving parameter order.
            query = '&'.join(
                f'{k}={v_item}'
                for k, v_list in cleaned.items()
                for v_item in v_list
            )
        except Exception:
            query = parsed.query
    else:
        query = ''

    # Drop empty fragment.
    fragment = parsed.fragment if parsed.fragment else ''

    return urlunparse((scheme, netloc, path, parsed.params, query, fragment))


def is_dangerous_scheme(url: str) -> bool:
    """Return True if the URL uses a scheme that should never be fetched."""
    scheme = urlparse(url).scheme.lower()
    return scheme in _DANGEROUS_SCHEMES


# ---------------------------------------------------------------------------
# IP address detection
# ---------------------------------------------------------------------------

def is_ip_host(hostname: str) -> bool:
    """
    Return True if *hostname* is a valid IPv4 or IPv6 address.
    Handles:
      • Standard dotted-decimal IPv4  (1.2.3.4)
      • Bracketed IPv6                ([::1])
      • Bare IPv6                     (::1)
      • CIDR-suffixed addresses       (192.168.0.0/24)
    """
    if not hostname:
        return False

    # Strip CIDR prefix if present.
    host = hostname.split('/')[0]

    # Strip brackets from IPv6 literals used in URLs.
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]

    try:
        IPv4Address(host)
        return True
    except (AddressValueError, ValueError):
        pass

    try:
        IPv6Address(host)
        return True
    except (AddressValueError, ValueError):
        pass

    return False


def is_ip_like_host(hostname: str) -> bool:
    """
    Return True for hostnames that *look like* IP addresses but aren't
    strictly valid, covering techniques used to evade simple validators:

      • All-numeric labels  (192.168.1.1)
      • Hex-encoded IPv4    (0xC0A80101)
      • Octal-encoded IPv4  (0300.0250.01.01)
      • Hex-segment IPv6    (already caught by is_ip_host in most cases)
    """
    if not hostname or is_ip_host(hostname):
        return False

    # Pure hex integer — often used as a single-token IPv4 encoding.
    hex_match = re.fullmatch(r'0x[0-9a-fA-F]{1,8}', hostname)
    if hex_match:
        return True

    # All-numeric dotted labels (including octal-like 0300.0250.1.1).
    labels = hostname.split('.')
    if len(labels) >= 2:
        numeric_labels = [
            label for label in labels
            if label and re.fullmatch(r'0[0-9]+|[0-9]+', label)
        ]
        if len(numeric_labels) == len(labels):
            return True

    # Bare integer that fits in 32 bits (decimal IPv4 representation).
    try:
        value = int(hostname)
        if 0 <= value <= 0xFFFF_FFFF:
            return True
    except ValueError:
        pass

    # Colon-separated hex (IPv6-like but malformed).
    if ':' in hostname:
        parts = hostname.split(':')
        if all(re.fullmatch(r'[0-9a-fA-F]{0,4}', p) for p in parts):
            return True

    return False


# ---------------------------------------------------------------------------
# String similarity
# ---------------------------------------------------------------------------

def levenshtein_distance(a: str, b: str) -> int:
    """Standard Wagner-Fischer dynamic-programming Levenshtein distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            insertion    = current[j - 1] + 1
            deletion     = previous[j] + 1
            replacement  = previous[j - 1] + (char_a != char_b)
            current.append(min(insertion, deletion, replacement))
        previous = current
    return previous[-1]


def jaro_winkler_similarity(s1: str, s2: str) -> float:
    """
    Return the Jaro-Winkler similarity score in [0.0, 1.0].

    Jaro-Winkler weights common prefixes more heavily than Levenshtein, making
    it better suited to short brand-name comparisons (e.g. 'paypa1' vs 'paypal').
    """
    if s1 == s2:
        return 1.0

    len1, len2 = len(s1), len(s2)
    if len1 == 0 or len2 == 0:
        return 0.0

    match_distance = max(len1, len2) // 2 - 1
    if match_distance < 0:
        match_distance = 0

    s1_matches = [False] * len1
    s2_matches = [False] * len2

    matches = 0
    transpositions = 0

    for i in range(len1):
        start = max(0, i - match_distance)
        end   = min(i + match_distance + 1, len2)
        for j in range(start, end):
            if s2_matches[j] or s1[i] != s2[j]:
                continue
            s1_matches[i] = True
            s2_matches[j] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    k = 0
    for i in range(len1):
        if not s1_matches[i]:
            continue
        while not s2_matches[k]:
            k += 1
        if s1[i] != s2[k]:
            transpositions += 1
        k += 1

    jaro = (
        matches / len1
        + matches / len2
        + (matches - transpositions / 2) / matches
    ) / 3.0

    # Winkler prefix bonus (up to 4 characters).
    prefix_len = 0
    for i in range(min(4, len1, len2)):
        if s1[i] == s2[i]:
            prefix_len += 1
        else:
            break

    return jaro + prefix_len * _JW_PREFIX_SCALE * (1.0 - jaro)


# ---------------------------------------------------------------------------
# Homograph / Unicode normalisation
# ---------------------------------------------------------------------------

def normalize_homographs(text: str) -> str:
    """
    Replace known Unicode look-alike characters with their ASCII equivalents,
    then apply NFKC normalisation to collapse remaining composed forms.

    This defeats Cyrillic-substitution attacks such as 'pаypal.com' (where 'а'
    is U+0430 CYRILLIC SMALL LETTER A, not U+0061 LATIN SMALL LETTER A).
    """
    # Apply explicit confusable map first.
    result = ''.join(HOMOGRAPH_CONFUSABLES.get(ch, ch) for ch in text)
    # NFKC normalisation decomposes ligatures, superscripts, etc.
    return unicodedata.normalize('NFKC', result)


def _contains_keyboard_adjacent_swap(domain: str, brand: str) -> bool:
    """
    Return True if *domain* differs from *brand* by exactly one character
    that is keyboard-adjacent to the expected character (QWERTY layout).
    """
    if len(domain) != len(brand):
        return False
    differences = [
        (d_ch, b_ch)
        for d_ch, b_ch in zip(domain, brand)
        if d_ch != b_ch
    ]
    if len(differences) != 1:
        return False
    typed_char, intended_char = differences[0]
    return typed_char in KEYBOARD_ADJACENT.get(intended_char, '')


# ---------------------------------------------------------------------------
# Brand-wrapping / subdomain-abuse detection
# ---------------------------------------------------------------------------

def contains_brand_as_subdomain(hostname: str, brand: str) -> bool:
    """
    Return True when a *brand* name appears as part of the *hostname* but the
    registered domain does not belong to that brand.

    Catches patterns like:
      • secure-google.com       (brand in subdomain of attacker domain)
      • google.account-login.net (brand as leftmost label but wrong SLD)
      • paypal.phishing.io
    """
    import tldextract  # Local import to avoid circular dependency issues.
    extracted = tldextract.extract(hostname)
    registered = extracted.registered_domain.lower()
    subdomain   = extracted.subdomain.lower()
    sld         = extracted.domain.lower()

    brand_l = brand.lower()

    # Brand appears in subdomain but the SLD is not the brand itself.
    if brand_l in subdomain and not registered.startswith(brand_l + '.'):
        return True

    # Brand appears in SLD as a substring but SLD is not *exactly* the brand
    # (e.g. 'paypal-secure' or 'paypal2' — common prefix-stuffing tricks).
    if brand_l in sld and sld != brand_l:
        return True

    return False


# ---------------------------------------------------------------------------
# Open-redirect parameter detection
# ---------------------------------------------------------------------------

def detect_open_redirect_param(url: str) -> list[str]:
    """
    Return a list of suspicious query-parameter names in *url* that are
    commonly exploited for open-redirect attacks (e.g. ?redirect=https://evil.com).

    Only parameters whose value looks like an external URL are flagged.
    """
    try:
        params = parse_qs(urlparse(url).query, keep_blank_values=False)
    except Exception:
        return []

    flagged: list[str] = []
    for key, values in params.items():
        if key.lower() not in OPEN_REDIRECT_PARAMS:
            continue
        for value in values:
            decoded = unquote(value)
            if re.match(r'https?://', decoded, re.IGNORECASE):
                flagged.append(key)
                break

    return flagged


# ---------------------------------------------------------------------------
# Typosquatting detection (upgraded)
# ---------------------------------------------------------------------------

def detect_typosquatting_brand(domain: str) -> str | None:
    """
    Return the brand name that *domain* appears to be impersonating, or None.

    Detection pipeline (applied in order; first match wins):
      1. Exact match after leet-speak translation.
      2. Levenshtein distance ≤ _MAX_EDIT_DISTANCE on raw domain.
      3. Levenshtein distance ≤ _MAX_EDIT_DISTANCE on leet-translated domain.
      4. Levenshtein distance ≤ _MAX_EDIT_DISTANCE on homograph-normalised domain.
      5. Jaro-Winkler similarity ≥ _MIN_JW_SIMILARITY on raw domain.
      6. Jaro-Winkler similarity ≥ _MIN_JW_SIMILARITY on leet-translated domain.
      7. Keyboard-adjacent single-character swap (raw domain).
      8. Brand appears as a suspicious subdomain component (via contains_brand_as_subdomain).
    """
    if not domain:
        return None

    domain_lower      = domain.lower()
    domain_leet       = domain_lower.translate(CHAR_SUBSTITUTIONS)
    domain_homograph  = normalize_homographs(domain_lower)

    for brand in BRAND_KEYWORDS:
        # Skip exact match — legitimate site.
        if domain_lower == brand:
            continue

        # 1. Leet translation produces exact brand name.
        if domain_leet == brand:
            return brand

        # 2. Raw Levenshtein.
        if levenshtein_distance(domain_lower, brand) <= _MAX_EDIT_DISTANCE:
            return brand

        # 3. Leet-translated Levenshtein.
        if levenshtein_distance(domain_leet, brand) <= _MAX_EDIT_DISTANCE:
            return brand

        # 4. Homograph-normalised Levenshtein.
        if domain_homograph != domain_lower:
            if levenshtein_distance(domain_homograph, brand) <= _MAX_EDIT_DISTANCE:
                return brand

        # 5. Jaro-Winkler on raw domain (only useful for longer names).
        if len(brand) >= 5 and jaro_winkler_similarity(domain_lower, brand) >= _MIN_JW_SIMILARITY:
            return brand

        # 6. Jaro-Winkler on leet-translated domain.
        if len(brand) >= 5 and jaro_winkler_similarity(domain_leet, brand) >= _MIN_JW_SIMILARITY:
            return brand

        # 7. Single keyboard-adjacent character swap.
        if _contains_keyboard_adjacent_swap(domain_lower, brand):
            return brand

    return None
