from ipaddress import ip_address

from .constants import BRAND_KEYWORDS, CHAR_SUBSTITUTIONS


def normalize_url(candidate_url: str) -> str:
    value = (candidate_url or '').strip()
    if value and '://' not in value:
        value = f'https://{value}'
    return value


def is_ip_host(hostname: str) -> bool:
    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False


def is_ip_like_host(hostname: str) -> bool:
    if not hostname:
        return False

    if ':' in hostname:
        return all(
            part == '' or all(c in '0123456789abcdefABCDEF' for c in part)
            for part in hostname.split(':')
        )

    labels = hostname.split('.')
    if len(labels) < 2:
        return False

    return all(label.isdigit() for label in labels if label)


def levenshtein_distance(a: str, b: str) -> int:
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
            insertion = current[j - 1] + 1
            deletion = previous[j] + 1
            replacement = previous[j - 1] + (char_a != char_b)
            current.append(min(insertion, deletion, replacement))
        previous = current
    return previous[-1]


def detect_typosquatting_brand(domain: str) -> str | None:
    if not domain:
        return None

    translated = domain.translate(CHAR_SUBSTITUTIONS)
    for brand in BRAND_KEYWORDS:
        close_distance = levenshtein_distance(domain, brand)
        translated_distance = levenshtein_distance(translated, brand)
        if (
            domain != brand
            and (
                translated == brand
                or close_distance == 1
                or translated_distance <= 1
            )
        ):
            return brand

    return None
