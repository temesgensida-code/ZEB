from typing import Any

BRAND_HASH_CATALOG: dict[str, dict[str, Any]] = {
    'Microsoft 365': {
        'phash': '1100101010101100110011001010101011110000101010101100110011110000',
        'authorizedDomains': {'microsoft.com', 'live.com', 'office.com', 'microsoftonline.com'},
        'similarityThreshold': 0.82,
    },
    'Google Workspace': {
        'phash': '1010101011001100111100001010101011001100111100001010101011001100',
        'authorizedDomains': {'google.com', 'accounts.google.com'},
        'similarityThreshold': 0.85,
    },
    'PayPal': {
        'phash': '1111000010101010110011001111000010101010110011001111000010101010',
        'authorizedDomains': {'paypal.com'},
        'similarityThreshold': 0.80,
    },
    'Apple ID': {
        'phash': '1010110011110000101010101100110011110000101010101100110011110000',
        'authorizedDomains': {'apple.com', 'icloud.com'},
        'similarityThreshold': 0.82,
    },
    'Chase Bank': {
        'phash': '1100110011110000101010101100110011110000101010101100110011110000',
        'authorizedDomains': {'chase.com'},
        'similarityThreshold': 0.80,
    },
    'Bank of America': {
        'phash': '1111110010101010110011001111000010101010110011001111000010101010',
        'authorizedDomains': {'bankofamerica.com'},
        'similarityThreshold': 0.80,
    },
    'Steam': {
        'phash': '0000111110101010110011001111000010101010110011001111000010101010',
        'authorizedDomains': {'steampowered.com', 'steamcommunity.com'},
        'similarityThreshold': 0.80,
    },
    'Netflix': {
        'phash': '1100001110101010110011001111000010101010110011001111000010101010',
        'authorizedDomains': {'netflix.com'},
        'similarityThreshold': 0.80,
    },
}


def hamming_distance(h1: str, h2: str) -> int:
    """Calculates bit-level Hamming distance between two binary hash strings."""
    min_len = min(len(h1), len(h2))
    diff = sum(c1 != c2 for c1, c2 in zip(h1[:min_len], h2[:min_len]))
    diff += abs(len(h1) - len(h2))
    return diff


def compute_phash(image_input: Any) -> str:
    """
    Computes a 64-bit perceptual hash (pHash) representation.
    Accepts PIL Image, binary/hex hash string, or byte array.
    """
    if isinstance(image_input, str):
        # Already binary string
        if all(c in '01' for c in image_input) and len(image_input) == 64:
            return image_input
        # Hex hash conversion
        try:
            return bin(int(image_input, 16))[2:].zfill(64)[:64]
        except Exception:
            return '0' * 64

    try:
        # If PIL is available and input is an Image
        from PIL import Image  # type: ignore
        if isinstance(image_input, Image.Image):
            img = image_input.convert('L').resize((8, 8), Image.Resampling.LANCZOS)
            pixels = list(img.getdata())
            avg = sum(pixels) / len(pixels) if pixels else 0
            return ''.join('1' if p > avg else '0' for p in pixels)
    except Exception:
        pass

    return '0' * 64


def evaluate_visual_impersonation(
    screenshot_or_hash: Any,
    registered_domain: str,
    findings: list,
) -> dict[str, Any]:
    """
    Compares perceptual hash of page screenshot against the BRAND_HASH_CATALOG.
    Flags CRITICAL_VISUAL_BRAND_IMPERSONATION if visual similarity matches an
    unauthorized domain.
    """
    if not screenshot_or_hash:
        return {
            'detected': False,
            'impersonatedBrand': None,
            'similarityScore': 0.0,
            'isAuthorizedDomain': True,
            'threshold': None,
        }

    target_phash = compute_phash(screenshot_or_hash)
    best_match: tuple[str, dict[str, Any]] | None = None
    highest_sim = 0.0

    for brand_name, data in BRAND_HASH_CATALOG.items():
        ref_hash = data['phash']
        dist = hamming_distance(target_phash, ref_hash)
        sim = 1.0 - (dist / 64.0)
        if sim > highest_sim:
            highest_sim = sim
            best_match = (brand_name, data)

    reg_domain_clean = registered_domain.lower().strip()

    if best_match and highest_sim >= best_match[1]['similarityThreshold']:
        brand_name, data = best_match
        is_authorized = reg_domain_clean in data['authorizedDomains'] or any(
            reg_domain_clean.endswith(f".{auth}") for auth in data['authorizedDomains']
        )

        if not is_authorized:
            findings.append({
                'type': 'CRITICAL_VISUAL_BRAND_IMPERSONATION',
                'flagged': True,
                'explanation': (
                    f"The visual layout of this page matches '{brand_name}' "
                    f"({highest_sim * 100:.1f}% similarity), but domain '{reg_domain_clean}' "
                    f'is NOT an authorized host for {brand_name}.'
                ),
            })
            return {
                'detected': True,
                'impersonatedBrand': brand_name,
                'similarityScore': round(highest_sim, 3),
                'isAuthorizedDomain': False,
                'threshold': data['similarityThreshold'],
            }

        return {
            'detected': False,
            'impersonatedBrand': brand_name,
            'similarityScore': round(highest_sim, 3),
            'isAuthorizedDomain': True,
            'threshold': data['similarityThreshold'],
        }

    return {
        'detected': False,
        'impersonatedBrand': None,
        'similarityScore': round(highest_sim, 3),
        'isAuthorizedDomain': True,
        'threshold': None,
    }
