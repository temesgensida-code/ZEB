"""
constants.py — Shared reference data for the URL safety checker.

Improvements over v1:
  • SUSPICIOUS_TLDS — expanded to ~50 entries covering newly-abused registries
  • BRAND_KEYWORDS — extended with major financial, social, and cloud brands
  • CHAR_SUBSTITUTIONS — covers more digit/symbol-to-letter swaps
  • HOMOGRAPH_CONFUSABLES — Unicode look-alike character map (Cyrillic, Greek …)
  • KEYBOARD_ADJACENT — common keyboard-proximity typo pairs
  • OPEN_REDIRECT_PARAMS — query-parameter names used in open-redirect attacks
  • SUSPICIOUS_PATH_KEYWORDS — path segments that indicate phishing landing pages
  • URL_SHORTENERS — known shortener hostnames whose destinations must be resolved
  • SANDBOX_KEYWORDS — expanded phishing-lure phrase list
  • SUSPICIOUS_SCRIPT_PATTERNS — more obfuscation and exfiltration patterns
  • SECURITY_HEADERS — expected response headers for the header-audit check
"""

# ---------------------------------------------------------------------------
# TLDs frequently associated with free/throwaway domains or phishing campaigns.
# Source: APWG eCrime reports, Spamhaus TLD reputation data.
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    # Free / throwaway registries
    'tk', 'ml', 'ga', 'cf', 'gq',
    # High-abuse generic TLDs
    'xyz', 'top', 'click', 'buzz', 'work', 'loan', 'win',
    'racing', 'party', 'faith', 'review', 'trade', 'date',
    'bid', 'stream', 'download', 'cricket', 'accountant',
    'science', 'webcam', 'country',
    # File-extension TLDs (trivially confused with actual files)
    'zip', 'mov',
    # Other commonly abused TLDs
    'club', 'live', 'icu', 'rest', 'cyou', 'cfd',
    'sbs', 'bar', 'monster', 'quest',
    # Newly-abused ccTLDs / second-level registries
    'tu', 'su', 'pw',
})

# ---------------------------------------------------------------------------
# Brand names whose phonetic / visual lookalikes indicate typosquatting.
# Covers financial, cloud, social, retail, and messaging platforms.
# ---------------------------------------------------------------------------
BRAND_KEYWORDS: frozenset[str] = frozenset({
    # Social / messaging
    'facebook', 'instagram', 'whatsapp', 'telegram', 'twitter',
    'tiktok', 'snapchat', 'linkedin', 'discord', 'reddit',
    # Financial
    'paypal', 'bankofamerica', 'wellsfargo', 'chase', 'citibank',
    'barclays', 'hsbc', 'americanexpress', 'cashapp', 'venmo',
    'coinbase', 'binance', 'robinhood', 'stripe',
    # Cloud / tech
    'google', 'microsoft', 'apple', 'amazon', 'netflix',
    'adobe', 'dropbox', 'github', 'salesforce', 'shopify',
    'cloudflare', 'godaddy', 'namecheap', 'wordpress',
    # Government / identity (frequently impersonated)
    'irs', 'usps', 'fedex', 'dhl', 'ups',
})

# ---------------------------------------------------------------------------
# Digit/symbol → letter substitutions used in leet-speak domain obfuscation.
# Applied before edit-distance comparison.
# ---------------------------------------------------------------------------
CHAR_SUBSTITUTIONS: dict[int, str] = str.maketrans({
    '0': 'o',
    '1': 'l',
    '2': 'z',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '6': 'g',
    '7': 't',
    '8': 'b',
    '9': 'g',
    '@': 'a',
    '$': 's',
    '!': 'i',
    '+': 't',
    '|': 'l',
})

# ---------------------------------------------------------------------------
# Unicode homograph confusable characters → their ASCII equivalents.
# Covers Cyrillic, Greek, Latin Extended, and common symbol lookalikes.
# Reference: https://unicode.org/reports/tr39/#confusables
# ---------------------------------------------------------------------------
HOMOGRAPH_CONFUSABLES: dict[str, str] = {
    # Cyrillic → Latin
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's', 'ј': 'j',
    # Greek → Latin
    'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k',
    'ν': 'n', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'y',
    # Latin Extended / lookalikes
    'ä': 'a', 'á': 'a', 'à': 'a', 'â': 'a',
    'ë': 'e', 'é': 'e', 'è': 'e',
    'ï': 'i', 'í': 'i',
    'ö': 'o', 'ó': 'o',
    'ü': 'u', 'ú': 'u',
    'ñ': 'n',
    # Symbol lookalikes
    'ℓ': 'l', '℮': 'e', '⁰': 'o',
    'ƿ': 'p', 'ƅ': 'b',
}

# ---------------------------------------------------------------------------
# Keyboard-proximity character pairs (QWERTY layout).
# Used as an additional signal in typosquatting detection.
# ---------------------------------------------------------------------------
KEYBOARD_ADJACENT: dict[str, str] = {
    'a': 'sqzw', 'b': 'vghn', 'c': 'xdfv', 'd': 'serfcx',
    'e': 'wsrd',  'f': 'drtgv', 'g': 'ftyhb', 'h': 'gyujn',
    'i': 'ujko',  'j': 'huikm', 'k': 'jiol',  'l': 'kop',
    'm': 'njk',   'n': 'bhjm',  'o': 'iklp',  'p': 'ol',
    'q': 'wa',    'r': 'edft',  's': 'qawedxz', 't': 'rfgy',
    'u': 'yhji',  'v': 'cfgb',  'w': 'qase',  'x': 'zsdc',
    'y': 'tghu',  'z': 'asx',
}

# ---------------------------------------------------------------------------
# Query-parameter names that open-redirect vulnerabilities commonly use.
# A URL containing these params with an external value is suspicious.
# ---------------------------------------------------------------------------
OPEN_REDIRECT_PARAMS: frozenset[str] = frozenset({
    'url', 'redirect', 'redirect_to', 'redirect_url', 'redirecturl',
    'return', 'return_to', 'returnurl', 'return_url',
    'next', 'goto', 'target', 'dest', 'destination',
    'link', 'forward', 'out', 'continue', 'to',
    'checkout_url', 'image_url', 'callback',
})

# ---------------------------------------------------------------------------
# Path-segment keywords commonly found in phishing landing pages.
# ---------------------------------------------------------------------------
SUSPICIOUS_PATH_KEYWORDS: frozenset[str] = frozenset({
    'login', 'signin', 'sign-in', 'log-in',
    'verify', 'verification', 'validate', 'validation',
    'secure', 'security', 'account', 'accounts',
    'update', 'confirm', 'authentication', 'authenticate',
    'recover', 'recovery', 'unlock', 'suspend', 'suspended',
    'billing', 'payment', 'invoice', 'wallet',
    'webscr',          # PayPal phishing classic
    'cmd=_login-run',  # PayPal clone pattern
})

# ---------------------------------------------------------------------------
# Hostnames of popular URL shorteners whose real destinations are hidden.
# Any URL from these should have its redirect chain fully resolved.
# ---------------------------------------------------------------------------
URL_SHORTENERS: frozenset[str] = frozenset({
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'short.link', 'tiny.cc', 'bl.ink',
    'rebrand.ly', 'cutt.ly', 'rb.gy', 'shorturl.at',
    'link.tl', 'lnkd.in', 'youtu.be', 'amzn.to',
    'fb.me', 'dl.konto.pl',
})

# ---------------------------------------------------------------------------
# Numeric thresholds
# ---------------------------------------------------------------------------
NEW_DOMAIN_DAYS_THRESHOLD: int = 180
REDIRECT_COUNT_THRESHOLD: int = 4   # tightened from 5

# HTML byte limit fetched in sandbox preview (1 MB)
SANDBOX_HTML_LIMIT: int = 1_000_000

# ---------------------------------------------------------------------------
# Phishing lure phrases scanned in page text
# ---------------------------------------------------------------------------
SANDBOX_KEYWORDS: list[str] = [
    # Urgency / threats
    'verify account',
    'confirm your identity',
    'account suspended',
    'account has been locked',
    'account will be closed',
    'login urgently',
    'urgent login',
    'immediate action required',
    'action required',
    'your account is at risk',
    # Credential / payment pressure
    'update your payment',
    'update payment information',
    'confirm your payment',
    'password expires',
    'password will expire',
    're-enter your password',
    'enter your credentials',
    # Fear / security theatre
    'security alert',
    'security notice',
    'unusual activity',
    'unauthorized access',
    'suspicious login',
    'we have detected',
    # Prize / reward lures
    'you have been selected',
    'congratulations you won',
    'claim your prize',
    'free gift',
]

# ---------------------------------------------------------------------------
# Inline / external script patterns associated with obfuscation or exfiltration
# ---------------------------------------------------------------------------
SUSPICIOUS_SCRIPT_PATTERNS: list[str] = [
    # Classic obfuscation primitives
    r'eval\s*\(',
    r'atob\s*\(',
    r'btoa\s*\(',
    r'document\.write\s*\(',
    r'fromcharcode\s*\(',
    r'unescape\s*\(',
    r'decodeuri(?:component)?\s*\(',
    # String-based deferred execution
    r'settimeout\s*\(\s*["\']',
    r'setinterval\s*\(\s*["\']',
    # Dynamic code construction
    r'new\s+function\s*\(',
    r'\[\s*["\']constructor["\']\s*\]',
    # Credential / form exfiltration patterns
    r'\.value\s*[+]?=.*fetch\s*\(',
    r'fetch\s*\(.*password',
    r'xmlhttprequest.*password',
    r'navigator\.sendbeacon\s*\(',
    # Clipboard / input hijacking
    r'document\.execcommand\s*\(\s*["\']copy',
    r'addeventlistener\s*\(\s*["\']paste',
    # Redirection tricks
    r'window\.location\s*=\s*atob\s*\(',
    r'location\.replace\s*\(\s*atob\s*\(',
    # Obfuscated variable-length hex/octal string literals
    r'\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){8,}',
    r'\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){4,}',
]

# ---------------------------------------------------------------------------
# Security response headers expected from trustworthy origins
# ---------------------------------------------------------------------------
SECURITY_HEADERS: list[str] = [
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
]
