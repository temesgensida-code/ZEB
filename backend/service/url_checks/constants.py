SUSPICIOUS_TLDS = {
    'xyz',
    'tk',
    'tu',
    'top',
    'gq',
    'ml',
    'cf',
    'ga',
    'click',
    'buzz',
    'work',
    'zip',
    'mov',
}

BRAND_KEYWORDS = {
    'facebook',
    'google',
    'microsoft',
    'apple',
    'amazon',
    'instagram',
    'netflix',
    'paypal',
    'whatsapp',
    'telegram',
    'bankofamerica',
}

CHAR_SUBSTITUTIONS = str.maketrans(
    {
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '7': 't',
        '8': 'b',
    }
)

NEW_DOMAIN_DAYS_THRESHOLD = 180
REDIRECT_COUNT_THRESHOLD = 5
SANDBOX_HTML_LIMIT = 1_000_000

SANDBOX_KEYWORDS = [
    'verify account',
    'login urgently',
    'urgent login',
    'confirm your identity',
    'account suspended',
    'update your payment',
    'password expires',
    'security alert',
]

SUSPICIOUS_SCRIPT_PATTERNS = [
    r'eval\\s*\\(',
    r'atob\\s*\\(',
    r'document\\.write\\s*\\(',
    r'fromcharcode\\s*\\(',
    r'unescape\\s*\\(',
    r'settimeout\\s*\\(\\s*["\']',
    r'setinterval\\s*\\(\\s*["\']',
]
