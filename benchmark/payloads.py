"""
payloads.py - Curated URL datasets for Locust stress testing.

Categorized into:
- CPU_HEAVY_URLS: Obfuscated IPs, deep TR39 Unicode homoglyphs, userinfo attacks,
  and typosquatting permutations designed to exercise CPU-bound regexes,
  Punycode/skeleton decoders, and heuristic engines.
- NETWORK_IO_URLS: Real-world domains, redirect endpoints, and diverse TLDs
  designed to exercise external socket I/O (WHOIS port 43, dnspython queries,
  TLS handshakes, and HTTP page fetches).
- ALL_URLS: Balanced distribution for general load testing.
"""

CPU_HEAVY_URLS = [
    # Cyrillic/Greek TR39 Mixed-Script Homoglyphs (forces TR39 confusable matrix scanning)
    "http://рaypal-login-update-account.com/",
    "http://gооgle-auth-verify.com/login",
    "http://аррle-id-security-protection.org/",
    "http://micrоsоft-365-login-verify.com/oauth/",
    "http://bаnkоfamericа-login-alert.net/auth",

    # Numeric IP Obfuscation (Hex, Dword, Octal, Mixed)
    "http://0x7f000001/verify",
    "http://2130706433/path/index.html",
    "http://0177.0.0.1/auth/reset",
    "http://0x7f.1/test",

    # RFC 3986 Deceptive Userinfo
    "http://security@google.com:update@0x7f000001/login",
    "http://admin:password@faceb00k-portal.xyz/verify",
    "http://support%40paypal.com:verify@127.0.0.1/account",

    # Brand Typosquatting Signals & Suspicious TLDs
    "http://paypa1-secure-checkout.xyz/",
    "http://faceb00k-login-checkpoint.top/",
    "http://amaz0n-prime-order-update.click/",
    "http://netf1ix-billing-reactivation.fit/",

    # High Entropy Paths & Long Obfuscated Queries
    "http://secure-token-check.buzz/auth?token=a8f9c1e2d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7&target=sandbox&ref=matrix",
    "http://verify-account-portal.xyz/a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0",
]

NETWORK_IO_URLS = [
    # Top-tier domains with extensive DNS records & HTTPS TLS handshakes
    "https://www.wikipedia.org/",
    "https://www.python.org/",
    "https://www.github.com/",
    "https://www.cloudflare.com/",
    "https://www.mozilla.org/",
    "https://www.iana.org/",
    "https://www.apache.org/",
    "https://www.kernel.org/",
    "https://www.eff.org/",
    "https://www.w3.org/",

    # Redirect chains and multi-hop destinations
    "https://httpbin.org/redirect/2",
    "https://httpbin.org/status/200",
]

# Combined dataset for realistic blended workload
ALL_URLS = CPU_HEAVY_URLS + NETWORK_IO_URLS
