import json
from urllib.request import Request, urlopen

DOH_ENDPOINTS = [
    'https://cloudflare-dns.com/dns-query',
    'https://dns.google/resolve',
]

DYNAMIC_DNS_PATTERNS = frozenset({
    'duckdns.org', 'no-ip.com', 'ddns.net', 'freedns.afraid.org',
    'dynu.net', 'zapto.org', 'hopto.org', 'sytes.net', 'myddns.me',
    'dynv6.net', 'changeip.com'
})

TUNNELING_PROVIDERS = frozenset({
    'ngrok-free.app', 'ngrok.io', 'loca.lt', 'trycloudflare.com',
    'serveo.net', 'pagekite.me', 'telebit.io', 'pinggy.link', 'bore.pub'
})


def query_doh(name: str, record_type: str = 'A', timeout: float = 1.5) -> list[dict]:
    """
    Queries DNS-over-HTTPS JSON endpoint.
    Returns list of answers: [{'name': ..., 'type': 1, 'TTL': 45, 'data': '...'}]
    Never raises uncaught exceptions (zero panic).
    """
    if not name:
        return []

    url = f"{DOH_ENDPOINTS[0]}?name={name}&type={record_type}"
    req = Request(url, headers={'Accept': 'application/dns-json', 'User-Agent': 'zeb-scanner/2.0'})
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data.get('Answer', [])
    except Exception:
        # Failover to secondary DoH endpoint
        try:
            fallback_url = f"{DOH_ENDPOINTS[1]}?name={name}&type={record_type}"
            req_fb = Request(fallback_url, headers={'Accept': 'application/dns-json', 'User-Agent': 'zeb-scanner/2.0'})
            with urlopen(req_fb, timeout=timeout) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return data.get('Answer', [])
        except Exception:
            return []


def audit_dns_and_flux(hostname: str, findings: list) -> dict:
    """
    Audits hostname for Dynamic DNS, reverse tunnels, and fast-flux rapid IP cycling.
    """
    low_host = hostname.lower().strip()
    is_ddns = any(low_host == d or low_host.endswith(f".{d}") for d in DYNAMIC_DNS_PATTERNS)
    is_tunnel = any(low_host == t or low_host.endswith(f".{t}") for t in TUNNELING_PROVIDERS)

    if is_ddns:
        findings.append({
            'type': 'DYNAMIC_DNS_RISK',
            'flagged': True,
            'explanation': 'The domain is hosted on a free Dynamic DNS provider, commonly used to evade takedowns.',
        })
    if is_tunnel:
        findings.append({
            'type': 'REVERSE_TUNNEL_RISK',
            'flagged': True,
            'explanation': 'The domain routes through an ephemeral reverse tunnel, concealing the origin server.',
        })

    # Query A records & TTL
    answers = query_doh(low_host, 'A')
    a_records = [ans.get('data') for ans in answers if ans.get('type') == 1 and ans.get('data')]
    ttls = [ans['TTL'] for ans in answers if 'TTL' in ans and isinstance(ans['TTL'], (int, float))]

    min_ttl = min(ttls) if ttls else None
    distinct_subnets = len({ip.rsplit('.', 1)[0] for ip in a_records if '.' in ip})

    is_fast_flux = False
    if min_ttl is not None and min_ttl < 60 and len(a_records) >= 3 and distinct_subnets >= 2:
        is_fast_flux = True
        findings.append({
            'type': 'FAST_FLUX_NETWORK',
            'flagged': True,
            'explanation': (
                f'Fast-flux characteristics detected: low TTL ({min_ttl}s) with '
                f'{len(a_records)} rotating IP addresses across {distinct_subnets} subnets.'
            ),
        })

    return {
        'aRecords': a_records,
        'minTtl': min_ttl,
        'isFastFlux': is_fast_flux,
        'isDynamicDns': is_ddns,
        'isTunnel': is_tunnel,
    }


def audit_mx_records(registered_domain: str, matched_brand: str | None, findings: list) -> dict:
    """
    Audits MX and TXT/SPF records for registered_domain.
    Flags brand impersonators without mail configuration.
    """
    if not registered_domain:
        return {'hasMx': False, 'mxHosts': [], 'hasSpf': False}

    mx_answers = query_doh(registered_domain, 'MX')
    has_mx = len(mx_answers) > 0
    mx_hosts = [ans['data'].split()[-1].rstrip('.') for ans in mx_answers if 'data' in ans]

    # Check SPF
    txt_answers = query_doh(registered_domain, 'TXT')
    txt_strings = [ans.get('data', '').replace('"', '') for ans in txt_answers]
    has_spf = any('v=spf1' in t.lower() for t in txt_strings)

    if matched_brand and not has_mx:
        findings.append({
            'type': 'BRAND_SPOOF_NO_MX',
            'flagged': True,
            'explanation': (
                f"Domain resembles brand '{matched_brand}' but maintains no mail exchange (MX) records. "
                'Legitimate enterprises always configure email infrastructure.'
            ),
        })

    return {
        'hasMx': has_mx,
        'mxHosts': mx_hosts,
        'hasSpf': has_spf,
    }
