import json
from urllib.request import Request, urlopen

HIGH_ABUSE_ASNS = {
    'AS200019', 'AS209605', 'AS44050', 'AS47583', 'AS208091', 'AS9009'
}


def lookup_asn_info(ip: str, findings: list) -> dict:
    """
    Resolves IP to Autonomous System (ASN) and hosting details.
    Zero-panic: returns default degraded dict on timeout/error.
    """
    if not ip or ip in ('127.0.0.1', 'localhost', '::1'):
        return {
            'available': False,
            'ip': ip,
            'asn': None,
            'asName': None,
            'org': None,
            'country': None,
            'countryCode': None,
            'isHosting': False,
            'isHighRiskAsn': False,
        }

    endpoint = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,as,asname,hosting"
    req = Request(endpoint, headers={'User-Agent': 'zeb-scanner/2.0'})
    try:
        with urlopen(req, timeout=1.8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if data.get('status') == 'success':
                asn_str = (data.get('as') or '').split()[0]
                is_high_risk_asn = asn_str in HIGH_ABUSE_ASNS
                is_hosting = bool(data.get('hosting', False))

                if is_high_risk_asn:
                    findings.append({
                        'type': 'HIGH_RISK_HOSTING_ASN',
                        'flagged': True,
                        'explanation': (
                            f"The site is hosted on {asn_str} ({data.get('asname')}), "
                            'a network associated with bulletproof hosting and persistent abuse campaigns.'
                        ),
                    })

                return {
                    'available': True,
                    'ip': ip,
                    'asn': asn_str,
                    'asName': data.get('asname'),
                    'org': data.get('org'),
                    'country': data.get('country'),
                    'countryCode': data.get('countryCode'),
                    'isHosting': is_hosting,
                    'isHighRiskAsn': is_high_risk_asn,
                }
    except Exception:
        pass

    return {
        'available': False,
        'ip': ip,
        'asn': None,
        'asName': None,
        'org': None,
        'country': None,
        'countryCode': None,
        'isHosting': False,
        'isHighRiskAsn': False,
    }
