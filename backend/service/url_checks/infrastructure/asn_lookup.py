import aiohttp
from ..session_manager import create_scan_session

HIGH_ABUSE_ASNS = {
    'AS200019', 'AS209605', 'AS44050', 'AS47583', 'AS208091', 'AS9009'
}


async def lookup_asn_info(
    ip: str,
    findings: list,
    session: aiohttp.ClientSession | None = None,
) -> dict:
    """
    Resolves IP to Autonomous System (ASN) and hosting details asynchronously via aiohttp.
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
    headers = {'User-Agent': 'zeb-scanner/2.0'}
    req_timeout = aiohttp.ClientTimeout(total=1.8)

    async def _fetch(sess: aiohttp.ClientSession) -> dict:
        try:
            async with sess.get(endpoint, headers=headers, timeout=req_timeout) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
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

    if session is not None:
        return await _fetch(session)
    async with create_scan_session(total_timeout=2.5) as local_session:
        return await _fetch(local_session)
