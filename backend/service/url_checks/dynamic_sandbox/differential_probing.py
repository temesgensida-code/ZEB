import concurrent.futures
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

VANTAGE_PROBES = {
    'desktop_chrome': {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
    'mobile_safari': {
        'User-Agent': (
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 '
            '(KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1'
        ),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
    'webmail_referer': {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
        ),
        'Referer': 'https://outlook.live.com/',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
}


def _probe_url(url: str, headers: dict[str, str], timeout: float = 1.8) -> dict:
    """Executes a single lightweight HTTP probe under the given header profile."""
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            return {
                'status': resp.status,
                'length': len(data),
                'snippet': data[:1024].decode('utf-8', errors='ignore'),
                'error': None,
            }
    except HTTPError as exc:
        return {
            'status': exc.code,
            'length': 0,
            'snippet': '',
            'error': str(exc),
        }
    except Exception as exc:
        return {
            'status': None,
            'length': 0,
            'snippet': '',
            'error': str(exc),
        }


def audit_multi_vantage_cloaking(url: str, findings: list) -> dict:
    """
    Issues concurrent HTTP GET probes across Desktop Chrome, Mobile Safari,
    and Webmail Referer profiles to uncover anti-analysis cloaking evasions.
    """
    probe_results: dict[str, dict] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_map = {
            executor.submit(_probe_url, url, headers): profile
            for profile, headers in VANTAGE_PROBES.items()
        }
        for fut in concurrent.futures.as_completed(future_map, timeout=2.5):
            profile = future_map[fut]
            try:
                probe_results[profile] = fut.result()
            except Exception:
                probe_results[profile] = {'status': None, 'length': 0, 'snippet': '', 'error': 'Timeout'}

    desktop = probe_results.get('desktop_chrome', {})
    mobile = probe_results.get('mobile_safari', {})
    webmail = probe_results.get('webmail_referer', {})

    desktop_status = desktop.get('status')
    mobile_status = mobile.get('status')
    webmail_status = webmail.get('status')

    desktop_len = desktop.get('length', 0)
    mobile_len = mobile.get('length', 0)

    cloaking_detected = False
    discrepancy_type: str | None = None

    # 1. Status code mismatch (e.g. desktop 404/403 while mobile 200)
    if (desktop_status in (403, 404) and mobile_status == 200) or (
        desktop_status == 200 and mobile_status in (403, 404)
    ):
        cloaking_detected = True
        discrepancy_type = 'STATUS_MISMATCH'
    elif desktop_status and mobile_status and desktop_status != mobile_status:
        cloaking_detected = True
        discrepancy_type = 'STATUS_MISMATCH'

    # 2. Payload size disparity (> 300% difference)
    elif min(desktop_len, mobile_len) > 0:
        ratio = abs(mobile_len - desktop_len) / min(desktop_len, mobile_len)
        if ratio >= 3.0:
            cloaking_detected = True
            discrepancy_type = 'PAYLOAD_LENGTH_DISPARITY'

    if cloaking_detected:
        findings.append({
            'type': 'ANTI_ANALYSIS_CLOAKING_DETECTED',
            'flagged': True,
            'explanation': (
                f'Anti-analysis cloaking detected: Web server presents different behavior to automated/desktop '
                f'scanners versus mobile visitors (Desktop HTTP {desktop_status} with {desktop_len} bytes vs '
                f'Mobile HTTP {mobile_status} with {mobile_len} bytes). Attackers use cloaking to conceal phishing kits.'
            ),
        })

    return {
        'cloakingDetected': cloaking_detected,
        'discrepancyType': discrepancy_type,
        'desktopStatus': desktop_status,
        'mobileStatus': mobile_status,
        'webmailStatus': webmail_status,
        'desktopLengthBytes': desktop_len,
        'mobileLengthBytes': mobile_len,
        'probes': probe_results,
    }
