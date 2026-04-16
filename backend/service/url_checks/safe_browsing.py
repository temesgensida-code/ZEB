import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def check_safe_browsing(target_url: str, api_key: str) -> list[dict]:
    payload = {
        'client': {'clientId': 'zeb-url-checker', 'clientVersion': '1.0.0'},
        'threatInfo': {
            'threatTypes': [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': target_url}],
        },
    }

    endpoint = (
        'https://safebrowsing.googleapis.com/v4/threatMatches:find'
        f'?key={api_key}'
    )

    request_data = json.dumps(payload).encode('utf-8')
    api_request = Request(
        endpoint,
        data=request_data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )

    try:
        with urlopen(api_request, timeout=10) as upstream:
            body = upstream.read().decode('utf-8')
    except HTTPError as exc:
        raise RuntimeError(f'Google API returned HTTP {exc.code}.') from exc
    except URLError as exc:
        raise ConnectionError('Could not reach Google Safe Browsing API.') from exc

    response_json = json.loads(body) if body else {}
    matches = response_json.get('matches', [])

    return [
        {
            'threatType': match.get('threatType', 'UNKNOWN'),
            'platformType': match.get('platformType', 'UNKNOWN'),
            'threatEntryType': match.get('threatEntryType', 'UNKNOWN'),
        }
        for match in matches
    ]
