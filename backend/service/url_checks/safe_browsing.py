import json
import aiohttp
from .session_manager import create_scan_session


async def check_safe_browsing(
    target_url: str,
    api_key: str,
    session: aiohttp.ClientSession | None = None,
) -> list[dict]:
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

    async def _fetch(sess: aiohttp.ClientSession) -> list[dict]:
        try:
            async with sess.post(endpoint, json=payload, timeout=aiohttp.ClientTimeout(total=10.0)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    matches = data.get('matches', [])
                    return [
                        {
                            'threatType': match.get('threatType', 'UNKNOWN'),
                            'platformType': match.get('platformType', 'UNKNOWN'),
                            'threatEntryType': match.get('threatEntryType', 'UNKNOWN'),
                        }
                        for match in matches
                    ]
                raise RuntimeError(f'Google API returned HTTP {resp.status}.')
        except (aiohttp.ClientError, RuntimeError):
            raise
        except Exception as exc:
            raise ConnectionError('Could not reach Google Safe Browsing API.') from exc

    if session is not None:
        return await _fetch(session)
    async with create_scan_session(total_timeout=12.0) as local_session:
        return await _fetch(local_session)
