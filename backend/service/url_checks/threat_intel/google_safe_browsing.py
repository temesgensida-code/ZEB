import os
import requests

from .base import BaseThreatEngine, EngineResult, EngineStatus


class GoogleSafeBrowsingEngine(BaseThreatEngine):
    """Resilient client for Google Safe Browsing Lookup API v4."""

    def __init__(self, api_key: str | None = None, timeout: float = 2.0):
        super().__init__(name='Google Safe Browsing', timeout=timeout)
        self.api_key = api_key or os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')

    def evaluate(self, target_url: str) -> EngineResult:
        if not self.api_key:
            return EngineResult(
                engine_name=self.name,
                status=EngineStatus.NOT_CONFIGURED,
                error_message='API key not configured in environment.',
            )

        endpoint = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}'
        payload = {
            'client': {'clientId': 'zeb-scanner', 'clientVersion': '2.0.0'},
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

        try:
            resp = requests.post(endpoint, json=payload, timeout=self.timeout)
            if resp.status_code == 429:
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.RATE_LIMITED,
                    error_message='Google Safe Browsing quota exceeded (HTTP 429).',
                )
            if resp.status_code != 200:
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.UNAVAILABLE,
                    error_message=f'Upstream HTTP error {resp.status_code}.',
                )

            data = resp.json()
            matches = data.get('matches', [])
            threat_types = [m.get('threatType', 'UNKNOWN') for m in matches]

            return EngineResult(
                engine_name=self.name,
                status=EngineStatus.HEALTHY,
                is_threat=len(matches) > 0,
                threat_types=threat_types,
                confidence=0.95 if matches else 0.0,
                details={'matchCount': len(matches)},
            )
        except requests.exceptions.Timeout:
            return EngineResult(
                engine_name=self.name,
                status=EngineStatus.TIMEOUT,
                error_message=f'Request timed out ({self.timeout}s limit).',
            )
        except Exception as exc:
            return EngineResult(
                engine_name=self.name,
                status=EngineStatus.UNAVAILABLE,
                error_message=str(exc),
            )
