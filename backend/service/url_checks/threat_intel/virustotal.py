import base64
import os
import requests

from .base import BaseThreatEngine, EngineResult, EngineStatus


class VirusTotalEngine(BaseThreatEngine):
    """Resilient client for VirusTotal API v3 URL lookup."""

    def __init__(self, api_key: str | None = None, timeout: float = 2.2):
        super().__init__(name='VirusTotal', timeout=timeout)
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')

    def evaluate(self, target_url: str) -> EngineResult:
        if not self.api_key:
            return EngineResult(
                engine_name=self.name,
                status=EngineStatus.NOT_CONFIGURED,
                error_message='VirusTotal API key not configured in environment.',
            )

        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip('=')
        endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        headers = {'x-apikey': self.api_key}

        try:
            resp = requests.get(endpoint, headers=headers, timeout=self.timeout)
            if resp.status_code == 429:
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.RATE_LIMITED,
                    error_message='VirusTotal rate limit reached (HTTP 429).',
                )
            if resp.status_code == 404:
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.HEALTHY,
                    is_threat=False,
                    confidence=0.0,
                    details={'note': 'URL not yet cataloged on VirusTotal'},
                )
            if resp.status_code != 200:
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.UNAVAILABLE,
                    error_message=f'Upstream HTTP error {resp.status_code}.',
                )

            stats = resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)

            is_threat = (malicious >= 2) or (malicious + suspicious >= 3)
            threat_types = ['VIRUSTOTAL_MALICIOUS'] if is_threat else []

            return EngineResult(
                engine_name=self.name,
                status=EngineStatus.HEALTHY,
                is_threat=is_threat,
                threat_types=threat_types,
                confidence=min(1.0, malicious * 0.25),
                details=stats,
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
