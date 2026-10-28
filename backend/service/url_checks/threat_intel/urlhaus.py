import requests

from .base import BaseThreatEngine, EngineResult, EngineStatus


class URLhausEngine(BaseThreatEngine):
    """
    Queries Abuse.ch URLhaus API (https://urlhaus-api.abuse.ch/v1/url/).
    Free, open community malware feed, no authentication required.
    """

    def __init__(self, timeout: float = 1.8):
        super().__init__(name='URLhaus', timeout=timeout)
        self.endpoint = 'https://urlhaus-api.abuse.ch/v1/url/'

    def evaluate(self, target_url: str) -> EngineResult:
        data = {'url': target_url}
        try:
            resp = requests.post(self.endpoint, data=data, timeout=self.timeout)
            if resp.status_code == 429:
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.RATE_LIMITED,
                    error_message='URLhaus rate limit reached (HTTP 429).',
                )
            if resp.status_code != 200:
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.UNAVAILABLE,
                    error_message=f'Upstream HTTP error {resp.status_code}.',
                )

            res = resp.json()
            query_status = res.get('query_status')
            if query_status == 'ok':
                threat = res.get('threat', 'MALWARE')
                url_status = res.get('url_status', 'unknown')
                reporter = res.get('reporter', 'unknown')
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.HEALTHY,
                    is_threat=True,
                    threat_types=[f"URLHAUS_{threat.upper()}"],
                    confidence=0.98,
                    details={'urlStatus': url_status, 'reporter': reporter},
                )
            elif query_status == 'no_results':
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.HEALTHY,
                    is_threat=False,
                    confidence=0.0,
                )
            else:
                return EngineResult(
                    engine_name=self.name,
                    status=EngineStatus.UNAVAILABLE,
                    error_message=f"Query status: {query_status}",
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
