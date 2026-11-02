import asyncio
import aiohttp

from .base import BaseThreatEngine, EngineResult, EngineStatus
from ..session_manager import create_scan_session


class URLhausEngine(BaseThreatEngine):
    """
    Asynchronous client for Abuse.ch URLhaus API (https://urlhaus-api.abuse.ch/v1/url/).
    Free, open community malware feed, no authentication required.
    """

    def __init__(self, timeout: float = 1.8):
        super().__init__(name='URLhaus', timeout=timeout)
        self.endpoint = 'https://urlhaus-api.abuse.ch/v1/url/'

    async def _evaluate_with_session(self, target_url: str, session: aiohttp.ClientSession) -> EngineResult:
        data = {'url': target_url}
        try:
            req_timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with session.post(self.endpoint, data=data, timeout=req_timeout) as resp:
                if resp.status == 429:
                    return EngineResult(
                        engine_name=self.name,
                        status=EngineStatus.RATE_LIMITED,
                        error_message='URLhaus rate limit reached (HTTP 429).',
                    )
                if resp.status != 200:
                    return EngineResult(
                        engine_name=self.name,
                        status=EngineStatus.UNAVAILABLE,
                        error_message=f'Upstream HTTP error {resp.status}.',
                    )

                res = await resp.json(content_type=None)
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
        except (asyncio.TimeoutError, aiohttp.ServerTimeoutError):
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

    async def evaluate(self, target_url: str, session: aiohttp.ClientSession | None = None) -> EngineResult:
        if session is not None:
            return await self._evaluate_with_session(target_url, session)
        async with create_scan_session(total_timeout=self.timeout + 1.0) as local_session:
            return await self._evaluate_with_session(target_url, local_session)
