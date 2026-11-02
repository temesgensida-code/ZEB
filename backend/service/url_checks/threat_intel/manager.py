import asyncio
from typing import Any
import aiohttp

from .base import BaseThreatEngine, EngineResult, EngineStatus
from .cache import ThreatIntelCache
from .google_safe_browsing import GoogleSafeBrowsingEngine
from .urlhaus import URLhausEngine
from .virustotal import VirusTotalEngine
from ..session_manager import create_scan_session


class ThreatIntelManager:
    """
    Coordinates multi-engine threat intelligence evaluations asynchronously.
    Provides circuit breaking, zero-panic execution, and local caching.
    """

    def __init__(self, cache_ttl: int = 1800, max_workers: int = 4, overall_timeout: float = 3.0):
        self.cache = ThreatIntelCache(ttl_seconds=cache_ttl)
        self.max_workers = max_workers
        self.overall_timeout = overall_timeout

    def _get_engines(self) -> list[BaseThreatEngine]:
        return [
            GoogleSafeBrowsingEngine(),
            URLhausEngine(),
            VirusTotalEngine(),
        ]

    async def _evaluate_with_session(self, target_url: str, session: aiohttp.ClientSession) -> dict[str, Any]:
        """
        Runs all threat intelligence engines concurrently as coroutines.
        Never raises unhandled exceptions.
        """
        # 1. Check local TTL cache
        cached = self.cache.get(target_url)
        if cached:
            _, cached_summary = cached
            return cached_summary

        engines = self._get_engines()
        tasks = [
            asyncio.create_task(engine.evaluate(target_url, session=session))
            for engine in engines
        ]

        try:
            raw_results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.overall_timeout,
            )
        except asyncio.TimeoutError:
            raw_results = []
            for task, engine in zip(tasks, engines):
                if task.done() and not task.cancelled():
                    try:
                        raw_results.append(task.result())
                    except Exception as exc:
                        raw_results.append(
                            EngineResult(
                                engine_name=engine.name,
                                status=EngineStatus.UNAVAILABLE,
                                error_message=str(exc),
                            )
                        )
                else:
                    task.cancel()
                    raw_results.append(
                        EngineResult(
                            engine_name=engine.name,
                            status=EngineStatus.TIMEOUT,
                            error_message=f'Overall TI dispatch timeout ({self.overall_timeout}s) exceeded.',
                        )
                    )

        results: list[EngineResult] = []
        for i, res in enumerate(raw_results):
            engine = engines[i]
            if isinstance(res, EngineResult):
                results.append(res)
            elif isinstance(res, Exception):
                results.append(
                    EngineResult(
                        engine_name=engine.name,
                        status=EngineStatus.UNAVAILABLE,
                        error_message=str(res),
                    )
                )
            else:
                results.append(
                    EngineResult(
                        engine_name=engine.name,
                        status=EngineStatus.UNAVAILABLE,
                        error_message='Unknown evaluation result.',
                    )
                )

        # 2. Compute Consensus and Metrics
        healthy_count = sum(1 for r in results if r.status == EngineStatus.HEALTHY)
        configured_count = sum(1 for r in results if r.status != EngineStatus.NOT_CONFIGURED)
        is_degraded = (healthy_count == 0) and (configured_count > 0)

        all_threat_types: list[str] = []
        is_any_threat = False
        weighted_score = 0

        for r in results:
            if r.is_threat:
                is_any_threat = True
                all_threat_types.extend(r.threat_types)

                # Weights: URLhaus (90), Google SB (80), VirusTotal (70+)
                if r.engine_name == 'URLhaus':
                    weighted_score += 90
                elif r.engine_name == 'Google Safe Browsing':
                    weighted_score += 80
                elif r.engine_name == 'VirusTotal':
                    malicious = r.details.get('malicious', 0) if isinstance(r.details, dict) else 0
                    extra = max(0, (malicious - 3) * 2)
                    weighted_score += (70 + extra)
                else:
                    weighted_score += 50

        consensus_score = min(100, weighted_score) if is_any_threat else 0

        summary = {
            'isThreat': is_any_threat,
            'consensusScore': consensus_score,
            'evaluatedEnginesCount': len(engines),
            'healthyEnginesCount': healthy_count,
            'evaluationDegraded': is_degraded,
            'threatTypes': list(set(all_threat_types)),
            'engines': [r.to_dict() for r in results],
        }

        # 3. Store in cache
        self.cache.set(target_url, results, summary)

        return summary

    async def evaluate(self, target_url: str, session: aiohttp.ClientSession | None = None) -> dict[str, Any]:
        if session is not None:
            return await self._evaluate_with_session(target_url, session)
        async with create_scan_session(total_timeout=self.overall_timeout + 1.0) as local_session:
            return await self._evaluate_with_session(target_url, local_session)
