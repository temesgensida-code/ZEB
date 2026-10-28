import concurrent.futures
from typing import Any

from .base import BaseThreatEngine, EngineResult, EngineStatus
from .cache import ThreatIntelCache
from .google_safe_browsing import GoogleSafeBrowsingEngine
from .urlhaus import URLhausEngine
from .virustotal import VirusTotalEngine


class ThreatIntelManager:
    """
    Coordinates multi-engine threat intelligence evaluations concurrently.
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

    def evaluate(self, target_url: str) -> dict[str, Any]:
        """
        Runs all threat intelligence engines in parallel and returns an aggregated result.
        Never raises unhandled exceptions.
        """
        # 1. Check local TTL cache
        cached = self.cache.get(target_url)
        if cached:
            _, cached_summary = cached
            return cached_summary

        engines = self._get_engines()
        results: list[EngineResult] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_engine = {
                executor.submit(engine.evaluate, target_url): engine
                for engine in engines
            }

            try:
                for future in concurrent.futures.as_completed(future_to_engine, timeout=self.overall_timeout):
                    engine = future_to_engine[future]
                    try:
                        res = future.result()
                        results.append(res)
                    except Exception as exc:
                        results.append(
                            EngineResult(
                                engine_name=engine.name,
                                status=EngineStatus.UNAVAILABLE,
                                error_message=str(exc),
                            )
                        )
            except concurrent.futures.TimeoutError:
                # Mark pending futures as timed out
                for future, engine in future_to_engine.items():
                    if not future.done():
                        results.append(
                            EngineResult(
                                engine_name=engine.name,
                                status=EngineStatus.TIMEOUT,
                                error_message=f'Overall TI dispatch timeout ({self.overall_timeout}s) exceeded.',
                            )
                        )

        # Ensure all registered engines have an entry in results
        seen_names = {r.engine_name for r in results}
        for engine in engines:
            if engine.name not in seen_names:
                results.append(
                    EngineResult(
                        engine_name=engine.name,
                        status=EngineStatus.TIMEOUT,
                        error_message='Evaluation did not finish within timeout budget.',
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
