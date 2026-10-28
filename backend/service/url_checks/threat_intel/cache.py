import hashlib
import threading
import time
from typing import Any

from .base import EngineResult


class ThreatIntelCache:
    """Thread-safe in-memory TTL cache for threat intelligence evaluations."""

    def __init__(self, ttl_seconds: int = 1800):  # 30 minutes default
        self._cache: dict[str, tuple[float, list[EngineResult], dict[str, Any]]] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def _make_key(self, url: str) -> str:
        return hashlib.sha256(url.strip().encode('utf-8')).hexdigest()

    def get(self, url: str) -> tuple[list[EngineResult], dict[str, Any]] | None:
        key = self._make_key(url)
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            timestamp, results, summary = entry
            if time.time() - timestamp > self._ttl:
                self._cache.pop(key, None)
                return None
            return results, summary

    def set(self, url: str, results: list[EngineResult], summary: dict[str, Any]) -> None:
        key = self._make_key(url)
        with self._lock:
            self._cache[key] = (time.time(), results, summary)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
