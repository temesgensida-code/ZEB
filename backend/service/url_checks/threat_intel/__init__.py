from .base import BaseThreatEngine, EngineResult, EngineStatus
from .cache import ThreatIntelCache
from .google_safe_browsing import GoogleSafeBrowsingEngine
from .manager import ThreatIntelManager
from .urlhaus import URLhausEngine
from .virustotal import VirusTotalEngine

# Singleton instance for view consumption
threat_intel_manager = ThreatIntelManager()

__all__ = [
    'EngineStatus',
    'EngineResult',
    'BaseThreatEngine',
    'ThreatIntelCache',
    'GoogleSafeBrowsingEngine',
    'URLhausEngine',
    'VirusTotalEngine',
    'ThreatIntelManager',
    'threat_intel_manager',
]
