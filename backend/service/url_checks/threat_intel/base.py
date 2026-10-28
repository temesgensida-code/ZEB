from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EngineStatus(str, Enum):
    HEALTHY = 'HEALTHY'
    RATE_LIMITED = 'RATE_LIMITED'
    UNAVAILABLE = 'UNAVAILABLE'
    NOT_CONFIGURED = 'NOT_CONFIGURED'
    TIMEOUT = 'TIMEOUT'


@dataclass
class EngineResult:
    engine_name: str
    status: EngineStatus
    is_threat: bool = False
    threat_types: list[str] = field(default_factory=list)
    confidence: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'name': self.engine_name,
            'status': self.status.value,
            'isThreat': self.is_threat,
            'threatTypes': self.threat_types,
            'confidence': round(self.confidence, 2),
            'details': self.details,
            'errorMessage': self.error_message,
        }


class BaseThreatEngine(ABC):
    """Abstract base class for all threat intelligence providers."""

    def __init__(self, name: str, timeout: float = 2.0):
        self.name = name
        self.timeout = timeout

    @abstractmethod
    def evaluate(self, target_url: str) -> EngineResult:
        """Analyze target_url and return an EngineResult without raising unhandled exceptions."""
        raise NotImplementedError
