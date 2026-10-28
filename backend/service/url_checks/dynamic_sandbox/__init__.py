from .differential_probing import VANTAGE_PROBES, audit_multi_vantage_cloaking
from .headless_worker import HeadlessBrowserWorker
from .manager import DynamicSandboxManager
from .visual_matcher import (
    BRAND_HASH_CATALOG,
    compute_phash,
    evaluate_visual_impersonation,
    hamming_distance,
)

dynamic_sandbox_manager = DynamicSandboxManager()

__all__ = [
    'audit_multi_vantage_cloaking',
    'VANTAGE_PROBES',
    'compute_phash',
    'hamming_distance',
    'BRAND_HASH_CATALOG',
    'evaluate_visual_impersonation',
    'HeadlessBrowserWorker',
    'DynamicSandboxManager',
    'dynamic_sandbox_manager',
]
