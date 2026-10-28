from .credential_harvesters import (
    SENSITIVE_INPUT_PATTERNS,
    audit_clickjacking_overlays,
    audit_credential_harvesters,
)
from .manager import DomInspectionManager
from .payload_downloads import (
    DANGEROUS_FILE_EXTENSIONS,
    DANGEROUS_MIME_TYPES,
    DOUBLE_EXT_PATTERN,
    audit_download_payloads,
)
from .web3_signatures import WEB3_DRAINER_PATTERNS, audit_web3_signatures

dom_inspection_manager = DomInspectionManager()

__all__ = [
    'SENSITIVE_INPUT_PATTERNS',
    'audit_credential_harvesters',
    'audit_clickjacking_overlays',
    'WEB3_DRAINER_PATTERNS',
    'audit_web3_signatures',
    'DANGEROUS_FILE_EXTENSIONS',
    'DANGEROUS_MIME_TYPES',
    'DOUBLE_EXT_PATTERN',
    'audit_download_payloads',
    'DomInspectionManager',
    'dom_inspection_manager',
]
