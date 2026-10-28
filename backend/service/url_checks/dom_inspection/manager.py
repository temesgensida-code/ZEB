from typing import Any
from bs4 import BeautifulSoup

from .credential_harvesters import audit_clickjacking_overlays, audit_credential_harvesters
from .payload_downloads import audit_download_payloads
from .web3_signatures import audit_web3_signatures


class DomInspectionManager:
    """
    Coordinates deep DOM heuristics, sensitive input audits, Web3 drainer detection,
    and drive-by download payload inspection.
    """

    def evaluate(
        self,
        soup: BeautifulSoup,
        response_headers: dict | None = None,
        page_url: str = '',
        registered_domain: str = '',
        findings: list | None = None,
    ) -> dict[str, Any]:
        target_findings = findings if findings is not None else []
        headers = response_headers or {}

        cred_audit: dict[str, Any] = {
            'isHttpLogin': False,
            'hasPasswordInput': False,
            'sensitiveInputsFound': [],
        }
        clickjack_audit: dict[str, Any] = {
            'hasClickjackingOverlays': False,
            'overlayCount': 0,
            'overlays': [],
        }
        web3_audit: dict[str, Any] = {
            'hasWeb3DrainerSignatures': False,
            'detectedSignatures': [],
        }
        download_audit: dict[str, Any] = {
            'isExecutableDownload': False,
            'isDoubleExtension': False,
            'downloadFilename': None,
            'contentType': '',
            'autoDownloadAnchors': [],
        }

        if soup:
            try:
                cred_audit = audit_credential_harvesters(
                    soup, page_url, registered_domain, target_findings
                )
            except Exception:
                pass

            try:
                clickjack_audit = audit_clickjacking_overlays(soup, target_findings)
            except Exception:
                pass

            try:
                web3_audit = audit_web3_signatures(soup, target_findings)
            except Exception:
                pass

        try:
            download_audit = audit_download_payloads(
                soup, headers, page_url, target_findings
            )
        except Exception:
            pass

        return {
            'credentialHarvester': cred_audit,
            'clickjacking': clickjack_audit,
            'web3Drainer': web3_audit,
            'driveByDownload': download_audit,
        }
