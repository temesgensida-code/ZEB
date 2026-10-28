import time
from typing import Any

from .differential_probing import audit_multi_vantage_cloaking
from .headless_worker import HeadlessBrowserWorker
from .visual_matcher import evaluate_visual_impersonation


class DynamicSandboxManager:
    """
    Coordinates dynamic client-side JS rendering, differential multi-vantage probing,
    and perceptual hash visual clone matching.
    """

    def __init__(self, overall_timeout_sec: float = 5.0):
        self.worker = HeadlessBrowserWorker()
        self.overall_timeout = overall_timeout_sec

    def evaluate(
        self,
        target_url: str,
        registered_domain: str,
        findings: list | None = None,
    ) -> dict[str, Any]:
        target_findings = findings if findings is not None else []
        start_time = time.time()

        # 1. Multi-vantage differential cloaking probing (Fast HTTP)
        cloaking_result = audit_multi_vantage_cloaking(target_url, target_findings)

        # 2. Dynamic headless browser execution (Playwright / Chromium)
        worker_result = self.worker.run_sandbox_session(target_url)

        screenshot_uri = worker_result.get('screenshotDataUri')
        intercepted = worker_result.get('interceptedRequests', [])
        suspicious_exfil = worker_result.get('suspiciousExfiltrations', [])

        # Record findings for background network exfiltration if captured
        for exfil in suspicious_exfil:
            target_findings.append({
                'type': 'EXFILTRATION_SINK_DETECTED',
                'flagged': True,
                'explanation': (
                    f"Background network monitor intercepted exfiltration beacon to "
                    f"'{exfil.get('sinkType')}' ({exfil.get('url')})."
                ),
            })

        # 3. Visual brand impersonation matching (pHash)
        visual_result = {
            'detected': False,
            'impersonatedBrand': None,
            'similarityScore': 0.0,
            'isAuthorizedDomain': True,
            'threshold': None,
        }
        if screenshot_uri:
            visual_result = evaluate_visual_impersonation(
                screenshot_uri, registered_domain, target_findings
            )

        elapsed_ms = int((time.time() - start_time) * 1000)

        return {
            'headlessWorkerExecuted': bool(worker_result.get('executed')),
            'executionTimeMs': elapsed_ms,
            'cloakingAnalysis': cloaking_result,
            'visualMatching': visual_result,
            'networkHarvester': {
                'totalOutboundRequests': len(intercepted),
                'suspiciousBackgroundExfiltration': suspicious_exfil,
            },
            'screenshot': {
                'available': bool(screenshot_uri),
                'format': 'png',
                'dataUri': screenshot_uri,
            },
            'hydratedHtml': worker_result.get('hydratedHtml'),
        }
