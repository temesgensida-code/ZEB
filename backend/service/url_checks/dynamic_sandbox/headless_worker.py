import base64
from typing import Any

from ..constants import EXFILTRATION_SINK_PATTERNS


class HeadlessBrowserWorker:
    """
    Manages Playwright headless Chromium execution in a hardened container sandbox.
    Applies stealth evasion patches and harvests background network telemetry.
    """

    def __init__(self, navigation_timeout_ms: int = 4000, overall_timeout_ms: int = 5500):
        self.nav_timeout = navigation_timeout_ms
        self.overall_timeout = overall_timeout_ms

    def is_available(self) -> bool:
        """Checks if Playwright and headless browser dependencies are present."""
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    def run_sandbox_session(self, target_url: str) -> dict[str, Any]:
        """
        Executes dynamic JS rendering, intercepts network calls, and captures viewport screenshot.
        Guarantees zero unhandled exceptions.
        """
        if not self.is_available():
            return {
                'available': False,
                'executed': False,
                'error': 'Headless browser environment (Playwright) not configured or installed.',
                'hydratedHtml': None,
                'screenshotDataUri': None,
                'interceptedRequests': [],
                'suspiciousExfiltrations': [],
            }

        try:
            from playwright.sync_api import sync_playwright

            intercepted_requests: list[dict[str, Any]] = []
            suspicious_exfil: list[dict[str, Any]] = []

            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-web-security',
                    ],
                )
                context = browser.new_context(
                    viewport={'width': 1280, 'height': 800},
                    user_agent=(
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                        '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
                    ),
                )

                # Stealth script injection
                context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                    window.chrome = { runtime: {}, loadTimes: function() {}, csi: function() {} };
                    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                """)

                page = context.new_page()

                def on_request(request):
                    method = request.method
                    req_url = request.url
                    if method in ('POST', 'PUT'):
                        intercepted_requests.append({
                            'url': req_url,
                            'method': method,
                            'resourceType': request.resource_type,
                        })
                        # Check against exfiltration sinks
                        import re
                        for pattern, label in EXFILTRATION_SINK_PATTERNS:
                            if re.search(pattern, req_url, re.IGNORECASE):
                                suspicious_exfil.append({
                                    'url': req_url,
                                    'sinkType': label,
                                    'method': method,
                                })

                page.on('request', on_request)

                try:
                    page.goto(target_url, timeout=self.nav_timeout, wait_until='domcontentloaded')
                    page.wait_for_timeout(1000)
                except Exception:
                    pass

                hydrated_html = page.content()
                screenshot_bytes = page.screenshot(type='png')
                b64_data = base64.b64encode(screenshot_bytes).decode('ascii')
                screenshot_uri = f"data:image/png;base64,{b64_data}"

                browser.close()

                return {
                    'available': True,
                    'executed': True,
                    'error': None,
                    'hydratedHtml': hydrated_html,
                    'screenshotDataUri': screenshot_uri,
                    'interceptedRequests': intercepted_requests,
                    'suspiciousExfiltrations': suspicious_exfil,
                }
        except Exception as exc:
            return {
                'available': False,
                'executed': False,
                'error': str(exc),
                'hydratedHtml': None,
                'screenshotDataUri': None,
                'interceptedRequests': [],
                'suspiciousExfiltrations': [],
            }
