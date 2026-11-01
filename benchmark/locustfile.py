"""
locustfile.py - Locust stress testing suite with Network I/O vs CPU profiling.

Features:
- Telemetry extraction: Reads diagnostic timing response headers (X-Time-Network-IO-Ms,
  X-Time-CPU-Ms, X-Time-Total-Ms) returned by the backend.
- Custom Locust events: Fires separate metric streams for NETWORK_IO and CPU_BOUND
  so they appear in Locust's real-time Web UI charts and exported HTML/CSV reports.
- User scenarios:
  1. CpuBoundUser: Stresses CPU regexes, TR39 matrix, and IP de-obfuscation.
  2. NetworkIoUser: Stresses WHOIS, DNS, TLS, and HTTP external socket requests.
  3. MixedWorkloadUser: Blended distribution simulating production traffic.
"""

import random
import uuid
from locust import HttpUser, task, between, events
try:
    from .payloads import CPU_HEAVY_URLS, NETWORK_IO_URLS, ALL_URLS
except ImportError:
    from payloads import CPU_HEAVY_URLS, NETWORK_IO_URLS, ALL_URLS


def _record_diagnostic_metrics(response):
    """
    Extract diagnostic timing headers and fire dedicated Locust metrics.
    """
    if not response or not hasattr(response, "headers"):
        return

    headers = response.headers
    net_io_header = headers.get("X-Time-Network-IO-Ms")
    cpu_header = headers.get("X-Time-CPU-Ms")
    total_header = headers.get("X-Time-Total-Ms")

    try:
        if net_io_header is not None:
            net_io_ms = float(net_io_header)
            events.request.fire(
                request_type="NETWORK_IO",
                name="External Socket Wait (WHOIS/DNS/HTTP)",
                response_time=net_io_ms,
                response_length=0,
                exception=None,
                context={},
            )
    except (ValueError, TypeError):
        pass

    try:
        if cpu_header is not None:
            cpu_ms = float(cpu_header)
            events.request.fire(
                request_type="CPU_BOUND",
                name="Heuristic & Parser Execution (TR39/DOM/Regex)",
                response_time=cpu_ms,
                response_length=0,
                exception=None,
                context={},
            )
    except (ValueError, TypeError):
        pass

    try:
        if total_header is not None:
            server_total_ms = float(total_header)
            events.request.fire(
                request_type="SERVER_TOTAL",
                name="Server Handler Total Time",
                response_time=server_total_ms,
                response_length=0,
                exception=None,
                context={},
            )
    except (ValueError, TypeError):
        pass


class BaseCheckUrlUser(HttpUser):
    """Base class for check-url users with standard post logic."""
    abstract = True

    def _execute_check(self, target_url: str, scenario_tag: str):
        payload = {
            "url": target_url,
            "sessionId": str(uuid.uuid4()),
        }
        with self.client.post(
            "/api/check-url/",
            json=payload,
            name=f"/api/check-url/ [{scenario_tag}]",
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                _record_diagnostic_metrics(response)
                response.success()
            elif response.status_code == 400:
                # 400 bad request (e.g. malformed test input) is acceptable if testing invalid inputs
                _record_diagnostic_metrics(response)
                response.success()
            else:
                response.failure(f"HTTP {response.status_code}: {response.text[:120]}")


class CpuBoundUser(BaseCheckUrlUser):
    """
    Scenario A: Isolates CPU-bound heuristics (TR39 Unicode matrix,
    obfuscated IP decoding, userinfo parsing, brand typosquatting).
    """
    weight = 1
    wait_time = between(0.05, 0.2)

    @task
    def check_cpu_heavy_url(self):
        target = random.choice(CPU_HEAVY_URLS)
        self._execute_check(target, scenario_tag="CPU_HEAVY")


class NetworkIoUser(BaseCheckUrlUser):
    """
    Scenario B: Stresses external network I/O (WHOIS port 43 socket,
    dnspython resolution, TLS handshakes, redirect traversals).
    """
    weight = 1
    wait_time = between(0.2, 0.8)

    @task
    def check_network_io_url(self):
        target = random.choice(NETWORK_IO_URLS)
        self._execute_check(target, scenario_tag="NETWORK_IO")


class MixedWorkloadUser(BaseCheckUrlUser):
    """
    Default Workload: Realistic production distribution combining both
    CPU-heavy and Network-I/O-heavy URLs.
    """
    weight = 3
    wait_time = between(0.1, 0.5)

    @task
    def check_mixed_url(self):
        target = random.choice(ALL_URLS)
        self._execute_check(target, scenario_tag="MIXED")
