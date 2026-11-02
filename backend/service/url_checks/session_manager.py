"""
Session Manager for Asynchronous URL Checking
Provides context-managed aiohttp.ClientSession instances with zero-trust network tuning,
custom timeouts, connection pooling, and SSL tolerance for probing untrusted hosts.
"""

from contextlib import asynccontextmanager
import aiohttp


@asynccontextmanager
async def create_scan_session(total_timeout: float = 12.0):
    """
    Yields an aiohttp.ClientSession configured for high-concurrency inspection:
    - 30 max connections, 6 max per host.
    - Ephemeral dummy cookie jar preventing cookie retention across scans.
    - Zero-panic timeout configuration.
    """
    timeout = aiohttp.ClientTimeout(
        total=total_timeout,
        connect=3.0,
        sock_read=7.0,
    )
    connector = aiohttp.TCPConnector(
        limit=30,
        limit_per_host=6,
        ttl_dns_cache=300,
        ssl=False,  # Allow probing sites with expired or self-signed certs
    )
    cookie_jar = aiohttp.DummyCookieJar()

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        cookie_jar=cookie_jar,
        headers={'User-Agent': 'zeb-url-checker-sandbox/2.0'},
    ) as session:
        yield session
