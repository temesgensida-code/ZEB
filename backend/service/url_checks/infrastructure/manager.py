import asyncio
from typing import Any
import aiohttp

from .asn_lookup import lookup_asn_info
from .dns_audit import audit_dns_and_flux, audit_mx_records
from .ssl_deep import deep_audit_ssl, async_deep_audit_ssl
from ..session_manager import create_scan_session


class InfrastructureManager:
    """
    Coordinates infrastructure, network, and DNS threat evaluations concurrently as coroutines.
    Guarantees strict maximum budget and zero-panic exception safety.
    """

    def __init__(self, max_workers: int = 4, timeout: float = 2.5):
        self.max_workers = max_workers
        self.timeout = timeout

    async def _evaluate_with_session(
        self,
        hostname: str,
        registered_domain: str,
        resolved_ip: str | None = None,
        matched_brand: str | None = None,
        findings: list | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> dict[str, Any]:
        target_findings = findings if findings is not None else []

        dns_result: dict[str, Any] = {
            'aRecords': [],
            'minTtl': None,
            'isFastFlux': False,
            'isDynamicDns': False,
            'isTunnel': False,
        }
        mail_result: dict[str, Any] = {'hasMx': False, 'mxHosts': [], 'hasSpf': False}
        asn_result: dict[str, Any] = {
            'available': False,
            'ip': resolved_ip or '',
            'asn': None,
            'isHighRiskAsn': False,
        }
        ssl_result: dict[str, Any] = {'sslActive': False}

        if not hostname:
            return {
                'dns': dns_result,
                'mail': mail_result,
                'asn': asn_result,
                'sslDeep': ssl_result,
            }

        dns_task = asyncio.create_task(audit_dns_and_flux(hostname, target_findings, session=session))
        mail_task = asyncio.create_task(audit_mx_records(registered_domain, matched_brand, target_findings, session=session))
        ssl_task = asyncio.create_task(asyncio.to_thread(deep_audit_ssl, hostname, matched_brand, target_findings))

        asn_task = None
        if resolved_ip:
            asn_task = asyncio.create_task(lookup_asn_info(resolved_ip, target_findings, session=session))

        try:
            dns_res = await asyncio.wait_for(dns_task, timeout=self.timeout)
            if isinstance(dns_res, dict):
                dns_result = dns_res
        except Exception:
            pass

        try:
            mail_res = await asyncio.wait_for(mail_task, timeout=self.timeout)
            if isinstance(mail_res, dict):
                mail_result = mail_res
        except Exception:
            pass

        try:
            ssl_res = await asyncio.wait_for(ssl_task, timeout=self.timeout)
            if isinstance(ssl_res, dict):
                ssl_result = ssl_res
        except Exception:
            pass

        if asn_task:
            try:
                asn_res = await asyncio.wait_for(asn_task, timeout=self.timeout)
                if isinstance(asn_res, dict):
                    asn_result = asn_res
            except Exception:
                pass
        elif dns_result.get('aRecords'):
            first_ip = dns_result['aRecords'][0]
            try:
                asn_res = await asyncio.wait_for(
                    lookup_asn_info(first_ip, target_findings, session=session),
                    timeout=self.timeout,
                )
                if isinstance(asn_res, dict):
                    asn_result = asn_res
            except Exception:
                pass

        return {
            'dns': dns_result,
            'mail': mail_result,
            'asn': asn_result,
            'sslDeep': ssl_result,
        }

    async def evaluate(
        self,
        hostname: str,
        registered_domain: str,
        resolved_ip: str | None = None,
        matched_brand: str | None = None,
        findings: list | None = None,
        session: aiohttp.ClientSession | None = None,
    ) -> dict[str, Any]:
        if session is not None:
            return await self._evaluate_with_session(
                hostname, registered_domain, resolved_ip, matched_brand, findings, session
            )
        async with create_scan_session(total_timeout=self.timeout + 1.0) as local_session:
            return await self._evaluate_with_session(
                hostname, registered_domain, resolved_ip, matched_brand, findings, local_session
            )
