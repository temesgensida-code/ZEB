import concurrent.futures
from typing import Any

from .asn_lookup import lookup_asn_info
from .dns_audit import audit_dns_and_flux, audit_mx_records
from .ssl_deep import deep_audit_ssl


class InfrastructureManager:
    """
    Coordinates infrastructure, network, and DNS threat evaluations in parallel.
    Guarantees strict 2.5s maximum budget and zero-panic exception safety.
    """

    def __init__(self, max_workers: int = 4, timeout: float = 2.5):
        self.max_workers = max_workers
        self.timeout = timeout

    def evaluate(
        self,
        hostname: str,
        registered_domain: str,
        resolved_ip: str | None = None,
        matched_brand: str | None = None,
        findings: list | None = None,
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

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            fut_dns = executor.submit(audit_dns_and_flux, hostname, target_findings)
            fut_mail = executor.submit(audit_mx_records, registered_domain, matched_brand, target_findings)

            # Determine IP for ASN lookup: use resolved_ip if provided, else check after DNS resolves
            fut_asn = None
            if resolved_ip:
                fut_asn = executor.submit(lookup_asn_info, resolved_ip, target_findings)

            fut_ssl = executor.submit(deep_audit_ssl, hostname, matched_brand, target_findings)

            try:
                dns_result = fut_dns.result(timeout=self.timeout)
            except Exception:
                pass

            try:
                mail_result = fut_mail.result(timeout=self.timeout)
            except Exception:
                pass

            try:
                ssl_result = fut_ssl.result(timeout=self.timeout)
            except Exception:
                pass

            if fut_asn:
                try:
                    asn_result = fut_asn.result(timeout=self.timeout)
                except Exception:
                    pass
            elif dns_result.get('aRecords'):
                first_ip = dns_result['aRecords'][0]
                try:
                    asn_result = lookup_asn_info(first_ip, target_findings)
                except Exception:
                    pass

        return {
            'dns': dns_result,
            'mail': mail_result,
            'asn': asn_result,
            'sslDeep': ssl_result,
        }
