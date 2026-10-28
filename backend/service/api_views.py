"""
Developer API Scan View (Pillar 7)
Dedicated high-throughput developer scan endpoint with API key authentication,
usage logging, and strict third-party commercial service isolation.
"""

import time
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .mongo import authenticate_api_key, check_quota_and_rate_limit, record_usage_log
from .url_checks import normalize_url, analyze_url_structure


class DeveloperScanView(APIView):
    """
    POST /api/v1/scan
    Public developer endpoint providing programmatic access to ZEB's proprietary
    zero-trust heuristics. Commercial third-party threat feeds (Google Safe Browsing,
    VirusTotal) are strictly excluded.
    """
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        start_time = time.time()

        # 1. Authenticate API Key
        raw_key = request.headers.get('X-API-Key') or request.META.get('HTTP_X_API_KEY')
        key_doc = authenticate_api_key(raw_key)
        if not key_doc:
            return Response(
                {
                    'error': 'Invalid, expired, or missing API key.',
                    'hint': 'Include a valid key via header: X-API-Key: zeb_live_...',
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # 2. Enforce Rate Limits & Daily Quota
        allowed, throttle_msg = check_quota_and_rate_limit(key_doc)
        if not allowed:
            return Response(
                {'error': throttle_msg},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # 3. Validate & Canonicalize Target URL
        target_url = (request.data.get('url') or '').strip()
        canonical_url = normalize_url(target_url)
        if not canonical_url:
            return Response(
                {'error': 'A valid http:// or https:// URL is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 4. Execute ZEB Proprietary Heuristics Matrix (STRICTLY NO THIRD-PARTY FEEDS)
        # Note: analyze_url_structure runs Pillars 1, 3, 4, 5 heuristics
        structure_analysis = analyze_url_structure(canonical_url)

        findings = structure_analysis.get('findings', [])
        flagged_count = sum(1 for f in findings if f.get('flagged'))

        high_severity_types = {
            'WEB3_BLIND_SIGN_DRAINER',
            'DOUBLE_EXTENSION_DECEPTION',
            'EXFILTRATION_SINK_DETECTED',
            'USERINFO_SPOOFING_ATTACK',
            'FAST_FLUX_DETECTED',
            'BULLETPROOF_HOSTING_DETECTED',
            'OBFUSCATED_IP_ROUTING',
            'PASSWORD_ON_UNENCRYPTED_ORIGIN',
        }

        has_critical = any(f.get('type') in high_severity_types for f in findings)
        sandbox = structure_analysis.get('sandboxPreview') or {}
        risk_score = sandbox.get('riskScore', 0)

        if has_critical or risk_score >= 60:
            verdict = 'UNSAFE'
        elif flagged_count > 0 or risk_score >= 30:
            verdict = 'UNSURE'
        else:
            verdict = 'SAFE'

        latency_ms = max(1, int((time.time() - start_time) * 1000))

        # 5. High-Velocity MongoDB Audit Logging
        client_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '127.0.0.1'))
        if ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()

        record_usage_log(
            key_doc=key_doc,
            target_url=target_url,
            response_status=200,
            latency_ms=latency_ms,
            client_ip=client_ip,
        )

        # 6. Structured Developer Response
        return Response(
            {
                'targetUrl': target_url,
                'canonicalUrl': canonical_url,
                'verdict': verdict,
                'riskScore': risk_score,
                'flaggedSignalsCount': flagged_count,
                'analysis': structure_analysis,
                'engineNotice': 'Analyzed exclusively with ZEB proprietary zero-trust heuristics (Third-party commercial APIs omitted).',
                'meta': {
                    'latencyMs': latency_ms,
                    'keyPrefix': key_doc.get('key_prefix'),
                    'timestamp': time.time(),
                },
            },
            status=status.HTTP_200_OK,
        )
