import asyncio
import json
import logging
import os
import time
import uuid
from urllib.parse import urlparse

from django.http import StreamingHttpResponse
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
import tldextract

from .async_api import AsyncAPIView

from .url_checks import (
    analyze_url_structure,
    check_safe_browsing,
    create_scan_session,
    defang_url,
    normalize_url,
    refang_url,
    threat_intel_manager,
)
from .url_checks.common import (
    decode_obfuscated_ip,
    detect_typosquatting_brand,
    extract_and_audit_userinfo,
    is_ip_host,
    is_ip_like_host,
)
from .url_checks.constants import (
    BRAND_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from .url_checks.domain_age import analyze_domain_age
from .url_checks.dynamic_sandbox import dynamic_sandbox_manager
from .url_checks.infrastructure import infrastructure_manager
from .url_checks.redirect_chain import analyze_redirect_chain
from .url_checks.sandbox_preview import analyze_sandbox_preview
from .url_checks.structure import analyze_idn_homographs

logger = logging.getLogger(__name__)

CRITICAL_THREAT_TYPES = frozenset({
    'EXFILTRATION_SINK_DETECTED',
    'USERINFO_DECEPTION_ATTACK',
    'MIXED_SCRIPT_HOMOGRAPH',
    'WHOLE_SCRIPT_HOMOGRAPH',
    'SSRF_ATTEMPT_BLOCKED',
    'OBFUSCATED_IP_ADDRESS',
    'FAST_FLUX_NETWORK',
    'BRAND_SPOOF_NO_MX',
    'FREE_SSL_ON_BRAND_LURE',
    'HIGH_RISK_HOSTING_ASN',
    'DOUBLE_EXTENSION_DECEPTION',
    'DANGEROUS_EXECUTABLE_DOWNLOAD',
    'WEB3_BLIND_SIGN_DRAINER',
    'WEB3_NFT_APPROVAL_DRAINER',
    'WEB3_PERMIT2_ALLOWANCE_DRAINER',
    'EXCESSIVE_IDENTITY_HARVESTING',
    'INSECURE_HTTP_CREDENTIAL_FORM',
    'CLICKJACKING_OVERLAY_TRAP',
    'REALTIME_OTP_HARVESTING_LURE',
    'AUTOMATED_DRIVE_BY_DOWNLOAD',
    'CRITICAL_VISUAL_BRAND_IMPERSONATION',
    'ANTI_ANALYSIS_CLOAKING_DETECTED',
})


def _format_sse(event: str, data: dict) -> str:
    """Format Server-Sent Event chunk according to text/event-stream spec."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

# ── Global progress tracking ──────────────────────────────────────────────────
# Format: {session_id: {'currentStage': str, 'isComplete': bool}}
_progress_tracker = {}


def set_progress(session_id: str, stage: str) -> None:
	"""Update the current checking stage for a session."""
	_progress_tracker[session_id] = {
		'currentStage': stage,
		'isComplete': False,
	}


def mark_complete(session_id: str) -> None:
	"""Mark a session as complete."""
	if session_id in _progress_tracker:
		_progress_tracker[session_id]['isComplete'] = True


def get_progress(session_id: str) -> dict:
	"""Get the current progress for a session."""
	return _progress_tracker.get(
		session_id,
		{'currentStage': 'Initializing...', 'isComplete': False},
	)


def cleanup_progress(session_id: str) -> None:
	"""Clean up progress tracking for a session."""
	_progress_tracker.pop(session_id, None)


def _is_shortener_url(url: str) -> bool:
	"""Return True if the URL's host is a known shortener domain."""
	try:
		host = urlparse(url).hostname or ''
		return host.lower() in URL_SHORTENERS
	except Exception:
		return False


def _build_url_exposure(raw_url: str, canonical_url: str, structure_analysis: dict, original_input_type: str) -> dict:
	sa = structure_analysis or {}
	userinfo = sa.get('userinfoAnalysis') or {}
	ip_obf = sa.get('ipObfuscation') or {}
	idn = sa.get('idnAnalysis') or {}
	redirect_analysis = sa.get('redirectAnalysis') or {}
	sandbox = sa.get('sandboxPreview') or {}
	link_xray = sandbox.get('linkXRay') or {
		'forms': [],
		'externalAssetCount': 0,
		'hiddenIframesCount': 0,
		'exfiltrationSinksDetected': [],
	}

	parsed = urlparse(canonical_url)
	raw_host = parsed.netloc or sa.get('hostname', '')

	return {
		'originalInputType': original_input_type,
		'hostAnalysis': {
			'rawHost': raw_host,
			'canonicalHost': ip_obf.get('decodedIp') or sa.get('hostname', ''),
			'userinfoDeception': {
				'detected': bool(userinfo.get('flagged')),
				'deceptivePrefix': userinfo.get('deceptivePrefix', ''),
				'targetHost': userinfo.get('cleanHost', ''),
			},
			'ipEncoding': {
				'isObfuscated': bool(ip_obf.get('isObfuscated')),
				'format': ip_obf.get('format'),
				'decodedIp': ip_obf.get('decodedIp'),
			},
			'idn': {
				'isIdn': bool(idn.get('isIdn')),
				'punycode': idn.get('punycode', ''),
				'unicode': idn.get('unicode', ''),
				'hasMixedScript': bool(idn.get('hasMixedScript')),
				'confusableGlyphs': idn.get('confusableGlyphs', []),
			},
		},
		'traversal': {
			'initialUrl': canonical_url,
			'unrolledParameters': redirect_analysis.get('unrolledParameters', []),
			'hops': redirect_analysis.get('hops', []),
			'totalHops': len(redirect_analysis.get('hops', [])),
			'finalUrl': redirect_analysis.get('finalUrl', canonical_url),
		},
		'linkXRay': {
			'forms': link_xray.get('forms', []),
			'externalAssetCount': link_xray.get('externalAssetCount', 0),
			'hiddenIframesCount': link_xray.get('hiddenIframesCount', 0),
			'exfiltrationSinksDetected': link_xray.get('exfiltrationSinksDetected', []),
		},
	}


def _build_verdict(ti_result: dict, structure_analysis: dict) -> tuple[str, str]:
	"""Derive a consolidated verdict string and human-readable explanation."""
	ti = ti_result or {}
	threat_types = ti.get('threatTypes', [])
	if ti.get('isThreat'):
		joined_types = ', '.join(threat_types) if threat_types else 'Malicious payload or phishing'
		return (
			'UNSAFE',
			f'This URL has been flagged as dangerous by threat intelligence engines ({joined_types}). '
			'Do NOT visit this site — it may contain malware, credential-harvesting phishing kits, '
			'or destructive payloads.',
		)

	sa = structure_analysis or {}
	findings = sa.get('findings', [])

	# Check high-confidence malicious findings from Pillar 1, Pillar 3 & Pillar 5
	critical_findings = [
		f for f in findings
		if f.get('flagged') and f.get('type') in CRITICAL_THREAT_TYPES
	]
	if critical_findings:
		return (
			'UNSAFE',
			f"Critical threat detected: {critical_findings[0]['explanation']}",
		)

	risk_signals = []
	if sa.get('isIpBased'):
		risk_signals.append('IP-based host')
	if sa.get('hasSuspiciousTld'):
		risk_signals.append('suspicious TLD')
	if sa.get('hasTyposquattingSignal'):
		risk_signals.append('possible brand impersonation')
	if sa.get('hasNewDomainRisk'):
		risk_signals.append('recently registered domain')
	if sa.get('hasRedirectRisk'):
		risk_signals.append('suspicious redirect chain')

	infra = sa.get('infrastructure', {}) or {}
	dns_data = infra.get('dns', {}) or {}
	if dns_data.get('isDynamicDns'):
		risk_signals.append('hosted on Dynamic DNS')
	if dns_data.get('isTunnel'):
		risk_signals.append('ephemeral reverse tunnel')
	ssl_data = infra.get('sslDeep', {}) or {}
	if ssl_data.get('isVeryRecent'):
		risk_signals.append('very recent SSL certificate (<24h)')

	sandbox = sa.get('sandboxPreview', {}) or {}
	sandbox_risk = sandbox.get('riskScore', 0)
	if sandbox_risk >= 50:
		risk_signals.append(f'high sandbox risk score ({sandbox_risk}/100)')
	elif sandbox_risk >= 25:
		risk_signals.append(f'moderate sandbox risk score ({sandbox_risk}/100)')

	if risk_signals:
		joined = ', '.join(risk_signals)
		return (
			'UNSURE',
			f'No cataloged threat intelligence matches were found, but we detected risk signals: {joined}. '
			'Exercise caution before visiting or entering credentials on this site.',
		)

	if ti.get('evaluationDegraded'):
		return (
			'UNSURE',
			'External threat intelligence feeds were temporarily unreachable or rate-limited; '
			'verdict is based entirely on structural and passive content analysis.',
		)

	return (
		'SAFE',
		'No known threats were detected by multi-engine threat intelligence feeds, '
		'and our structural analysis did not identify strong risk signals. '
		'Always remain vigilant.',
	)


class UrlSafetyCheckView(AsyncAPIView):
	authentication_classes = []
	permission_classes = [AllowAny]

	async def post(self, request):
		t_view_start = time.perf_counter()
		raw_url = request.data.get('url', '')
		session_id = request.data.get('sessionId') or str(uuid.uuid4())

		# ── Stage 1: Validate & Re-fang ──────────────────────────────────────
		t_cpu0 = time.perf_counter()
		set_progress(session_id, 'Validating URL format...')
		refanged_raw = refang_url(raw_url)
		is_defanged = raw_url.strip() != refanged_raw.strip()
		original_input_type = 'DEFANGED_URL' if is_defanged else 'STANDARD_URL'

		target_url = normalize_url(refanged_raw)

		parsed = urlparse(target_url)
		if not parsed.scheme or not parsed.netloc:
			cleanup_progress(session_id)
			total_ms = (time.perf_counter() - t_view_start) * 1000
			resp = Response(
				{'error': 'Please provide a valid URL (e.g. https://example.com or bit.ly/abc).'},
				status=status.HTTP_400_BAD_REQUEST,
			)
			resp['X-Time-Total-Ms'] = f"{total_ms:.2f}"
			resp['X-Time-Network-IO-Ms'] = "0.00"
			resp['X-Time-CPU-Ms'] = f"{total_ms:.2f}"
			return resp

		is_shortener = _is_shortener_url(target_url)
		cpu_stage1_ms = (time.perf_counter() - t_cpu0) * 1000

		# ── Stage 2-7: Parallel Dispatch of Threat Intel & Structure Analysis ──
		set_progress(session_id, 'Querying multi-engine threat intelligence feeds & structural heuristics...')
		telemetry = {}
		t_net0 = time.perf_counter()

		async with create_scan_session(total_timeout=15.0) as session:
			ti_task = asyncio.create_task(threat_intel_manager.evaluate(target_url, session=session))
			struct_task = asyncio.create_task(analyze_url_structure(target_url, telemetry=telemetry, session=session))

			ti_result, structure_analysis = await asyncio.gather(ti_task, struct_task)

		threat_intel_io_ms = (time.perf_counter() - t_net0) * 1000
		threats = ti_result.get('threatTypes', [])

		# ── Stage 8: Verdict & Exposure ───────────────────────────────────────
		t_scoring0 = time.perf_counter()
		verdict, message = _build_verdict(ti_result, structure_analysis)
		url_exposure = _build_url_exposure(raw_url, target_url, structure_analysis, original_input_type)
		scoring_cpu_ms = (time.perf_counter() - t_scoring0) * 1000

		mark_complete(session_id)
		cleanup_progress(session_id)

		response_data = {
			'url': target_url,
			'rawInput': raw_url,
			'defangedUrl': defang_url(target_url),
			'verdict': verdict,
			'unsafe': verdict == 'UNSAFE',
			'isShortener': is_shortener,
			'message': message,
			'threats': threats,
			'threatIntel': ti_result,
			'structureAnalysis': structure_analysis,
			'urlExposure': url_exposure,
			'sessionId': session_id,
		}

		total_ms = (time.perf_counter() - t_view_start) * 1000
		network_io_ms = (
			threat_intel_io_ms +
			telemetry.get('io_whois_ms', 0.0) +
			telemetry.get('io_redirect_ms', 0.0) +
			telemetry.get('io_sandbox_ssl_ms', 0.0) +
			telemetry.get('io_sandbox_http_ms', 0.0) +
			telemetry.get('io_infra_ms', 0.0)
		)
		cpu_ms = (
			cpu_stage1_ms +
			telemetry.get('cpu_structure_ms', 0.0) +
			telemetry.get('cpu_dom_analysis_ms', 0.0) +
			telemetry.get('dynamic_sandbox_ms', 0.0) +
			scoring_cpu_ms
		)

		breakdown_parts = [
			f"ti={threat_intel_io_ms:.1f}ms",
			f"whois={telemetry.get('io_whois_ms', 0.0):.1f}ms",
			f"redirect={telemetry.get('io_redirect_ms', 0.0):.1f}ms",
			f"sandbox_ssl={telemetry.get('io_sandbox_ssl_ms', 0.0):.1f}ms",
			f"sandbox_http={telemetry.get('io_sandbox_http_ms', 0.0):.1f}ms",
			f"infra={telemetry.get('io_infra_ms', 0.0):.1f}ms",
			f"cpu_struct={telemetry.get('cpu_structure_ms', 0.0):.1f}ms",
			f"cpu_dom={telemetry.get('cpu_dom_analysis_ms', 0.0):.1f}ms",
			f"scoring={scoring_cpu_ms:.1f}ms",
		]
		breakdown_str = ';'.join(breakdown_parts)

		response = Response(response_data, status=status.HTTP_200_OK)
		response['X-Session-ID'] = session_id
		response['X-Time-Total-Ms'] = f"{total_ms:.2f}"
		response['X-Time-Network-IO-Ms'] = f"{network_io_ms:.2f}"
		response['X-Time-CPU-Ms'] = f"{cpu_ms:.2f}"
		response['X-Time-Breakdown'] = breakdown_str
		return response


class UrlCheckProgressView(AsyncAPIView):
	authentication_classes = []
	permission_classes = [AllowAny]

	async def get(self, request):
		session_id = request.query_params.get('sessionId')
		if not session_id:
			return Response(
				{'error': 'sessionId is required'},
				status=status.HTTP_400_BAD_REQUEST,
			)
		progress = get_progress(session_id)
		return Response(progress, status=status.HTTP_200_OK)


class UrlSafetyCheckStreamView(AsyncAPIView):
	"""
	POST /api/check-url/stream/
	Asynchronous Server-Sent Events (SSE) streaming endpoint.
	Emits subsystem completion events sequentially over an async generator,
	enforcing monotonic verdict progression to eliminate conflicting verdicts.
	"""
	authentication_classes = []
	permission_classes = [AllowAny]

	async def post(self, request):
		t_view_start = time.perf_counter()
		raw_url = request.data.get('url', '')
		session_id = request.data.get('sessionId') or str(uuid.uuid4())

		refanged_raw = refang_url(raw_url)
		is_defanged = raw_url.strip() != refanged_raw.strip()
		original_input_type = 'DEFANGED_URL' if is_defanged else 'STANDARD_URL'
		target_url = normalize_url(refanged_raw)

		parsed = urlparse(target_url)
		if not parsed.scheme or not parsed.netloc:
			return Response(
				{'error': 'Please provide a valid URL (e.g. https://example.com or bit.ly/abc).'},
				status=status.HTTP_400_BAD_REQUEST,
			)

		is_shortener = _is_shortener_url(target_url)

		async def sse_event_generator():
			tasks = []
			try:
				# 1. Emit init event instantly
				init_data = {
					'canonicalUrl': target_url,
					'rawInput': raw_url,
					'defangedUrl': defang_url(target_url),
					'sessionId': session_id,
					'isShortener': is_shortener,
					'originalInputType': original_input_type,
					'totalEngines': 6,
				}
				yield _format_sse('init', init_data)

				# 2. Fast CPU Pre-flight Analysis
				hostname = (parsed.hostname or '').lower()
				tld = ''
				registered_domain = ''
				registered_domain_full = ''
				if hostname:
					extracted = tldextract.extract(hostname)
					tld = extracted.suffix.lower()
					registered_domain = extracted.domain.lower()
					registered_domain_full = extracted.registered_domain.lower()

				has_ip_host = (is_ip_host(hostname) or is_ip_like_host(hostname)) if hostname else False
				is_suspicious_tld = tld.split('.')[-1] in SUSPICIOUS_TLDS if tld else False
				typosquatting_match = detect_typosquatting_brand(registered_domain)
				has_typosquatting_signal = typosquatting_match is not None

				decoded_ip, ip_obf_type = decode_obfuscated_ip(hostname) if hostname else (None, None)
				is_obfuscated_ip = ip_obf_type is not None
				userinfo_data = extract_and_audit_userinfo(target_url)
				idn_analysis = analyze_idn_homographs(hostname) if hostname else {}

				preflight_findings = []
				if userinfo_data.get('flagged'):
					preflight_findings.append({
						'type': 'USERINFO_DECEPTION_ATTACK',
						'flagged': True,
						'explanation': userinfo_data['explanation'],
					})
				if is_obfuscated_ip:
					preflight_findings.append({
						'type': 'OBFUSCATED_IP_ADDRESS',
						'flagged': True,
						'explanation': (
							f"The URL hostname '{hostname}' is an obfuscated {ip_obf_type} representation "
							f"of IP address {decoded_ip}. Attackers use alternate IP encodings to bypass filters."
						),
					})
				elif has_ip_host:
					preflight_findings.append({
						'type': 'IP_BASED_URL',
						'flagged': True,
						'explanation': (
							'The URL uses an IP address instead of a readable domain name. '
							'Attackers often do this to hide identity and quickly rotate hosts.'
						),
					})
				if idn_analysis.get('hasMixedScript'):
					scripts_joined = ', '.join(idn_analysis['scriptHistogram'].keys())
					preflight_findings.append({
						'type': 'MIXED_SCRIPT_HOMOGRAPH',
						'flagged': True,
						'explanation': (
							f"Internationalized Domain Name spoofing detected: Domain uses mixed Unicode scripts "
							f"({scripts_joined}) containing confusable look-alike characters "
							f"rendered as '{idn_analysis['unicode']}' (Punycode: {idn_analysis['punycode']})."
						),
					})
				elif idn_analysis.get('isIdn') and (
					idn_analysis.get('confusableGlyphs')
					or any(b in idn_analysis.get('skeleton', '') for b in BRAND_KEYWORDS)
				):
					preflight_findings.append({
						'type': 'WHOLE_SCRIPT_HOMOGRAPH',
						'flagged': True,
						'explanation': (
							f"Unicode homograph detected: Host displays look-alike characters mapping to ASCII skeleton "
							f"'{idn_analysis['skeleton']}' (Punycode: {idn_analysis['punycode']})."
						),
					})
				if is_suspicious_tld:
					preflight_findings.append({
						'type': 'SUSPICIOUS_TLD',
						'flagged': True,
						'explanation': (
							f"The top-level domain '.{tld.split('.')[-1]}' is frequently abused "
							'in phishing and scam campaigns due to low registration friction.'
						),
					})
				if has_typosquatting_signal:
					preflight_findings.append({
						'type': 'TYPOSQUATTING_SIGNAL',
						'flagged': True,
						'explanation': (
							f"The domain looks like a typo variant of '{typosquatting_match}' "
							'for example letter substitution like faceb00k, '
							'which is a common credential-harvesting trick.'
						),
					})

				escalated_to_unsafe = False
				for f in preflight_findings:
					if f.get('flagged') and f.get('type') in CRITICAL_THREAT_TYPES:
						escalated_to_unsafe = True
						yield _format_sse('critical_escalation', {
							'verdict': 'UNSAFE',
							'subsystem': 'preflight',
							'threatSignal': f['type'],
							'explanation': f['explanation'],
							'timestamp': time.time(),
						})
						break

				# 3. Open Context-Managed Scan Session & Concurrent Queue
				async with create_scan_session(total_timeout=18.0) as session:
					queue = asyncio.Queue()
					redirect_ready_evt = asyncio.Event()
					redirect_holder = [None]

					async def run_threat_intel():
						t0 = time.perf_counter()
						try:
							res = await threat_intel_manager.evaluate(target_url, session=session)
							is_threat = bool(res.get('isThreat'))
							badge = 'FLAGGED' if is_threat else 'CLEAN'
							await queue.put(('threat_intel', res, [], badge, (time.perf_counter() - t0) * 1000))
						except Exception as exc:
							logger.exception("Stream threat intel worker error: %s", exc)
							await queue.put(('threat_intel', {'isThreat': False, 'threatTypes': [], 'evaluationDegraded': True}, [], 'DEGRADED', 0.0))

					async def run_infrastructure():
						t0 = time.perf_counter()
						findings = []
						try:
							res = await infrastructure_manager.evaluate(
								hostname=hostname,
								registered_domain=registered_domain_full,
								resolved_ip=decoded_ip if is_obfuscated_ip else None,
								matched_brand=typosquatting_match,
								findings=findings,
								session=session,
							)
							flagged = any(f.get('flagged') for f in findings)
							badge = 'FLAGGED' if flagged else 'CLEAN'
							await queue.put(('infrastructure', res, findings, badge, (time.perf_counter() - t0) * 1000))
						except Exception as exc:
							logger.exception("Stream infra worker error: %s", exc)
							await queue.put(('infrastructure', {'dns': {}, 'mail': {}, 'asn': {}, 'sslDeep': {}, 'evaluationDegraded': True}, [], 'DEGRADED', 0.0))

					async def run_domain_age():
						t0 = time.perf_counter()
						findings = []
						try:
							res = await analyze_domain_age(registered_domain_full, findings)
							flagged = bool(res.get('isNewDomain'))
							badge = 'FLAGGED' if flagged else 'CLEAN'
							await queue.put(('domain_age', res, findings, badge, (time.perf_counter() - t0) * 1000))
						except Exception as exc:
							logger.exception("Stream domain age worker error: %s", exc)
							await queue.put(('domain_age', {'available': False, 'isNewDomain': None, 'evaluationDegraded': True}, [], 'DEGRADED', 0.0))

					async def run_redirect_chain():
						t0 = time.perf_counter()
						findings = []
						try:
							res = await analyze_redirect_chain(target_url, registered_domain_full, findings, session=session)
							flagged = bool(
								res.get('tooManyRedirects')
								or len(res.get('suspiciousRedirectHops', [])) > 0
								or len(res.get('schemeDowngrades', [])) > 0
							)
							badge = 'FLAGGED' if flagged else 'CLEAN'
							redirect_holder[0] = res
							redirect_ready_evt.set()
							await queue.put(('redirect_chain', res, findings, badge, (time.perf_counter() - t0) * 1000))
						except Exception as exc:
							logger.exception("Stream redirect worker error: %s", exc)
							redirect_holder[0] = {'finalUrl': target_url}
							redirect_ready_evt.set()
							await queue.put(('redirect_chain', {'available': False, 'hops': [], 'finalUrl': target_url, 'evaluationDegraded': True}, [], 'DEGRADED', 0.0))

					async def run_sandbox_preview():
						try:
							await asyncio.wait_for(redirect_ready_evt.wait(), timeout=12.0)
						except Exception:
							pass
						t0 = time.perf_counter()
						findings = []
						dest_url = (redirect_holder[0] or {}).get('finalUrl') or target_url
						try:
							res = await analyze_sandbox_preview(dest_url, findings, session=session)
							risk = res.get('riskScore', 0)
							flagged = risk >= 25 or any(f.get('flagged') for f in findings)
							badge = 'FLAGGED' if flagged else 'CLEAN'
							await queue.put(('sandbox_preview', res, findings, badge, (time.perf_counter() - t0) * 1000))
						except Exception as exc:
							logger.exception("Stream sandbox preview worker error: %s", exc)
							await queue.put(('sandbox_preview', {'available': False, 'htmlAnalyzed': False, 'riskScore': 0, 'evaluationDegraded': True}, [], 'DEGRADED', 0.0))

					async def run_dynamic_sandbox():
						t0 = time.perf_counter()
						findings = []
						try:
							res = await dynamic_sandbox_manager.evaluate(
								target_url=target_url,
								registered_domain=registered_domain_full,
								findings=findings,
								session=session,
							)
							flagged = bool(res.get('cloakingDetected')) or any(f.get('flagged') for f in findings)
							badge = 'FLAGGED' if flagged else 'CLEAN'
							await queue.put(('dynamic_sandbox', res, findings, badge, (time.perf_counter() - t0) * 1000))
						except Exception as exc:
							logger.exception("Stream dynamic sandbox worker error: %s", exc)
							await queue.put(('dynamic_sandbox', {'cloakingDetected': False, 'headlessWorkerExecuted': False, 'evaluationDegraded': True}, [], 'DEGRADED', 0.0))

					tasks = [
						asyncio.create_task(run_threat_intel()),
						asyncio.create_task(run_infrastructure()),
						asyncio.create_task(run_domain_age()),
						asyncio.create_task(run_redirect_chain()),
						asyncio.create_task(run_sandbox_preview()),
						asyncio.create_task(run_dynamic_sandbox()),
					]

					all_subsystem_data = {}
					all_findings = list(preflight_findings)
					completed_count = 0

					while completed_count < 6:
						subsystem_key, data, findings, status_badge, latency = await queue.get()
						completed_count += 1
						all_subsystem_data[subsystem_key] = data
						all_findings.extend(findings)

						has_critical = any(
							f.get('flagged') and f.get('type') in CRITICAL_THREAT_TYPES
							for f in findings
						)
						if subsystem_key == 'threat_intel' and data.get('isThreat'):
							has_critical = True

						if has_critical and not escalated_to_unsafe:
							escalated_to_unsafe = True
							crit_expl = "Critical threat detected during progressive inspection."
							crit_type = "CRITICAL_THREAT"
							if subsystem_key == 'threat_intel':
								threat_types = data.get('threatTypes', [])
								crit_type = threat_types[0] if threat_types else 'THREAT_INTEL_MATCH'
								crit_expl = f"Threat intelligence match: {', '.join(threat_types)}"
							else:
								for f in findings:
									if f.get('flagged') and f.get('type') in CRITICAL_THREAT_TYPES:
										crit_type = f.get('type')
										crit_expl = f.get('explanation', crit_expl)
										break
							yield _format_sse('critical_escalation', {
								'verdict': 'UNSAFE',
								'subsystem': subsystem_key,
								'threatSignal': crit_type,
								'explanation': crit_expl,
								'timestamp': time.time(),
							})

						yield _format_sse('subsystem_result', {
							'subsystem': subsystem_key,
							'statusBadge': status_badge,
							'data': data,
							'findings': findings,
							'completedCount': completed_count,
							'totalEngines': 6,
							'latencyMs': round(latency, 1),
							'engineLatencyMs': round(latency, 1),
						})

				if not all_findings:
					all_findings.append({
						'type': 'NO_STRONG_STRUCTURE_SIGNALS',
						'flagged': False,
						'explanation': 'No strong URL structure red flags were detected, but this still does not prove the destination is safe.',
					})

				sa = {
					'isIpBased': has_ip_host,
					'hasSuspiciousTld': is_suspicious_tld,
					'hasTyposquattingSignal': has_typosquatting_signal,
					'hasNewDomainRisk': bool((all_subsystem_data.get('domain_age') or {}).get('isNewDomain')),
					'hasRedirectRisk': bool(
						(all_subsystem_data.get('redirect_chain') or {}).get('tooManyRedirects')
						or len((all_subsystem_data.get('redirect_chain') or {}).get('suspiciousRedirectHops', [])) > 0
					),
					'hasSandboxContentRisk': bool(
						len((all_subsystem_data.get('sandbox_preview') or {}).get('matchedKeywords', [])) > 0
						or len((all_subsystem_data.get('sandbox_preview') or {}).get('fakeLoginForms', [])) > 0
						or len((all_subsystem_data.get('sandbox_preview') or {}).get('suspiciousScripts', [])) > 0
					),
					'hostname': hostname,
					'tld': tld,
					'registeredDomain': registered_domain,
					'registeredDomainFull': registered_domain_full,
					'domainAge': all_subsystem_data.get('domain_age', {}),
					'redirectAnalysis': all_subsystem_data.get('redirect_chain', {}),
					'sandboxPreview': all_subsystem_data.get('sandbox_preview', {}),
					'idnAnalysis': idn_analysis,
					'userinfoAnalysis': userinfo_data,
					'ipObfuscation': {
						'isObfuscated': is_obfuscated_ip,
						'format': ip_obf_type,
						'decodedIp': decoded_ip,
					},
					'infrastructure': all_subsystem_data.get('infrastructure', {}),
					'dynamicSandbox': all_subsystem_data.get('dynamic_sandbox', {}),
					'findings': all_findings,
				}

				ti_result = all_subsystem_data.get('threat_intel', {})
				verdict, message = _build_verdict(ti_result, sa)
				if escalated_to_unsafe:
					verdict = 'UNSAFE'

				url_exposure = _build_url_exposure(raw_url, target_url, sa, original_input_type)
				total_ms = (time.perf_counter() - t_view_start) * 1000

				final_payload = {
					'url': target_url,
					'rawInput': raw_url,
					'defangedUrl': defang_url(target_url),
					'verdict': verdict,
					'unsafe': verdict == 'UNSAFE',
					'isShortener': is_shortener,
					'message': message,
					'threats': ti_result.get('threatTypes', []),
					'threatIntel': ti_result,
					'structureAnalysis': sa,
					'urlExposure': url_exposure,
					'sessionId': session_id,
					'telemetry': {
						'totalMs': round(total_ms, 2),
					},
				}

				yield _format_sse('final_verdict', final_payload)
				yield _format_sse('complete', {'durationMs': round(total_ms, 2), 'timestamp': time.time()})

			except asyncio.CancelledError:
				logger.info("SSE streaming connection cancelled by client for session: %s", session_id)
				raise
			except Exception as exc:
				logger.exception("Unexpected error in SSE streaming generator: %s", exc)
				yield _format_sse('error', {'error': str(exc), 'hint': 'Safety audit stream encountered an internal error.'})
			finally:
				for t in tasks:
					if not t.done():
						t.cancel()

		response = StreamingHttpResponse(
			sse_event_generator(),
			content_type='text/event-stream; charset=utf-8',
		)
		response['Cache-Control'] = 'no-cache, no-transform'
		response['X-Accel-Buffering'] = 'no'
		response['X-Session-ID'] = session_id
		return response

