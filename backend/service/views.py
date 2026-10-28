import os
import uuid
from urllib.parse import urlparse

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .url_checks import (
    analyze_url_structure,
    check_safe_browsing,
    defang_url,
    normalize_url,
    refang_url,
    threat_intel_manager,
)
from .url_checks.constants import URL_SHORTENERS

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
		if f.get('flagged') and f.get('type') in (
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
		)
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


class UrlSafetyCheckView(APIView):
	authentication_classes = []
	permission_classes = [AllowAny]

	def post(self, request):
		raw_url = request.data.get('url', '')
		session_id = request.data.get('sessionId') or str(uuid.uuid4())

		# ── Stage 1: Validate & Re-fang ──────────────────────────────────────
		set_progress(session_id, 'Validating URL format...')
		refanged_raw = refang_url(raw_url)
		is_defanged = raw_url.strip() != refanged_raw.strip()
		original_input_type = 'DEFANGED_URL' if is_defanged else 'STANDARD_URL'

		target_url = normalize_url(refanged_raw)

		parsed = urlparse(target_url)
		if not parsed.scheme or not parsed.netloc:
			cleanup_progress(session_id)
			return Response(
				{'error': 'Please provide a valid URL (e.g. https://example.com or bit.ly/abc).'},
				status=status.HTTP_400_BAD_REQUEST,
			)

		is_shortener = _is_shortener_url(target_url)

		# ── Stage 2: Multi-Engine Threat Intelligence ─────────────────────────
		set_progress(session_id, 'Querying multi-engine threat intelligence feeds...')
		ti_result = threat_intel_manager.evaluate(target_url)
		threats = ti_result.get('threatTypes', [])

		# ── Stage 3: URL structure ────────────────────────────────────────────
		set_progress(session_id, 'Analyzing URL structure...')

		# ── Stage 4: Domain age (triggered inside analyze_url_structure) ──────
		set_progress(session_id, 'Checking domain age via WHOIS...')

		# ── Stage 5: Redirect chain ────────────────────────────────────────────
		set_progress(session_id, 'Following redirect chain...')

		# ── Stage 6: Sandbox preview ───────────────────────────────────────────
		set_progress(session_id, 'Running sandbox page analysis...')

		structure_analysis = analyze_url_structure(target_url)

		verdict, message = _build_verdict(ti_result, structure_analysis)
		url_exposure = _build_url_exposure(raw_url, target_url, structure_analysis, original_input_type)

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

		response = Response(response_data, status=status.HTTP_200_OK)
		response['X-Session-ID'] = session_id
		return response


class UrlCheckProgressView(APIView):
	authentication_classes = []
	permission_classes = [AllowAny]

	def get(self, request):
		session_id = request.query_params.get('sessionId')
		if not session_id:
			return Response(
				{'error': 'sessionId is required'},
				status=status.HTTP_400_BAD_REQUEST,
			)
		progress = get_progress(session_id)
		return Response(progress, status=status.HTTP_200_OK)
