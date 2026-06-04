import os
import uuid
from urllib.parse import urlparse

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .url_checks import analyze_url_structure, check_safe_browsing, normalize_url
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


def _build_verdict(threats, structure_analysis) -> tuple[str, str]:
	"""Derive a verdict string and a human-readable message."""
	if threats:
		return (
			'UNSAFE',
			'This URL has been flagged as dangerous by Google Safe Browsing. '
			'Do NOT visit this site — it may contain malware, phishing forms, '
			'or other content that could harm your device or steal your information.',
		)

	sa = structure_analysis or {}
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
			f'No known Google Safe Browsing threats were found, but we detected some '
			f'risk signals: {joined}. Exercise caution before visiting or entering any '
			f'personal information on this site.',
		)

	return (
		'SAFE',
		'No known threats were found by Google Safe Browsing, and our structural '
		'and content analysis did not detect strong risk signals. '
		'This does not guarantee the URL is 100% safe — always be cautious.',
	)


class UrlSafetyCheckView(APIView):
	authentication_classes = []
	permission_classes = [AllowAny]

	def post(self, request):
		raw_url = request.data.get('url', '')
		session_id = request.data.get('sessionId') or str(uuid.uuid4())

		# ── Stage 1: Validate ─────────────────────────────────────────────────
		set_progress(session_id, 'Validating URL format...')
		target_url = normalize_url(raw_url)

		parsed = urlparse(target_url)
		if not parsed.scheme or not parsed.netloc:
			cleanup_progress(session_id)
			return Response(
				{'error': 'Please provide a valid URL (e.g. https://example.com or bit.ly/abc).'},
				status=status.HTTP_400_BAD_REQUEST,
			)

		api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
		if not api_key:
			cleanup_progress(session_id)
			return Response(
				{'error': 'Google Safe Browsing API key is missing from server configuration.'},
				status=status.HTTP_500_INTERNAL_SERVER_ERROR,
			)

		is_shortener = _is_shortener_url(target_url)

		# ── Stage 2: Google Safe Browsing ─────────────────────────────────────
		set_progress(session_id, 'Checking against Google Safe Browsing...')
		try:
			threats = check_safe_browsing(target_url, api_key)
		except (RuntimeError, ConnectionError) as exc:
			cleanup_progress(session_id)
			return Response({'error': str(exc)}, status=status.HTTP_502_BAD_GATEWAY)

		# ── Stage 3: URL structure ────────────────────────────────────────────
		set_progress(session_id, 'Analyzing URL structure...')

		# ── Stage 4: Domain age (triggered inside analyze_url_structure) ──────
		set_progress(session_id, 'Checking domain age via WHOIS...')

		# ── Stage 5: Redirect chain ────────────────────────────────────────────
		set_progress(session_id, 'Following redirect chain...')

		# ── Stage 6: Sandbox preview ───────────────────────────────────────────
		set_progress(session_id, 'Running sandbox page analysis...')

		structure_analysis = analyze_url_structure(target_url)

		verdict, message = _build_verdict(threats, structure_analysis)

		mark_complete(session_id)
		cleanup_progress(session_id)

		response_data = {
			'url': target_url,
			'verdict': verdict,
			'unsafe': verdict == 'UNSAFE',
			'isShortener': is_shortener,
			'message': message,
			'threats': threats,
			'structureAnalysis': structure_analysis,
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
