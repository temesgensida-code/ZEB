import os
import uuid
from urllib.parse import urlparse

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .url_checks import analyze_url_structure, check_safe_browsing, normalize_url

# Global progress tracking dictionary
# Format: {session_id: {'currentStage': str, 'isComplete': bool}}
_progress_tracker = {}


def set_progress(session_id, stage):
	"""Update the current checking stage for a session."""
	if session_id not in _progress_tracker:
		_progress_tracker[session_id] = {'currentStage': stage, 'isComplete': False}
	else:
		_progress_tracker[session_id]['currentStage'] = stage


def mark_complete(session_id):
	"""Mark a session as complete."""
	if session_id in _progress_tracker:
		_progress_tracker[session_id]['isComplete'] = True


def get_progress(session_id):
	"""Get the current progress for a session."""
	return _progress_tracker.get(session_id, {'currentStage': 'Initializing...', 'isComplete': False})


def cleanup_progress(session_id):
	"""Clean up progress tracking for a session."""
	_progress_tracker.pop(session_id, None)


class UrlSafetyCheckView(APIView):
	authentication_classes = []
	permission_classes = [AllowAny]

	def post(self, request):
		raw_url = request.data.get('url', '')
		session_id = str(uuid.uuid4())
		
		set_progress(session_id, 'Validating URL format...')
		target_url = normalize_url(raw_url)

		parsed = urlparse(target_url)
		if not parsed.scheme or not parsed.netloc:
			cleanup_progress(session_id)
			return Response(
				{'error': 'Please provide a valid URL.'},
				status=status.HTTP_400_BAD_REQUEST,
			)

		api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
		if not api_key:
			cleanup_progress(session_id)
			return Response(
				{'error': 'Google Safe Browsing API key is missing in .env.'},
				status=status.HTTP_500_INTERNAL_SERVER_ERROR,
			)

		set_progress(session_id, 'Checking against Google Safe Browsing...')
		try:
			threats = check_safe_browsing(target_url, api_key)
		except RuntimeError as exc:
			cleanup_progress(session_id)
			return Response(
				{'error': str(exc)},
				status=status.HTTP_502_BAD_GATEWAY,
			)
		except ConnectionError as exc:
			cleanup_progress(session_id)
			return Response(
				{'error': str(exc)},
				status=status.HTTP_502_BAD_GATEWAY,
			)

		set_progress(session_id, 'Analyzing URL structure...')
		structure_analysis = analyze_url_structure(target_url)

		unsafe = len(threats) > 0
		verdict = 'UNSAFE' if unsafe else 'UNSURE'

		mark_complete(session_id)
		cleanup_progress(session_id)

		response_data = {
			'url': target_url,
			'verdict': verdict,
			'unsafe': unsafe,
			'message': (
				'Potentially unsafe URL detected.'
				if unsafe
				else (
					'No known threats were found by Google Safe Browsing, '
					'but this does not guarantee the URL is safe.'
				)
			),
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
