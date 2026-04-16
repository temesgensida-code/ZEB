import os
from urllib.parse import urlparse

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .url_checks import analyze_url_structure, check_safe_browsing, normalize_url


class UrlSafetyCheckView(APIView):
	authentication_classes = []
	permission_classes = [AllowAny]

	def post(self, request):
		raw_url = request.data.get('url', '')
		target_url = normalize_url(raw_url)

		parsed = urlparse(target_url)
		if not parsed.scheme or not parsed.netloc:
			return Response(
				{'error': 'Please provide a valid URL.'},
				status=status.HTTP_400_BAD_REQUEST,
			)

		api_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
		if not api_key:
			return Response(
				{'error': 'Google Safe Browsing API key is missing in .env.'},
				status=status.HTTP_500_INTERNAL_SERVER_ERROR,
			)

		try:
			threats = check_safe_browsing(target_url, api_key)
		except RuntimeError as exc:
			return Response(
				{'error': str(exc)},
				status=status.HTTP_502_BAD_GATEWAY,
			)
		except ConnectionError as exc:
			return Response(
				{'error': str(exc)},
				status=status.HTTP_502_BAD_GATEWAY,
			)

		structure_analysis = analyze_url_structure(target_url)

		unsafe = len(threats) > 0
		verdict = 'UNSAFE' if unsafe else 'UNSURE'

		return Response(
			{
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
			},
			status=status.HTTP_200_OK,
		)
