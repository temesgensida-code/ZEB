import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class UrlSafetyCheckView(APIView):
	authentication_classes = []
	permission_classes = [AllowAny]

	@staticmethod
	def normalize_url(candidate_url: str) -> str:
		value = (candidate_url or '').strip()
		if value and '://' not in value:
			value = f'https://{value}'
		return value

	def post(self, request):
		raw_url = request.data.get('url', '')
		target_url = self.normalize_url(raw_url)

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

		payload = {
			'client': {'clientId': 'zeb-url-checker', 'clientVersion': '1.0.0'},
			'threatInfo': {
				'threatTypes': [
					'MALWARE',
					'SOCIAL_ENGINEERING',
					'UNWANTED_SOFTWARE',
					'POTENTIALLY_HARMFUL_APPLICATION',
				],
				'platformTypes': ['ANY_PLATFORM'],
				'threatEntryTypes': ['URL'],
				'threatEntries': [{'url': target_url}],
			},
		}

		endpoint = (
			'https://safebrowsing.googleapis.com/v4/threatMatches:find'
			f'?key={api_key}'
		)

		request_data = json.dumps(payload).encode('utf-8')
		api_request = Request(
			endpoint,
			data=request_data,
			headers={'Content-Type': 'application/json'},
			method='POST',
		)

		try:
			with urlopen(api_request, timeout=10) as upstream:
				body = upstream.read().decode('utf-8')
		except HTTPError as exc:
			return Response(
				{'error': f'Google API returned HTTP {exc.code}.'},
				status=status.HTTP_502_BAD_GATEWAY,
			)
		except URLError:
			return Response(
				{'error': 'Could not reach Google Safe Browsing API.'},
				status=status.HTTP_502_BAD_GATEWAY,
			)

		response_json = json.loads(body) if body else {}
		matches = response_json.get('matches', [])

		threats = [
			{
				'threatType': match.get('threatType', 'UNKNOWN'),
				'platformType': match.get('platformType', 'UNKNOWN'),
				'threatEntryType': match.get('threatEntryType', 'UNKNOWN'),
			}
			for match in matches
		]

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
			},
			status=status.HTTP_200_OK,
		)
