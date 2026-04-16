import json
import os
from datetime import date, datetime
from ipaddress import ip_address
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import tldextract
import whois
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


SUSPICIOUS_TLDS = {
	'xyz',
	'tk',
	'tu',
	'top',
	'gq',
	'ml',
	'cf',
	'ga',
	'click',
	'buzz',
	'work',
	'zip',
	'mov',
}

BRAND_KEYWORDS = {
	'facebook',
	'google',
	'microsoft',
	'apple',
	'amazon',
	'instagram',
	'netflix',
	'paypal',
	'whatsapp',
	'telegram',
	'bankofamerica',
}

CHAR_SUBSTITUTIONS = str.maketrans(
	{
		'0': 'o',
		'1': 'l',
		'3': 'e',
		'4': 'a',
		'5': 's',
		'7': 't',
		'8': 'b',
	}
)

NEW_DOMAIN_DAYS_THRESHOLD = 180


def levenshtein_distance(a: str, b: str) -> int:
	if a == b:
		return 0
	if not a:
		return len(b)
	if not b:
		return len(a)

	previous = list(range(len(b) + 1))
	for i, char_a in enumerate(a, start=1):
		current = [i]
		for j, char_b in enumerate(b, start=1):
			insertion = current[j - 1] + 1
			deletion = previous[j] + 1
			replacement = previous[j - 1] + (char_a != char_b)
			current.append(min(insertion, deletion, replacement))
		previous = current
	return previous[-1]


class UrlSafetyCheckView(APIView):
	authentication_classes = []
	permission_classes = [AllowAny]

	@staticmethod
	def normalize_url(candidate_url: str) -> str:
		value = (candidate_url or '').strip()
		if value and '://' not in value:
			value = f'https://{value}'
		return value

	@staticmethod
	def is_ip_host(hostname: str) -> bool:
		try:
			ip_address(hostname)
			return True
		except ValueError:
			return False

	@staticmethod
	def is_ip_like_host(hostname: str) -> bool:
		if not hostname:
			return False
		if ':' in hostname:
			return all(part == '' or all(c in '0123456789abcdefABCDEF' for c in part) for part in hostname.split(':'))

		labels = hostname.split('.')
		if len(labels) < 2:
			return False
		return all(label.isdigit() for label in labels if label)

	@staticmethod
	def parse_creation_date(value):
		if isinstance(value, datetime):
			return value.date()
		if isinstance(value, date):
			return value
		if isinstance(value, list):
			candidates = [UrlSafetyCheckView.parse_creation_date(item) for item in value]
			candidates = [item for item in candidates if item is not None]
			return min(candidates) if candidates else None
		return None

	def analyze_domain_age(self, query_domain: str, findings: list) -> dict:
		if not query_domain:
			return {
				'available': False,
				'isNewDomain': None,
				'domainAgeDays': None,
				'createdDate': None,
			}

		try:
			whois_result = whois.whois(query_domain)
		except Exception:
			findings.append(
				{
					'type': 'DOMAIN_AGE_UNAVAILABLE',
					'flagged': False,
					'explanation': (
						'WHOIS data could not be retrieved for this domain, '
						'so domain age could not be verified.'
					),
				}
			)
			return {
				'available': False,
				'isNewDomain': None,
				'domainAgeDays': None,
				'createdDate': None,
			}

		created = self.parse_creation_date(getattr(whois_result, 'creation_date', None))
		if not created:
			findings.append(
				{
					'type': 'DOMAIN_AGE_UNAVAILABLE',
					'flagged': False,
					'explanation': (
						'WHOIS did not return a reliable creation date, '
						'so domain age could not be verified.'
					),
				}
			)
			return {
				'available': False,
				'isNewDomain': None,
				'domainAgeDays': None,
				'createdDate': None,
			}

		age_days = max((date.today() - created).days, 0)
		is_new_domain = age_days < NEW_DOMAIN_DAYS_THRESHOLD

		if is_new_domain:
			findings.append(
				{
					'type': 'NEW_DOMAIN_RISK',
					'flagged': True,
					'explanation': (
						f'This domain appears to be about {age_days} days old. '
						'New domains are higher risk because attackers often use recently '
						'registered domains for short-lived phishing campaigns.'
					),
				}
			)

		return {
			'available': True,
			'isNewDomain': is_new_domain,
			'domainAgeDays': age_days,
			'createdDate': created.isoformat(),
		}

	def analyze_url_structure(self, target_url: str) -> dict:
		parsed = urlparse(target_url)
		hostname = (parsed.hostname or '').lower()

		tld = ''
		registered_domain = ''
		registered_domain_full = ''
		if hostname:
			extracted = tldextract.extract(hostname)
			tld = extracted.suffix.lower()
			registered_domain = extracted.domain.lower()
			registered_domain_full = extracted.registered_domain.lower()

		has_ip_host = (self.is_ip_host(hostname) or self.is_ip_like_host(hostname)) if hostname else False
		is_suspicious_tld = tld.split('.')[-1] in SUSPICIOUS_TLDS if tld else False

		translated = registered_domain.translate(CHAR_SUBSTITUTIONS)
		typosquatting_match = None

		for brand in BRAND_KEYWORDS:
			close_distance = levenshtein_distance(registered_domain, brand)
			translated_distance = levenshtein_distance(translated, brand)

			if (
				registered_domain == brand
				or translated == brand
				or close_distance == 1
				or translated_distance <= 1
			):
				if registered_domain != brand:
					typosquatting_match = brand
					break

		has_typosquatting_signal = typosquatting_match is not None

		findings = []
		if has_ip_host:
			findings.append(
				{
					'type': 'IP_BASED_URL',
					'flagged': True,
					'explanation': (
						'The URL uses an IP address instead of a readable domain name. '
						'Attackers often do this to hide identity and quickly rotate hosts.'
					),
				}
			)

		if is_suspicious_tld:
			findings.append(
				{
					'type': 'SUSPICIOUS_TLD',
					'flagged': True,
					'explanation': (
						f"The top-level domain '.{tld.split('.')[-1]}' is frequently abused "
						'in phishing and scam campaigns due to low registration friction.'
					),
				}
			)

		if has_typosquatting_signal:
			findings.append(
				{
					'type': 'TYPOSQUATTING_SIGNAL',
					'flagged': True,
					'explanation': (
						f"The domain looks like a typo variant of '{typosquatting_match}' "
						'for example letter substitution like faceb00k, '
						'which is a common credential-harvesting trick.'
					),
				}
			)

		domain_age = self.analyze_domain_age(registered_domain_full, findings)

		if not findings:
			findings.append(
				{
					'type': 'NO_STRONG_STRUCTURE_SIGNALS',
					'flagged': False,
					'explanation': (
						'No strong URL structure red flags were detected, '
						'but this still does not prove the destination is safe.'
					),
				}
			)

		return {
			'isIpBased': has_ip_host,
			'hasSuspiciousTld': is_suspicious_tld,
			'hasTyposquattingSignal': has_typosquatting_signal,
			'hasNewDomainRisk': bool(domain_age['isNewDomain']),
			'hostname': hostname,
			'tld': tld,
			'registeredDomain': registered_domain,
			'registeredDomainFull': registered_domain_full,
			'domainAge': domain_age,
			'findings': findings,
		}

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

		structure_analysis = self.analyze_url_structure(target_url)

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
