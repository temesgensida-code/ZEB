from datetime import date, datetime

import whois

from .constants import NEW_DOMAIN_DAYS_THRESHOLD


def parse_creation_date(value):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, list):
        candidates = [parse_creation_date(item) for item in value]
        candidates = [item for item in candidates if item is not None]
        return min(candidates) if candidates else None
    return None


def analyze_domain_age(query_domain: str, findings: list) -> dict:
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

    created = parse_creation_date(getattr(whois_result, 'creation_date', None))
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
