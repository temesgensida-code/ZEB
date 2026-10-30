"""
Developer Authentication & Authorization Module.
Provides Google ID Token verification, stateless HMAC-SHA256 JWT tokens,
and DRF authentication/permission classes for developer API endpoints.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.parse
import urllib.request
from django.conf import settings
from rest_framework import authentication, permissions, exceptions

from .mongo import get_dev_user

logger = logging.getLogger(__name__)


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string without trailing '=' padding."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def _base64url_decode(data_str: str) -> bytes:
    """Decode base64url string, adding required '=' padding."""
    rem = len(data_str) % 4
    if rem > 0:
        data_str += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data_str.encode('utf-8'))


def create_access_token(user_id: str, email: str, expiry_days: int = 7) -> str:
    """
    Creates a signed HMAC-SHA256 JWT access token using Django SECRET_KEY.
    Default validity: 7 days.
    """
    secret = settings.SECRET_KEY.encode('utf-8')
    header = {"alg": "HS256", "typ": "JWT"}
    now_ts = int(time.time())
    exp_ts = now_ts + (expiry_days * 86400)

    payload = {
        "sub": str(user_id),
        "email": (email or '').lower().strip(),
        "iat": now_ts,
        "exp": exp_ts,
    }

    header_b64 = _base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = _base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = _base64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_access_token(token: str) -> dict | None:
    """
    Verifies the HMAC-SHA256 signature and expiration time of a JWT.
    Returns the payload dictionary if valid, or None if invalid/expired.
    """
    if not token or not isinstance(token, str) or token.count('.') != 2:
        return None

    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        secret = settings.SECRET_KEY.encode('utf-8')
        expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        actual_sig = _base64url_decode(sig_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload_bytes = _base64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))

        # Check expiration
        if 'exp' in payload and payload['exp'] < int(time.time()):
            return None

        return payload
    except Exception as e:
        logger.debug("Failed to verify access token: %s", e)
        return None


def verify_google_token(id_token: str) -> dict:
    """
    Verifies an incoming Google Identity Services ID token.
    Supports a mock fallback for offline development and automated unit tests.
    Returns: { google_id, email, name, picture }
    Raises ValueError on invalid token.
    """
    clean_token = (id_token or '').strip()
    if not clean_token:
        raise ValueError("Missing ID token.")

    # 1. Dev & test mock mode fallback
    google_client_id = getattr(settings, 'GOOGLE_CLIENT_ID', '') or os.getenv('GOOGLE_CLIENT_ID', '')
    if clean_token.startswith('mock_') or clean_token.startswith('test_mock_'):
        email = 'developer@example.com'
        if '@' in clean_token:
            for sep in (':', '_'):
                if sep in clean_token:
                    candidate = clean_token.rsplit(sep, 1)[-1]
                    if '@' in candidate:
                        email = candidate
                        break
            else:
                email = clean_token
        else:
            parts = clean_token.split('_')
            if len(parts) >= 3 and '@' not in parts[-1]:
                email = f"{parts[-1]}@example.com"

        return {
            'google_id': f"mock-gid-{hashlib.md5(email.encode('utf-8')).hexdigest()[:12]}",
            'email': email,
            'name': email.split('@')[0].capitalize(),
            'picture': f"https://ui-avatars.com/api/?name={urllib.parse.quote(email.split('@')[0])}&background=10b981&color=fff",
        }

    # 2. Production verification via Google Tokeninfo API
    url = f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(clean_token)}"
    req = urllib.request.Request(
        url,
        headers={'User-Agent': 'ZEB-Security-Engine/1.0'}
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Google token verification failed: {str(e)}")

    if 'error_description' in data:
        raise ValueError(f"Google authentication error: {data['error_description']}")

    # Verify audience matches client ID if configured
    if google_client_id and data.get('aud') != google_client_id:
        raise ValueError("Google token audience does not match configured GOOGLE_CLIENT_ID.")

    email = data.get('email', '').lower().strip()
    if not email:
        raise ValueError("Google token is missing an email address.")

    return {
        'google_id': data.get('sub', ''),
        'email': email,
        'name': data.get('name', '') or email.split('@')[0],
        'picture': data.get('picture', ''),
    }


class DevUser:
    """
    Lightweight user object attached to request.user when authenticated via DevUserAuthentication.
    Compatible with Django REST Framework permissions.
    """
    is_authenticated = True
    is_anonymous = False

    def __init__(self, doc: dict):
        self.doc = doc
        self.id = str(doc.get('id') or doc.get('_id'))
        self.pk = self.id
        self.email = doc.get('email', '')
        self.name = doc.get('name', '')
        self.picture = doc.get('picture', '')

    def __str__(self):
        return f"DevUser<{self.email}>"

    def __getitem__(self, item):
        return self.doc.get(item)


class DevUserAuthentication(authentication.BaseAuthentication):
    """
    DRF authentication scheme parsing 'Authorization: Bearer <jwt>'
    Validates token and populates request.user and request.dev_user.
    """
    def authenticate_header(self, request):
        return 'Bearer realm="api"'

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header:
            return None

        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return None

        raw_token = parts[1].strip()
        payload = verify_access_token(raw_token)
        if not payload:
            raise exceptions.AuthenticationFailed('Invalid or expired authentication token.')

        user_id = payload.get('sub')
        user_doc = get_dev_user(user_id)
        if not user_doc:
            raise exceptions.AuthenticationFailed('User account not found or deactivated.')

        request.dev_user = user_doc
        return (DevUser(user_doc), raw_token)


class IsDevUserAuthenticated(permissions.BasePermission):
    """
    Requires the request to be authenticated by a valid DevUser.
    """
    def has_permission(self, request, view):
        return bool(request.user and getattr(request.user, 'is_authenticated', False))
