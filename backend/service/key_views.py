"""
Developer API Key Management & Analytics Views (Pillar 7)
Provides endpoints to generate, list, revoke API keys and view usage analytics.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from bson import ObjectId

from .mongo import (
    create_api_key_for_user,
    list_user_keys,
    revoke_api_key,
    get_key_analytics,
)


class KeyManagementView(APIView):
    """
    GET /api/v1/keys/  - List user's active API keys (hashes omitted)
    POST /api/v1/keys/ - Create a new API key (returns the raw secret once)
    """
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        user_id = request.query_params.get('userId') or 'public_dev'
        keys = list_user_keys(user_id)
        return Response({'keys': keys}, status=status.HTTP_200_OK)

    def post(self, request):
        user_id = request.data.get('userId') or 'public_dev'
        key_name = request.data.get('name') or 'Default API Key'
        daily_quota = int(request.data.get('dailyQuota', 1000))
        rate_limit = int(request.data.get('rateLimitPerMinute', 60))

        key_doc, raw_secret = create_api_key_for_user(
            user_id=user_id,
            key_name=key_name,
            daily_quota=daily_quota,
            rate_limit=rate_limit,
        )

        return Response(
            {
                'key': key_doc,
                'rawSecret': raw_secret,
                'notice': 'Copy this API key now. For security, it will not be shown again.',
            },
            status=status.HTTP_201_CREATED,
        )


class KeyRevokeView(APIView):
    """
    DELETE /api/v1/keys/<key_id>/ - Revoke/deactivate an API key
    """
    authentication_classes = []
    permission_classes = []

    def delete(self, request, key_id):
        user_id = request.query_params.get('userId')
        success = revoke_api_key(key_id, user_id=user_id)
        if not success:
            return Response(
                {'error': 'API key not found or already revoked.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({'status': 'revoked', 'keyId': key_id}, status=status.HTTP_200_OK)


class KeyUsageView(APIView):
    """
    GET /api/v1/usage/?keyId=<key_id> - Aggregated usage metrics and audit logs
    """
    authentication_classes = []
    permission_classes = []

    def get(self, request):
        key_id = request.query_params.get('keyId')
        if not key_id:
            return Response(
                {'error': 'Missing required query parameter: keyId'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        analytics = get_key_analytics(key_id)
        return Response(analytics, status=status.HTTP_200_OK)
