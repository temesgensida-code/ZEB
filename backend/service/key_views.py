"""
Developer API Key Management & Analytics Views (Pillar 7).
Provides endpoints to generate, list, revoke API keys and view usage analytics.
Enforces DevUser authentication, 1-key limit, and quota boundaries.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .auth import DevUserAuthentication, IsDevUserAuthenticated
from .mongo import (
    create_api_key_for_user,
    list_user_keys,
    revoke_api_key,
    get_key_analytics,
    get_user_analytics,
)


class KeyManagementView(APIView):
    """
    GET /api/v1/keys/  - List authenticated user's active API keys (maximum 1)
    POST /api/v1/keys/ - Create a new API key (enforces max 1 active key policy)
    """
    authentication_classes = [DevUserAuthentication]
    permission_classes = [IsDevUserAuthenticated]

    def get(self, request):
        user_id = str(request.user.id)
        keys = list_user_keys(user_id)
        return Response({'keys': keys}, status=status.HTTP_200_OK)

    def post(self, request):
        user_id = str(request.user.id)
        key_name = (request.data.get('name') or 'Default API Key').strip()

        # Strict security defaults: 1,000 req/day and 5 req/min
        daily_quota = 1000
        rate_limit = 5

        try:
            key_doc, raw_secret = create_api_key_for_user(
                user_id=user_id,
                key_name=key_name,
                daily_quota=daily_quota,
                rate_limit=rate_limit,
            )
        except ValueError as err:
            return Response({'error': str(err)}, status=status.HTTP_400_BAD_REQUEST)

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
    DELETE /api/v1/keys/<key_id>/ - Revoke/deactivate an API key owned by the authenticated user
    """
    authentication_classes = [DevUserAuthentication]
    permission_classes = [IsDevUserAuthenticated]

    def delete(self, request, key_id):
        user_id = str(request.user.id)
        success = revoke_api_key(key_id, user_id=user_id)
        if not success:
            return Response(
                {'error': 'API key not found, already revoked, or not owned by your account.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response({'status': 'revoked', 'keyId': key_id}, status=status.HTTP_200_OK)


class KeyUsageView(APIView):
    """
    GET /api/v1/usage/?keyId=<key_id> - Aggregated usage metrics and audit logs for key
    Or user-level aggregate metrics if keyId is omitted.
    """
    authentication_classes = [DevUserAuthentication]
    permission_classes = [IsDevUserAuthenticated]

    def get(self, request):
        user_id = str(request.user.id)
        key_id = request.query_params.get('keyId')

        if key_id:
            # Verify the key belongs to this authenticated user
            user_keys = list_user_keys(user_id)
            if not any(k['_id'] == key_id for k in user_keys):
                return Response(
                    {'error': 'Key not found or unauthorized.'},
                    status=status.HTTP_403_FORBIDDEN,
                )
            analytics = get_key_analytics(key_id)
        else:
            analytics = get_user_analytics(user_id)

        return Response(analytics, status=status.HTTP_200_OK)
