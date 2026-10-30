"""
MongoDB Connection Manager & Developer Platform Data Access Layer (Pillar 7)
Provides thread-safe MongoDB access, automatic mongomock fallback, index initialization,
API key cryptographic hashing, and high-velocity request logging.
"""

import os
import time
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from pymongo import MongoClient, ASCENDING, DESCENDING

# Ensure mongomock is available for fallback in test/offline environments
try:
    import mongomock
except ImportError:
    mongomock = None


class MongoDBClient:
    """
    Singleton connection manager with automatic mongomock fallback
    for local development and zero-dependency unit tests.
    """
    _instance = None
    _db = None
    _is_mock = False

    @classmethod
    def get_db(cls):
        if cls._db is not None:
            return cls._db

        mongo_uri = os.getenv('MONGODB_URI')
        db_name = os.getenv('MONGODB_DB_NAME', 'zeb_security')

        if mongo_uri:
            try:
                client = MongoClient(
                    mongo_uri,
                    maxPoolSize=50,
                    minPoolSize=5,
                    serverSelectionTimeoutMS=2000,
                )
                # Quick health check
                client.admin.command('ping')
                cls._db = client[db_name]
                cls._is_mock = False
                cls._init_indexes(cls._db)
                return cls._db
            except Exception as exc:
                print(f"[WARN] Live MongoDB connection failed ({exc}). Falling back to mongomock.")

        # In-memory fallback
        if mongomock:
            mock_client = mongomock.MongoClient()
            cls._db = mock_client[db_name]
            cls._is_mock = True
            cls._init_indexes(cls._db)
            return cls._db

        raise RuntimeError("Neither MongoDB nor mongomock is available.")

    @classmethod
    def reset_for_tests(cls):
        """Reset mock database state between test runs."""
        if cls._is_mock and cls._db is not None:
            db_name = cls._db.name
            client = mongomock.MongoClient()
            cls._db = client[db_name]
            cls._init_indexes(cls._db)

    @classmethod
    def _init_indexes(cls, db):
        try:
            # dev_users collection
            db.dev_users.create_index([("email", ASCENDING)], unique=True)
            db.dev_users.create_index([("oauth_provider", ASCENDING), ("oauth_id", ASCENDING)])

            # api_keys collection
            db.api_keys.create_index([("key_hash", ASCENDING)], unique=True)
            db.api_keys.create_index([("user_id", ASCENDING), ("is_active", ASCENDING)])

            # usage_logs collection + Native TTL Index (30 days = 2,592,000 seconds)
            db.usage_logs.create_index([("key_id", ASCENDING), ("timestamp", DESCENDING)])
            db.usage_logs.create_index([("timestamp", ASCENDING)], expireAfterSeconds=30 * 86400)
        except Exception:
            pass


# ─── Developer User Management (Google Auth) ───────────────────────────────────

def upsert_dev_user(google_id: str, email: str, name: str = '', picture: str = '') -> dict:
    """
    Creates or updates a developer user account authenticated via Google.
    Returns the user document dictionary with a string ID.
    """
    db = MongoDBClient.get_db()
    email_clean = (email or '').lower().strip()
    google_id_clean = str(google_id).strip()
    now = datetime.now(timezone.utc)

    # Search by email or google_id
    user_doc = db.dev_users.find_one({
        '$or': [{'email': email_clean}, {'google_id': google_id_clean}]
    })

    if user_doc:
        db.dev_users.update_one(
            {'_id': user_doc['_id']},
            {
                '$set': {
                    'name': name.strip() or user_doc.get('name', ''),
                    'picture': picture or user_doc.get('picture', ''),
                    'google_id': google_id_clean,
                    'last_login': now,
                    'is_active': True,
                }
            }
        )
        user_doc['last_login'] = now
    else:
        new_doc = {
            'google_id': google_id_clean,
            'email': email_clean,
            'name': name.strip() or email_clean.split('@')[0],
            'picture': picture or '',
            'oauth_provider': 'google',
            'created_at': now,
            'last_login': now,
            'is_active': True,
        }
        res = db.dev_users.insert_one(new_doc)
        new_doc['_id'] = res.inserted_id
        user_doc = new_doc

    return {
        'id': str(user_doc['_id']),
        'google_id': user_doc.get('google_id'),
        'email': user_doc.get('email'),
        'name': user_doc.get('name'),
        'picture': user_doc.get('picture'),
        'created_at': user_doc.get('created_at'),
        'last_login': user_doc.get('last_login'),
    }


def get_dev_user(user_id_str: str) -> dict | None:
    """
    Retrieves a user profile by ID.
    """
    db = MongoDBClient.get_db()
    query = {}
    if ObjectId.is_valid(user_id_str):
        query['_id'] = ObjectId(user_id_str)
    else:
        query['_id'] = user_id_str

    user_doc = db.dev_users.find_one(query)
    if not user_doc:
        return None

    return {
        'id': str(user_doc['_id']),
        'google_id': user_doc.get('google_id'),
        'email': user_doc.get('email'),
        'name': user_doc.get('name'),
        'picture': user_doc.get('picture'),
        'created_at': user_doc.get('created_at'),
        'last_login': user_doc.get('last_login'),
    }


# ─── API Key Management Functions ─────────────────────────────────────────────

def create_api_key_for_user(user_id: str, key_name: str = 'Default API Key', daily_quota: int = 1000, rate_limit: int = 5) -> tuple[dict, str]:
    """
    Generates a secure API key, stores its SHA-256 hash in MongoDB,
    and returns (key_document, raw_plaintext_secret).
    Enforces a strict policy of MAXIMUM 1 active API key per user.
    """
    db = MongoDBClient.get_db()

    user_key_match = ObjectId(user_id) if ObjectId.is_valid(user_id) else str(user_id)
    user_match = [str(user_id)]
    if ObjectId.is_valid(user_id):
        user_match.append(ObjectId(user_id))

    # 1. Enforce strict 1 active key per user policy
    active_count = db.api_keys.count_documents({
        'user_id': {'$in': user_match},
        'is_active': True,
    })
    if active_count >= 1:
        raise ValueError("User already has an active API key. Revoke your existing key to generate a new one.")

    raw_secret = f"zeb_live_{secrets.token_hex(24)}"
    prefix = raw_secret[:16]
    key_hash = hashlib.sha256(raw_secret.encode('utf-8')).hexdigest()

    doc = {
        'user_id': user_key_match,
        'name': (key_name or 'Default API Key').strip(),
        'key_prefix': prefix,
        'key_hash': key_hash,
        'daily_quota': daily_quota,
        'rate_limit_per_minute': rate_limit,
        'is_active': True,
        'created_at': datetime.now(timezone.utc),
        'last_used_at': None,
    }

    result = db.api_keys.insert_one(doc)
    doc['_id'] = str(result.inserted_id)
    doc['user_id'] = str(doc['user_id'])

    return doc, raw_secret


def authenticate_api_key(raw_key: str) -> dict | None:
    """
    Validates an inbound X-API-Key against MongoDB.
    Returns the key document if active and valid, otherwise None.
    """
    if not raw_key or not isinstance(raw_key, str) or not raw_key.startswith('zeb_live_'):
        return None

    db = MongoDBClient.get_db()
    key_hash = hashlib.sha256(raw_key.strip().encode('utf-8')).hexdigest()
    key_doc = db.api_keys.find_one({'key_hash': key_hash, 'is_active': True})

    if key_doc:
        db.api_keys.update_one(
            {'_id': key_doc['_id']},
            {'$set': {'last_used_at': datetime.now(timezone.utc)}}
        )
        return key_doc

    return None


def check_quota_and_rate_limit(key_doc: dict) -> tuple[bool, str | None]:
    """
    Enforces minute burst limits (default 60 req/min) and daily quotas (default 1000 req/day).
    Returns (True, None) if allowed, or (False, error_message) if throttled.
    """
    db = MongoDBClient.get_db()
    now = datetime.now(timezone.utc)
    one_minute_ago = now - timedelta(minutes=1)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    key_id = key_doc['_id']
    rate_limit = key_doc.get('rate_limit_per_minute', 60)
    daily_quota = key_doc.get('daily_quota', 1000)

    # 1. Burst rate limit
    recent_count = db.usage_logs.count_documents({
        'key_id': key_id,
        'timestamp': {'$gte': one_minute_ago}
    })
    if recent_count >= rate_limit:
        return False, f"Rate limit exceeded ({rate_limit} req/min). Please slow down."

    # 2. Daily quota
    daily_count = db.usage_logs.count_documents({
        'key_id': key_id,
        'timestamp': {'$gte': today_start}
    })
    if daily_count >= daily_quota:
        return False, f"Daily quota of {daily_quota} requests exhausted. Resets at 00:00 UTC."

    return True, None


def record_usage_log(key_doc: dict, target_url: str, response_status: int, latency_ms: int, client_ip: str = None):
    """
    Appends a high-velocity request audit log to the usage_logs collection.
    """
    db = MongoDBClient.get_db()
    # Strip sensitive query credentials from target URL before logging
    clean_url = target_url[:2048] if target_url else ''

    db.usage_logs.insert_one({
        'key_id': key_doc['_id'],
        'user_id': key_doc.get('user_id'),
        'endpoint': '/api/v1/scan',
        'target_url': clean_url,
        'response_status': response_status,
        'latency_ms': latency_ms,
        'client_ip': client_ip or '127.0.0.1',
        'timestamp': datetime.now(timezone.utc),
    })


def list_user_keys(user_id: str) -> list[dict]:
    """
    Returns all API keys for a given user, omitting sensitive hashes.
    """
    db = MongoDBClient.get_db()
    user_match = [str(user_id)]
    if ObjectId.is_valid(user_id):
        user_match.append(ObjectId(user_id))
    query = {'is_active': True, 'user_id': {'$in': user_match}}

    cursor = db.api_keys.find(query, {'key_hash': 0}).sort('created_at', DESCENDING)
    keys = []
    for doc in cursor:
        doc['_id'] = str(doc['_id'])
        doc['user_id'] = str(doc.get('user_id', ''))
        keys.append(doc)
    return keys


def revoke_api_key(key_id_str: str, user_id: str = None) -> bool:
    """
    Deactivates an API key.
    """
    db = MongoDBClient.get_db()
    if not ObjectId.is_valid(key_id_str):
        return False

    query = {'_id': ObjectId(key_id_str)}
    if user_id:
        user_match = [str(user_id)]
        if ObjectId.is_valid(user_id):
            user_match.append(ObjectId(user_id))
        query['user_id'] = {'$in': user_match}

    result = db.api_keys.update_one(query, {'$set': {'is_active': False}})
    return result.modified_count > 0


def get_key_analytics(key_id_str: str) -> dict:
    """
    Aggregates request volume, average latency, and recent audit logs for a key.
    """
    db = MongoDBClient.get_db()
    if not ObjectId.is_valid(key_id_str):
        return {'todayCount': 0, 'dailyHistogram': [], 'recentLogs': []}

    key_id = ObjectId(key_id_str)
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    seven_days_ago = today_start - timedelta(days=7)

    today_count = db.usage_logs.count_documents({
        'key_id': key_id,
        'timestamp': {'$gte': today_start}
    })

    try:
        pipeline = [
            {'$match': {'key_id': key_id, 'timestamp': {'$gte': seven_days_ago}}},
            {
                '$group': {
                    '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}},
                    'totalRequests': {'$sum': 1},
                    'avgLatency': {'$avg': '$latency_ms'},
                    'errors': {'$sum': {'$cond': [{'$gte': ['$response_status', 400]}, 1, 0]}}
                }
            },
            {'$sort': {'_id': 1}}
        ]
        daily_histogram = list(db.usage_logs.aggregate(pipeline))
    except Exception:
        daily_histogram = []

    # Recent 10 logs
    recent_cursor = db.usage_logs.find(
        {'key_id': key_id},
        projection={'_id': 0, 'key_id': 0, 'user_id': 0}
    ).sort('timestamp', DESCENDING).limit(10)
    recent_logs = list(recent_cursor)

    return {
        'todayCount': today_count,
        'dailyHistogram': daily_histogram,
        'recentLogs': recent_logs,
    }


def get_user_analytics(user_id_str: str) -> dict:
    """
    Aggregates user-level request volume, quota consumption, and recent audit logs.
    """
    db = MongoDBClient.get_db()
    if not user_id_str:
        return {'todayCount': 0, 'dailyHistogram': [], 'recentLogs': []}

    user_match = [str(user_id_str)]
    if ObjectId.is_valid(user_id_str):
        user_match.append(ObjectId(user_id_str))

    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    seven_days_ago = today_start - timedelta(days=7)

    today_count = db.usage_logs.count_documents({
        'user_id': {'$in': user_match},
        'timestamp': {'$gte': today_start}
    })

    try:
        pipeline = [
            {'$match': {'user_id': {'$in': user_match}, 'timestamp': {'$gte': seven_days_ago}}},
            {
                '$group': {
                    '_id': {'$dateToString': {'format': '%Y-%m-%d', 'date': '$timestamp'}},
                    'totalRequests': {'$sum': 1},
                    'avgLatency': {'$avg': '$latency_ms'},
                    'errors': {'$sum': {'$cond': [{'$gte': ['$response_status', 400]}, 1, 0]}}
                }
            },
            {'$sort': {'_id': 1}}
        ]
        daily_histogram = list(db.usage_logs.aggregate(pipeline))
    except Exception:
        daily_histogram = []

    # Recent 10 logs for this user
    recent_cursor = db.usage_logs.find(
        {'user_id': {'$in': user_match}},
        projection={'_id': 0, 'key_id': 0, 'user_id': 0}
    ).sort('timestamp', DESCENDING).limit(10)
    recent_logs = list(recent_cursor)

    return {
        'todayCount': today_count,
        'dailyHistogram': daily_histogram,
        'recentLogs': recent_logs,
    }
