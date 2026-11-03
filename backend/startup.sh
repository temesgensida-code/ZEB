#!/usr/bin/env bash
set -e

# Always resolve to backend directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

python manage.py migrate --noinput
python manage.py collectstatic --noinput

# Respect Render's WEB_CONCURRENCY, fallback to GUNICORN_WORKERS or 2
WORKERS="${WEB_CONCURRENCY:-${GUNICORN_WORKERS:-2}}"

exec gunicorn backend.asgi:application \
    --bind 0.0.0.0:${PORT:-8000} \
    --workers "$WORKERS" \
    --worker-class uvicorn.workers.UvicornWorker \
    --timeout 60 \
    --keep-alive 15 \
    --access-logfile - \
    --error-logfile -

