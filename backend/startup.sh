#!/usr/bin/env bash
set -e

python manage.py migrate --noinput
python manage.py collectstatic --noinput

exec gunicorn backend.asgi:application \
    --bind 0.0.0.0:${PORT:-8000} \
    --workers ${GUNICORN_WORKERS:-3} \
    --worker-class uvicorn.workers.UvicornWorker \
    --timeout 60 \
    --keep-alive 15 \
    --access-logfile - \
    --error-logfile -
