#!/usr/bin/env bash
set -e

python manage.py migrate --noinput
python manage.py collectstatic --noinput

exec gunicorn backend.wsgi --bind 0.0.0.0:${PORT:-8000} --workers ${GUNICORN_WORKERS:-3}
