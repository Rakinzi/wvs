# WVS Backend

This backend now uses `uv` for Python dependency management.

## Setup

```bash
cd wvs_backend
uv sync
uv run flask --app manage.py db upgrade
```

## Run

```bash
uv run python manage.py
uv run celery -A app.celery_app:celery_app worker --loglevel=info
uv run celery -A app.celery_app:celery_app beat --loglevel=info
```

## Migrations

```bash
uv run flask --app manage.py db upgrade
```

## Environment

Development defaults now use SQLite at `instance/wvs.db`.

Set these when you want production-style services:

```bash
export APP_ENV=production
export DATABASE_URL=mysql+pymysql://user:password@host/database
export SECRET_KEY=change-me
export JWT_SECRET_KEY=change-me-too
export CELERY_BROKER_URL=amqp://guest:guest@localhost:5672//
export CELERY_RESULT_BACKEND=rpc://
```

Optional:

- `REPORT_FOLDER`
- `AUTO_CREATE_TABLES`
- `PHISHING_DB_URL`
- `MAX_SCAN_TIME`
- `REQUESTS_CACHE_NAME`
- `REQUESTS_CACHE_TTL_SECONDS`
- `HUGGINGFACE_API_TOKEN`
- `HUGGINGFACE_URL_MODEL`
- `HUGGINGFACE_TIMEOUT_SECONDS`
- `ZAP_ENABLED`
- `ZAP_BASE_URL`
- `ZAP_API_KEY`

## Improvements Made

- Added `pyproject.toml` so dependencies are explicit and reproducible with `uv`
- Removed hardcoded MySQL credentials from default config
- Switched development fallback storage to local SQLite
- Centralized Flask and Celery initialization around one app factory
- Stopped duplicate command registration and duplicated Celery configuration
- Made table creation explicit instead of a startup side effect
- Added typed settings and request validation with Pydantic
- Added cached HTTP threat-intel fetches and retry logic for external requests
- Added optional OWASP ZAP integration when a local/remote ZAP daemon is available
