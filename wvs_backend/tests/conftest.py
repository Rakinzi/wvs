from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app, db
from app.models import User


@pytest.fixture()
def app(tmp_path: Path):
    reports_dir = tmp_path / "reports"
    cache_path = tmp_path / "http_cache"
    database_path = tmp_path / "test.db"

    class TestConfig:
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{database_path}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False

        SECRET_KEY = "test-secret-key-with-32-bytes-minimum"
        JWT_SECRET_KEY = "test-jwt-secret-key-with-32-bytes-minimum"
        JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
        JWT_TOKEN_LOCATION = ["cookies"]
        JWT_ERROR_MESSAGE_KEY = "error"
        JWT_COOKIE_SECURE = False
        JWT_COOKIE_SAMESITE = "Lax"
        JWT_COOKIE_CSRF_PROTECT = True
        JWT_SESSION_COOKIE = True
        JWT_ACCESS_CSRF_HEADER_NAME = "X-CSRF-TOKEN"
        SESSION_COOKIE_SECURE = False
        SESSION_COOKIE_HTTPONLY = True
        SESSION_COOKIE_SAMESITE = "Lax"
        FRONTEND_BASE_URL = "http://localhost:5173"
        CORS_ORIGINS = ["http://localhost:5173"]
        RESET_PASSWORD_TOKEN_TTL_MINUTES = 60
        SECURITY_HEADERS_ENABLED = True
        ALLOW_PRIVATE_SCAN_TARGETS = True
        REQUIRE_VERIFIED_TARGETS = False
        TARGET_VERIFICATION_TOKEN_TTL_HOURS = 24
        TARGET_VERIFICATION_TIMEOUT_SECONDS = 5
        TARGET_VERIFICATION_MAX_BYTES = 100000
        TARGET_VERIFICATION_MAX_REDIRECTS = 3
        UX_SCAN_ENABLED = True
        UX_SCAN_MAX_PAGES = 10
        UX_SCAN_DEFAULT_PAGES = 5
        UX_SCAN_PAGE_TIMEOUT_SECONDS = 20
        UX_SCAN_SCREENSHOT_DIR = str(reports_dir / "screenshots")
        UX_SCAN_ENABLE_AI_REVIEW = False
        UX_SCAN_MOBILE_WIDTH = 390
        UX_SCAN_MOBILE_HEIGHT = 844
        UX_SCAN_DESKTOP_WIDTH = 1440
        UX_SCAN_DESKTOP_HEIGHT = 1024
        VISUAL_AI_ENABLED = False
        VISUAL_AI_PROVIDER = None
        VISUAL_AI_API_KEY = None
        VISUAL_AI_MODEL = None
        VISUAL_AI_BASE_URL = "https://api.openai.com/v1"
        VISUAL_AI_TIMEOUT_SECONDS = 10
        VISUAL_AI_MAX_SCREENSHOTS_PER_SCAN = 3
        LIGHTHOUSE_ENABLED = False
        LIGHTHOUSE_CLI_PATH = None
        LIGHTHOUSE_TIMEOUT_SECONDS = 30
        SECURITY_SCAN_QUEUE = "security_scans"
        UX_SCAN_QUEUE = "ux_scans"
        UX_SCAN_RATE_LIMIT = "10/h"
        SCAN_RESULT_RETENTION_DAYS = 90
        SCREENSHOT_RETENTION_DAYS = 30

        SMTP_HOST = "localhost"
        SMTP_PORT = 25
        SMTP_USE_TLS = False
        SMTP_USER = None
        SMTP_PASSWORD = None
        SMTP_FROM_EMAIL = None

        CELERY_BROKER_URL = "memory://"
        CELERY_RESULT_BACKEND = "cache+memory://"
        CELERY_TASK_SERIALIZER = "json"
        CELERY_RESULT_SERIALIZER = "json"
        CELERY_ACCEPT_CONTENT = ["json"]
        CELERY_TASK_TRACK_STARTED = True
        CELERY_TASK_TIME_LIMIT = 1800
        CELERY_TIMEZONE = "UTC"
        BROKER_CONNECTION_RETRY_ON_STARTUP = False
        CELERY_IMPORTS = ("app.tasks.ssl_checks", "app.tasks.scan_jobs")
        CELERY_BEAT_SCHEDULE = {}

        DNSBL_ENABLED = True
        PHISHING_DB_URL = "https://example.com/phishing.txt"
        REPORT_FOLDER = str(reports_dir)
        MAX_SCAN_TIME = 300
        AUTO_CREATE_TABLES = False
        CORS_HEADERS = "Content-Type,Authorization,X-CSRF-TOKEN"
        RATELIMIT_STORAGE_URI = "memory://"
        RATELIMIT_HEADERS_ENABLED = True
        REQUESTS_CACHE_NAME = str(cache_path)
        REQUESTS_CACHE_TTL_SECONDS = 60
        ZAP_ENABLED = False
        ZAP_BASE_URL = "http://127.0.0.1:8080"
        ZAP_API_KEY = ""
        ZAP_SPIDER_MAX_MINUTES = 1
        ZAP_ACTIVE_SCAN_MAX_MINUTES = 1

        @classmethod
        def validate(cls) -> None:
            reports_dir.mkdir(parents=True, exist_ok=True)
            cache_path.parent.mkdir(parents=True, exist_ok=True)

    app = create_app(TestConfig)
    app.config.update(TESTING=True)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def user(app):
    with app.app_context():
        user = User(username="tester", email="tester@example.com", email_verified=True)
        user.set_password("Password123")
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
        return user


@pytest.fixture()
def auth_client(client, user):
    response = client.post(
        "/login",
        json={"identifier": user.username, "password": "Password123"},
    )
    assert response.status_code == 200
    return client


@pytest.fixture()
def auth_headers(auth_client):
    csrf_cookie = auth_client.get_cookie("csrf_access_token")
    assert csrf_cookie is not None
    return {"X-CSRF-TOKEN": csrf_cookie.value}
