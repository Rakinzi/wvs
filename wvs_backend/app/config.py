from datetime import timedelta
from pathlib import Path

from app.settings import INSTANCE_DIR, settings


class Config:
    SQLALCHEMY_DATABASE_URI = settings.database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = settings.secret_key
    JWT_SECRET_KEY = settings.effective_jwt_secret_key
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_TOKEN_LOCATION = ["cookies"]
    JWT_ERROR_MESSAGE_KEY = "error"
    JWT_COOKIE_SECURE = settings.app_env.lower() == "production"
    JWT_COOKIE_SAMESITE = "Lax"
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_SESSION_COOKIE = True
    JWT_ACCESS_CSRF_HEADER_NAME = "X-CSRF-TOKEN"
    SESSION_COOKIE_SECURE = settings.app_env.lower() == "production"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    FRONTEND_BASE_URL = settings.frontend_base_url
    CORS_ORIGINS = settings.allowed_frontend_origins
    RESET_PASSWORD_TOKEN_TTL_MINUTES = settings.reset_password_token_ttl_minutes
    SECURITY_HEADERS_ENABLED = settings.security_headers_enabled
    ALLOW_PRIVATE_SCAN_TARGETS = settings.allow_private_scan_targets

    SMTP_HOST = settings.smtp_host
    SMTP_PORT = settings.smtp_port
    SMTP_USE_TLS = settings.smtp_use_tls
    SMTP_USER = settings.smtp_user
    SMTP_PASSWORD = settings.smtp_password
    SMTP_FROM_EMAIL = settings.smtp_from_email or settings.smtp_user

    CELERY_BROKER_URL = settings.celery_broker_url
    CELERY_RESULT_BACKEND = settings.celery_result_backend
    CELERY_TASK_SERIALIZER = "json"
    CELERY_RESULT_SERIALIZER = "json"
    CELERY_ACCEPT_CONTENT = ["json"]
    CELERY_TASK_TRACK_STARTED = True
    CELERY_TASK_TIME_LIMIT = 30 * 60
    CELERY_TIMEZONE = settings.celery_timezone
    BROKER_CONNECTION_RETRY_ON_STARTUP = True
    CELERY_IMPORTS = ("app.tasks.ssl_checks", "app.tasks.scan_jobs")
    CELERY_BEAT_SCHEDULE = {
        "check-ssl-tls-updates-daily": {
            "task": "app.tasks.check_ssl_tls_updates",
            "schedule": timedelta(hours=24),
        },
    }

    DNSBL_ENABLED = True
    PHISHING_DB_URL = settings.phishing_db_url
    REPORT_FOLDER = settings.report_folder
    MAX_SCAN_TIME = settings.max_scan_time
    AUTO_CREATE_TABLES = settings.auto_create_tables
    CORS_HEADERS = "Content-Type,Authorization,X-CSRF-TOKEN"
    RATELIMIT_STORAGE_URI = settings.ratelimit_storage_uri
    RATELIMIT_HEADERS_ENABLED = True
    REQUESTS_CACHE_NAME = settings.requests_cache_name
    REQUESTS_CACHE_TTL_SECONDS = settings.requests_cache_ttl_seconds
    ZAP_ENABLED = settings.zap_enabled
    ZAP_BASE_URL = settings.zap_base_url
    ZAP_API_KEY = settings.zap_api_key
    ZAP_SPIDER_MAX_MINUTES = settings.zap_spider_max_minutes
    ZAP_ACTIVE_SCAN_MAX_MINUTES = settings.zap_active_scan_max_minutes

    @classmethod
    def validate(cls) -> None:
        INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
        Path(cls.REPORT_FOLDER).mkdir(parents=True, exist_ok=True)


class DevelopmentConfig(Config):
    DEBUG = settings.debug or settings.app_env.lower() == "development"
    AUTO_CREATE_TABLES = settings.auto_create_tables


class ProductionConfig(Config):
    DEBUG = False
    JWT_COOKIE_SECURE = True
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    SECRET_KEY = settings.secret_key
    JWT_SECRET_KEY = settings.jwt_secret_key
    SQLALCHEMY_DATABASE_URI = settings.database_url
    CELERY_BROKER_URL = settings.celery_broker_url
    CELERY_RESULT_BACKEND = settings.celery_result_backend

    @classmethod
    def validate(cls) -> None:
        super().validate()
        missing = [
            name
            for name, value in {
                "SECRET_KEY": cls.SECRET_KEY,
                "JWT_SECRET_KEY": cls.JWT_SECRET_KEY,
                "DATABASE_URL": cls.SQLALCHEMY_DATABASE_URI,
                "CELERY_BROKER_URL": cls.CELERY_BROKER_URL,
                "CELERY_RESULT_BACKEND": cls.CELERY_RESULT_BACKEND,
            }.items()
            if not value
        ]
        if missing:
            raise RuntimeError(
                f"Missing required production environment variables: {', '.join(missing)}"
            )


def get_config():
    environment = settings.app_env.lower()
    if environment == "production":
        return ProductionConfig
    return DevelopmentConfig
