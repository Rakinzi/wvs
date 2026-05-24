from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"
DEFAULT_SQLITE_PATH = INSTANCE_DIR / "wvs.db"
DEFAULT_REPORTS_PATH = BASE_DIR / "reports"


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_env: str = "development"
    debug: bool = False

    database_url: str = Field(default=f"sqlite:///{DEFAULT_SQLITE_PATH}", alias="DATABASE_URL")
    secret_key: str | None = Field(default="dev-secret-key", alias="SECRET_KEY")
    jwt_secret_key: str | None = Field(default=None, alias="JWT_SECRET_KEY")
    frontend_base_url: str = Field(default="http://localhost:5173", alias="FRONTEND_BASE_URL")
    frontend_origins: str | None = Field(default=None, alias="FRONTEND_ORIGINS")
    reset_password_token_ttl_minutes: int = Field(default=60, alias="RESET_PASSWORD_TOKEN_TTL_MINUTES")
    allow_private_scan_targets: bool = Field(default=False, alias="ALLOW_PRIVATE_SCAN_TARGETS")
    security_headers_enabled: bool = Field(default=True, alias="SECURITY_HEADERS_ENABLED")

    smtp_host: str = Field(default="smtp.gmail.com", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_use_tls: bool = Field(default=True, alias="SMTP_USE_TLS")
    smtp_user: str | None = Field(default=None, alias="GMAIL_USER")
    smtp_password: str | None = Field(default=None, alias="GMAIL_APP_PASSWORD")
    smtp_from_email: str | None = Field(default=None, alias="SMTP_FROM_EMAIL")

    celery_broker_url: str | None = Field(
        default="amqp://guest:guest@localhost:5672//",
        alias="CELERY_BROKER_URL",
    )
    celery_result_backend: str | None = Field(default="rpc://", alias="CELERY_RESULT_BACKEND")
    celery_timezone: str = Field(default="UTC", alias="CELERY_TIMEZONE")

    phishing_db_url: str = Field(
        default="https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        alias="PHISHING_DB_URL",
    )
    report_folder: str = Field(default=str(DEFAULT_REPORTS_PATH), alias="REPORT_FOLDER")
    max_scan_time: int = Field(default=300, alias="MAX_SCAN_TIME")
    auto_create_tables: bool = Field(default=False, alias="AUTO_CREATE_TABLES")
    ratelimit_storage_uri: str = Field(default="memory://", alias="RATELIMIT_STORAGE_URI")
    requests_cache_name: str = Field(default=str(INSTANCE_DIR / "http_cache"), alias="REQUESTS_CACHE_NAME")
    requests_cache_ttl_seconds: int = Field(default=3600, alias="REQUESTS_CACHE_TTL_SECONDS")
    huggingface_api_token: str | None = Field(default=None, alias="HUGGINGFACE_API_TOKEN")
    huggingface_url_model: str = Field(
        default="CrabInHoney/urlbert-tiny-v4-malicious-url-classifier",
        alias="HUGGINGFACE_URL_MODEL",
    )
    huggingface_timeout_seconds: int = Field(default=20, alias="HUGGINGFACE_TIMEOUT_SECONDS")

    zap_enabled: bool = Field(default=False, alias="ZAP_ENABLED")
    zap_base_url: str = Field(default="http://127.0.0.1:8080", alias="ZAP_BASE_URL")
    zap_api_key: str = Field(default="", alias="ZAP_API_KEY")
    zap_spider_max_minutes: int = Field(default=2, alias="ZAP_SPIDER_MAX_MINUTES")
    zap_active_scan_max_minutes: int = Field(default=4, alias="ZAP_ACTIVE_SCAN_MAX_MINUTES")

    @property
    def effective_jwt_secret_key(self) -> str | None:
        return self.jwt_secret_key or self.secret_key

    @property
    def allowed_frontend_origins(self) -> list[str]:
        raw_origins = self.frontend_origins or self.frontend_base_url
        origins = [
            origin.strip().rstrip("/")
            for origin in raw_origins.split(",")
            if origin.strip()
        ]
        return origins or [self.frontend_base_url.rstrip("/")]


settings = AppSettings()
