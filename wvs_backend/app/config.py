from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

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
    REQUIRE_VERIFIED_TARGETS = settings.require_verified_targets
    TARGET_VERIFICATION_TOKEN_TTL_HOURS = settings.target_verification_token_ttl_hours
    TARGET_VERIFICATION_TIMEOUT_SECONDS = settings.target_verification_timeout_seconds
    TARGET_VERIFICATION_MAX_BYTES = settings.target_verification_max_bytes
    TARGET_VERIFICATION_MAX_REDIRECTS = settings.target_verification_max_redirects
    UX_SCAN_ENABLED = settings.ux_scan_enabled
    UX_SCAN_MAX_PAGES = settings.ux_scan_max_pages
    UX_SCAN_DEFAULT_PAGES = settings.ux_scan_default_pages
    UX_SCAN_PAGE_TIMEOUT_SECONDS = settings.ux_scan_page_timeout_seconds
    UX_SCAN_SCREENSHOT_DIR = settings.ux_scan_screenshot_dir
    UX_SCAN_ENABLE_AI_REVIEW = settings.ux_scan_enable_ai_review
    UX_SCAN_MOBILE_WIDTH = settings.ux_scan_mobile_width
    UX_SCAN_MOBILE_HEIGHT = settings.ux_scan_mobile_height
    UX_SCAN_DESKTOP_WIDTH = settings.ux_scan_desktop_width
    UX_SCAN_DESKTOP_HEIGHT = settings.ux_scan_desktop_height
    VISUAL_AI_ENABLED = settings.visual_ai_enabled
    VISUAL_AI_PROVIDER = settings.visual_ai_provider
    VISUAL_AI_API_KEY = settings.visual_ai_api_key
    VISUAL_AI_MODEL = settings.visual_ai_model
    VISUAL_AI_BASE_URL = settings.visual_ai_base_url
    VISUAL_AI_TIMEOUT_SECONDS = settings.visual_ai_timeout_seconds
    VISUAL_AI_MAX_SCREENSHOTS_PER_SCAN = settings.visual_ai_max_screenshots_per_scan
    LIGHTHOUSE_ENABLED = settings.lighthouse_enabled
    LIGHTHOUSE_CLI_PATH = settings.lighthouse_cli_path
    LIGHTHOUSE_TIMEOUT_SECONDS = settings.lighthouse_timeout_seconds
    EXTERNAL_TOOLS_ENABLED = settings.external_tools_enabled
    EXTERNAL_TOOLS_TIMEOUT_SECONDS = settings.external_tools_timeout_seconds
    NMAP_ENABLED = settings.nmap_enabled
    NMAP_CLI_PATH = settings.nmap_cli_path
    NIKTO_ENABLED = settings.nikto_enabled
    NIKTO_CLI_PATH = settings.nikto_cli_path
    WHATWEB_ENABLED = settings.whatweb_enabled
    WHATWEB_CLI_PATH = settings.whatweb_cli_path
    WAFW00F_ENABLED = settings.wafw00f_enabled
    WAFW00F_CLI_PATH = settings.wafw00f_cli_path
    SSLSCAN_ENABLED = settings.sslscan_enabled
    SSLSCAN_CLI_PATH = settings.sslscan_cli_path
    WPSCAN_ENABLED = settings.wpscan_enabled
    WPSCAN_CLI_PATH = settings.wpscan_cli_path
    SQLMAP_ENABLED = settings.sqlmap_enabled
    SQLMAP_CLI_PATH = settings.sqlmap_cli_path
    NOSQLMAP_ENABLED = settings.nosqlmap_enabled
    NOSQLMAP_CLI_PATH = settings.nosqlmap_cli_path
    NOSQLMAP_COMMAND_TEMPLATE = settings.nosqlmap_command_template
    FFUF_ENABLED = settings.ffuf_enabled
    FFUF_CLI_PATH = settings.ffuf_cli_path
    FFUF_WORDLIST = settings.ffuf_wordlist
    SECURITY_SCAN_QUEUE = settings.security_scan_queue
    UX_SCAN_QUEUE = settings.ux_scan_queue
    AI_SCAN_QUEUE = settings.ai_scan_queue
    UX_SCAN_RATE_LIMIT = settings.ux_scan_rate_limit
    SCAN_RESULT_RETENTION_DAYS = settings.scan_result_retention_days
    SCREENSHOT_RETENTION_DAYS = settings.screenshot_retention_days
    UPTIME_MONITOR_ENABLED = settings.uptime_monitor_enabled
    UPTIME_MONITOR_DEFAULT_INTERVAL_MINUTES = settings.uptime_monitor_default_interval_minutes
    UPTIME_MONITOR_REQUEST_TIMEOUT_SECONDS = settings.uptime_monitor_request_timeout_seconds
    UPTIME_MONITOR_HISTORY_LIMIT = settings.uptime_monitor_history_limit
    MALWARE_SCAN_ENABLED = settings.malware_scan_enabled
    MALWARE_MAX_ARTIFACTS = settings.malware_max_artifacts
    MALWARE_MAX_DOWNLOAD_BYTES = settings.malware_max_download_bytes
    MALWARE_DOWNLOAD_TIMEOUT_SECONDS = settings.malware_download_timeout_seconds
    MALWARE_TEMP_DIR = settings.malware_temp_dir
    MALWARE_ALLOWED_EXTENSIONS = settings.malware_allowed_extensions
    CLAMAV_ENABLED = settings.clamav_enabled
    CLAMAV_NETWORK_SOCKET = settings.clamav_network_socket
    CLAMAV_UNIX_SOCKET = settings.clamav_unix_socket
    YARA_ENABLED = settings.yara_enabled
    YARA_RULES_DIR = settings.yara_rules_dir

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
    CELERY_IMPORTS = ("app.tasks.ssl_checks", "app.tasks.scan_jobs", "app.tasks.uptime")
    CELERY_BEAT_SCHEDULE = {
        "check-ssl-tls-updates-daily": {
            "task": "app.tasks.check_ssl_tls_updates",
            "schedule": timedelta(hours=24),
        },
        "run-uptime-monitors-every-minute": {
            "task": "app.tasks.run_due_uptime_checks",
            "schedule": timedelta(minutes=1),
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
    ZAP_AUTO_START = settings.zap_auto_start
    ZAP_START_CMD = settings.zap_start_cmd

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
        weak_secret_values = {
            "change-me",
            "change-me-too",
            "dev-secret-key",
            "dev-secret-key-change-me",
            "dev-jwt-secret-change-me",
        }
        weak = [
            name
            for name, value in {
                "SECRET_KEY": cls.SECRET_KEY,
                "JWT_SECRET_KEY": cls.JWT_SECRET_KEY,
            }.items()
            if value in weak_secret_values or len(value or "") < 32
        ]
        if weak:
            raise RuntimeError(
                "Production secrets must be unique random values of at least 32 characters: "
                + ", ".join(weak)
            )
        if "*" in cls.CORS_ORIGINS:
            raise RuntimeError("FRONTEND_ORIGINS must not include '*' in production")
        insecure_origins = []
        for origin in cls.CORS_ORIGINS:
            parsed = urlparse(origin)
            hostname = parsed.hostname or ""
            if parsed.scheme != "https" and hostname not in {"localhost", "127.0.0.1"}:
                insecure_origins.append(origin)
        if insecure_origins:
            raise RuntimeError("Production FRONTEND_ORIGINS must use HTTPS")


def get_config():
    environment = settings.app_env.lower()
    if environment == "production":
        return ProductionConfig
    return DevelopmentConfig
