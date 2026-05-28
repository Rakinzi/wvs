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
    require_verified_targets: bool = Field(default=False, alias="REQUIRE_VERIFIED_TARGETS")
    security_headers_enabled: bool = Field(default=True, alias="SECURITY_HEADERS_ENABLED")
    target_verification_token_ttl_hours: int = Field(default=24, alias="TARGET_VERIFICATION_TOKEN_TTL_HOURS")
    target_verification_timeout_seconds: int = Field(default=10, alias="TARGET_VERIFICATION_TIMEOUT_SECONDS")
    target_verification_max_bytes: int = Field(default=1_000_000, alias="TARGET_VERIFICATION_MAX_BYTES")
    target_verification_max_redirects: int = Field(default=3, alias="TARGET_VERIFICATION_MAX_REDIRECTS")
    ux_scan_enabled: bool = Field(default=True, alias="UX_SCAN_ENABLED")
    ux_scan_max_pages: int = Field(default=10, alias="UX_SCAN_MAX_PAGES")
    ux_scan_default_pages: int = Field(default=5, alias="UX_SCAN_DEFAULT_PAGES")
    ux_scan_page_timeout_seconds: int = Field(default=20, alias="UX_SCAN_PAGE_TIMEOUT_SECONDS")
    ux_scan_screenshot_dir: str = Field(default=str(DEFAULT_REPORTS_PATH / "screenshots"), alias="UX_SCAN_SCREENSHOT_DIR")
    ux_scan_enable_ai_review: bool = Field(default=False, alias="UX_SCAN_ENABLE_AI_REVIEW")
    ux_scan_mobile_width: int = Field(default=390, alias="UX_SCAN_MOBILE_WIDTH")
    ux_scan_mobile_height: int = Field(default=844, alias="UX_SCAN_MOBILE_HEIGHT")
    ux_scan_desktop_width: int = Field(default=1440, alias="UX_SCAN_DESKTOP_WIDTH")
    ux_scan_desktop_height: int = Field(default=1024, alias="UX_SCAN_DESKTOP_HEIGHT")
    visual_ai_enabled: bool = Field(default=False, alias="VISUAL_AI_ENABLED")
    visual_ai_provider: str | None = Field(default=None, alias="VISUAL_AI_PROVIDER")
    visual_ai_api_key: str | None = Field(default=None, alias="VISUAL_AI_API_KEY")
    visual_ai_model: str | None = Field(default=None, alias="VISUAL_AI_MODEL")
    visual_ai_base_url: str = Field(default="https://api.openai.com/v1", alias="VISUAL_AI_BASE_URL")
    visual_ai_timeout_seconds: int = Field(default=45, alias="VISUAL_AI_TIMEOUT_SECONDS")
    visual_ai_max_screenshots_per_scan: int = Field(default=5, alias="VISUAL_AI_MAX_SCREENSHOTS_PER_SCAN")
    abuse_scan_enabled: bool = Field(default=True, alias="ABUSE_SCAN_ENABLED")
    abuse_scan_default_budget: int = Field(default=8, alias="ABUSE_SCAN_DEFAULT_BUDGET")
    abuse_scan_max_budget: int = Field(default=20, alias="ABUSE_SCAN_MAX_BUDGET")
    abuse_scan_timeout_seconds: int = Field(default=8, alias="ABUSE_SCAN_TIMEOUT_SECONDS")
    broken_link_max_links_per_page: int = Field(default=50, alias="BROKEN_LINK_MAX_LINKS_PER_PAGE")
    broken_link_timeout_seconds: int = Field(default=8, alias="BROKEN_LINK_TIMEOUT_SECONDS")
    app_controls_enabled: bool = Field(default=True, alias="APP_CONTROLS_ENABLED")
    app_controls_timeout_seconds: int = Field(default=8, alias="APP_CONTROLS_TIMEOUT_SECONDS")
    app_controls_max_js_files: int = Field(default=20, alias="APP_CONTROLS_MAX_JS_FILES")
    app_controls_max_endpoints: int = Field(default=50, alias="APP_CONTROLS_MAX_ENDPOINTS")
    exposed_services_enabled: bool = Field(default=True, alias="EXPOSED_SERVICES_ENABLED")
    exposed_services_timeout_seconds: float = Field(default=1.5, alias="EXPOSED_SERVICES_TIMEOUT_SECONDS")
    exposed_services_max_ports: int = Field(default=32, alias="EXPOSED_SERVICES_MAX_PORTS")
    exposed_services_ports: str = Field(
        default="22,80,443,2222,3000,3306,3389,5000,5173,5432,6379,8000,8080,8443,9200,1025,8025,27017",
        alias="EXPOSED_SERVICES_PORTS",
    )
    lighthouse_enabled: bool = Field(default=False, alias="LIGHTHOUSE_ENABLED")
    lighthouse_cli_path: str | None = Field(default=None, alias="LIGHTHOUSE_CLI_PATH")
    lighthouse_timeout_seconds: int = Field(default=90, alias="LIGHTHOUSE_TIMEOUT_SECONDS")
    security_scan_queue: str = Field(default="security_scans", alias="SECURITY_SCAN_QUEUE")
    ux_scan_queue: str = Field(default="ux_scans", alias="UX_SCAN_QUEUE")
    ux_scan_rate_limit: str = Field(default="10/h", alias="UX_SCAN_RATE_LIMIT")
    scan_result_retention_days: int = Field(default=90, alias="SCAN_RESULT_RETENTION_DAYS")
    screenshot_retention_days: int = Field(default=30, alias="SCREENSHOT_RETENTION_DAYS")
    uptime_monitor_enabled: bool = Field(default=True, alias="UPTIME_MONITOR_ENABLED")
    uptime_monitor_default_interval_minutes: int = Field(default=5, alias="UPTIME_MONITOR_DEFAULT_INTERVAL_MINUTES")
    uptime_monitor_request_timeout_seconds: int = Field(default=15, alias="UPTIME_MONITOR_REQUEST_TIMEOUT_SECONDS")
    uptime_monitor_history_limit: int = Field(default=100, alias="UPTIME_MONITOR_HISTORY_LIMIT")
    malware_scan_enabled: bool = Field(default=True, alias="MALWARE_SCAN_ENABLED")
    malware_max_artifacts: int = Field(default=5, alias="MALWARE_MAX_ARTIFACTS")
    malware_max_download_bytes: int = Field(default=25 * 1024 * 1024, alias="MALWARE_MAX_DOWNLOAD_BYTES")
    malware_download_timeout_seconds: int = Field(default=20, alias="MALWARE_DOWNLOAD_TIMEOUT_SECONDS")
    malware_temp_dir: str = Field(default=str(DEFAULT_REPORTS_PATH / "malware"), alias="MALWARE_TEMP_DIR")
    malware_allowed_extensions: str = Field(
        default=".exe,.dll,.msi,.jar,.js,.vbs,.ps1,.bat,.cmd,.scr,.doc,.docm,.xls,.xlsm,.ppt,.pptm,.rtf,.pdf,.zip",
        alias="MALWARE_ALLOWED_EXTENSIONS",
    )
    clamav_enabled: bool = Field(default=False, alias="CLAMAV_ENABLED")
    clamav_network_socket: str | None = Field(default=None, alias="CLAMAV_NETWORK_SOCKET")
    clamav_unix_socket: str | None = Field(default=None, alias="CLAMAV_UNIX_SOCKET")
    yara_enabled: bool = Field(default=True, alias="YARA_ENABLED")
    yara_rules_dir: str = Field(default=str(BASE_DIR / "app" / "yara_rules"), alias="YARA_RULES_DIR")

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
    max_scan_time: int = Field(default=900, alias="MAX_SCAN_TIME")
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
    zap_auto_start: bool = Field(default=False, alias="ZAP_AUTO_START")
    zap_start_cmd: str | None = Field(default=None, alias="ZAP_START_CMD")

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
