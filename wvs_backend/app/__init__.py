from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy

from app.config import get_config


db = SQLAlchemy()
jwt = JWTManager()
celery = None
limiter = Limiter(key_func=get_remote_address, default_limits=[])


def init_celery(app: Flask):
    global celery
    if celery is None:
        from celery import Celery

        celery = Celery("wvs")

    celery.conf.update(
        broker_url=app.config["CELERY_BROKER_URL"],
        result_backend=app.config["CELERY_RESULT_BACKEND"],
        task_serializer=app.config["CELERY_TASK_SERIALIZER"],
        accept_content=app.config["CELERY_ACCEPT_CONTENT"],
        result_serializer=app.config["CELERY_RESULT_SERIALIZER"],
        task_track_started=app.config["CELERY_TASK_TRACK_STARTED"],
        task_time_limit=app.config["CELERY_TASK_TIME_LIMIT"],
        timezone=app.config["CELERY_TIMEZONE"],
        enable_utc=True,
        broker_connection_retry_on_startup=app.config["BROKER_CONNECTION_RETRY_ON_STARTUP"],
        imports=app.config["CELERY_IMPORTS"],
        beat_schedule=app.config["CELERY_BEAT_SCHEDULE"],
        task_default_queue=app.config["SECURITY_SCAN_QUEUE"],
        task_annotations={
            "app.tasks.run_full_scan_job": {"rate_limit": app.config["UX_SCAN_RATE_LIMIT"]},
        },
    )

    class FlaskTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = FlaskTask
    return celery


def register_blueprints(app: Flask) -> None:
    from app.routes.blocked_access import bp as blocked_access_bp
    from app.routes.dashboard import bp as dashboard_bp
    from app.routes.malicious import bp as malicious_bp
    from app.routes.news import bp as news_bp
    from app.routes.scans import bp as scans_bp
    from app.routes.targets import bp as targets_bp
    from app.routes.uptime import bp as uptime_bp
    from app.routes.users import bp as users_bp

    app.register_blueprint(blocked_access_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(news_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(malicious_bp)
    app.register_blueprint(targets_bp)
    app.register_blueprint(uptime_bp)


def create_app(config_class=None):
    resolved_config = config_class or get_config()
    resolved_config.validate()

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(resolved_config)

    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    CORS(
        app,
        resources={r"/*": {"origins": app.config["CORS_ORIGINS"]}},
        supports_credentials=True,
        allow_headers=["Authorization", "Content-Type", "X-CSRF-TOKEN"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )

    @jwt.unauthorized_loader
    def handle_missing_jwt(reason: str):
        return jsonify({"error": "Authentication is required"}), 401

    @jwt.invalid_token_loader
    def handle_invalid_jwt(reason: str):
        return jsonify({"error": "Invalid authentication token"}), 401

    @jwt.expired_token_loader
    def handle_expired_jwt(jwt_header, jwt_payload):
        return jsonify({"error": "Authentication token has expired"}), 401

    @jwt.revoked_token_loader
    def handle_revoked_jwt(jwt_header, jwt_payload):
        return jsonify({"error": "Authentication token is no longer valid"}), 401

    @jwt.needs_fresh_token_loader
    def handle_non_fresh_jwt(jwt_header, jwt_payload):
        return jsonify({"error": "A fresh authentication token is required"}), 401

    @jwt.user_lookup_error_loader
    def handle_missing_user(jwt_header, jwt_payload):
        return jsonify({"error": "Authenticated user was not found"}), 401

    @app.after_request
    def apply_security_headers(response):
        if not app.config.get("SECURITY_HEADERS_ENABLED", True):
            return response

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Permissions-Policy",
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'",
        )

        sensitive_paths = (
            "/login",
            "/register",
            "/forgot-password",
            "/reset-password",
            "/profile",
            "/users",
            "/scan",
            "/report",
            "/api/dashboard",
        )
        if request.headers.get("Authorization") or request.path.startswith(sensitive_paths):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"

        return response

    register_blueprints(app)

    from app.commands import register_commands

    register_commands(app)
    if app.config["AUTO_CREATE_TABLES"]:
        with app.app_context():
            db.create_all()

    return app
