from __future__ import annotations

from contextlib import asynccontextmanager

import sentry_sdk
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sentry_sdk.integrations.celery import CeleryIntegration
from sentry_sdk.integrations.fastapi import FastApiIntegration

from app import db
from app.config import get_config
from app.settings import settings


def _init_sentry() -> None:
    dsn = getattr(settings, "sentry_dsn", None)
    if not dsn:
        return
    sentry_sdk.init(
        dsn=dsn,
        environment=settings.app_env,
        integrations=[FastApiIntegration(), CeleryIntegration()],
        traces_sample_rate=getattr(settings, "sentry_traces_sample_rate", 0.0),
    )


def _security_headers(response: Response) -> None:
    if not settings.security_headers_enabled:
        return
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    config = get_config()
    db.init_db(config.SQLALCHEMY_DATABASE_URI)
    if getattr(config, "AUTO_CREATE_TABLES", False):
        db.create_all()
    yield
    db.session.remove()


def create_fastapi_app() -> FastAPI:
    _init_sentry()

    app = FastAPI(
        title="LaunchGuard Scanner API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_frontend_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-TOKEN"],
    )

    @app.middleware("http")
    async def session_and_security(request: Request, call_next):
        try:
            response = await call_next(request)
            _security_headers(response)
            return response
        finally:
            db.session.remove()

    # ── Routers ──────────────────────────────────────────────────────────────
    from app.routes.users import router as users_router
    from app.routes.scans import router as scans_router
    from app.routes.targets import router as targets_router
    from app.routes.uptime import router as uptime_router
    from app.routes.dashboard import router as dashboard_router
    from app.routes.malicious import router as malicious_router
    from app.routes.blocked_access import router as blocked_access_router
    from app.routes.news import router as news_router

    for r in (users_router, scans_router, targets_router, uptime_router,
              dashboard_router, malicious_router, blocked_access_router, news_router):
        app.include_router(r)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "service": "api"}

    return app
