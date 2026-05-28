# WVS

WVS is a full-stack website security and product-readiness platform. It combines the existing web vulnerability scanning pipeline with browser-based UX auditing so verified website owners can scan for launch blockers across security, accessibility, mobile layout, performance, and form usability.

The repository is split into:

- `wvs/`: React SPA for authentication, dashboarding, scan setup, history, and report viewing
- `wvs_backend/`: Flask API, Celery jobs, persistence, scanner modules, and PDF report generation

## Current Capabilities

Security scanning:
- SQL injection
- SSL/TLS and certificate checks
- security headers
- WordPress hardening and exposure checks
- optional OWASP ZAP integration
- malicious URL / reputation checks
- XSS checks
- technology fingerprinting
- sensitive file exposure checks
- DNS checks
- open redirect checks
- subdomain takeover checks

Product-readiness scanning:
- verified target ownership checks
- accessibility findings
- mobile/responsive layout findings
- performance UX findings
- form and interaction usability findings
- broken-link checks across rendered launch pages
- opt-in pre-production auth/admin route discovery
- bounded abuse-control checks for login, signup, reset, contact, and API endpoints
- bounded exposed-service checks for common dev, database, cache, admin, and web ports
- deterministic builder-ready remediation prompts
- optional AI visual review behind a provider abstraction
- scan-to-scan comparison for fixed, new, and unresolved findings

## Scan Profiles

The async full scan entrypoint now supports:

- `security_only`: preserves the original security-focused full scan behavior
- `product_readiness`: runs verified-target-aware UX/product checks
- `full_launch_audit`: combines the security pipeline with the product-readiness pipeline

## Development

Backend:

```bash
cd wvs_backend
uv sync
uv run flask --app manage.py db upgrade
uv run flask --app manage.py run
```

Celery worker:

```bash
cd wvs_backend
uv run celery -A app.celery_app.celery worker --loglevel=info
```

Separate workers for queue isolation:

```bash
cd wvs_backend
uv run celery -A app.celery_app.celery worker -Q security_scans --loglevel=info
uv run celery -A app.celery_app.celery worker -Q ux_scans --loglevel=info --concurrency=1
```

Frontend:

```bash
cd wvs
npm install
npm run dev
```

Playwright browser install for backend UX scans:

```bash
cd wvs_backend
uv run playwright install chromium
```

## Docker

The repository includes a Docker Compose setup for the full stack:

- `frontend`: Vite production build served by Nginx
- `backend`: Flask API served by Gunicorn
- `worker-security`: Celery worker for security scans
- `worker-ux`: Celery worker for Playwright-backed UX scans
- `beat`: Celery beat scheduler
- `redis`: Celery broker/result backend and rate-limit storage
- `db`: MySQL persistence
- `zap`: OWASP ZAP daemon for active web-app scanning

Create a local env file, then start the stack:

```bash
cp .env.docker.example .env.docker
docker compose --env-file .env.docker up --build
```

Open:

- Frontend: `http://localhost:8080`
- Backend API: `http://localhost:5001`

The backend image installs Chromium for Playwright and Lighthouse. Reports,
screenshots, request caches, and database files are stored in Docker volumes.

## Tests

Backend tests:

```bash
cd wvs_backend
uv run pytest
```

Frontend build check:

```bash
cd wvs
npm run build
```

## Key Environment Flags

Backend flags added for the product-readiness extension:

- `REQUIRE_VERIFIED_TARGETS`
- `TARGET_VERIFICATION_TOKEN_TTL_HOURS`
- `TARGET_VERIFICATION_TIMEOUT_SECONDS`
- `TARGET_VERIFICATION_MAX_BYTES`
- `TARGET_VERIFICATION_MAX_REDIRECTS`
- `UX_SCAN_ENABLED`
- `UX_SCAN_MAX_PAGES`
- `UX_SCAN_DEFAULT_PAGES`
- `UX_SCAN_PAGE_TIMEOUT_SECONDS`
- `UX_SCAN_SCREENSHOT_DIR`
- `UX_SCAN_ENABLE_AI_REVIEW`
- `UX_SCAN_MOBILE_WIDTH`
- `UX_SCAN_MOBILE_HEIGHT`
- `UX_SCAN_DESKTOP_WIDTH`
- `UX_SCAN_DESKTOP_HEIGHT`
- `VISUAL_AI_ENABLED`
- `VISUAL_AI_PROVIDER`
- `VISUAL_AI_API_KEY`
- `VISUAL_AI_MODEL`
- `VISUAL_AI_MAX_SCREENSHOTS_PER_SCAN`
- `VISUAL_AI_BASE_URL`
- `ABUSE_SCAN_ENABLED`
- `ABUSE_SCAN_DEFAULT_BUDGET`
- `ABUSE_SCAN_MAX_BUDGET`
- `ABUSE_SCAN_TIMEOUT_SECONDS`
- `BROKEN_LINK_MAX_LINKS_PER_PAGE`
- `BROKEN_LINK_TIMEOUT_SECONDS`
- `EXPOSED_SERVICES_ENABLED`
- `EXPOSED_SERVICES_TIMEOUT_SECONDS`
- `EXPOSED_SERVICES_MAX_PORTS`
- `EXPOSED_SERVICES_PORTS`
- `LIGHTHOUSE_ENABLED`
- `LIGHTHOUSE_CLI_PATH`
- `LIGHTHOUSE_TIMEOUT_SECONDS`
- `SECURITY_SCAN_QUEUE`
- `UX_SCAN_QUEUE`
- `UX_SCAN_RATE_LIMIT`
- `SCAN_RESULT_RETENTION_DAYS`
- `SCREENSHOT_RETENTION_DAYS`

Artifact cleanup:

```bash
cd wvs_backend
uv run flask --app manage.py cleanup-report-artifacts --dry-run
```

Lighthouse setup:

```bash
npm install -g lighthouse
export LIGHTHOUSE_ENABLED=true
```

## Safety

Use this system only against websites and applications you own or are explicitly authorized to assess. Product-readiness scans can inspect live pages, evaluate forms, and capture screenshots. Verification and SSRF protections reduce risk, but they do not replace operator responsibility.

More detail:

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [docs/UX_PRODUCT_READINESS_EXTENSION.md](docs/UX_PRODUCT_READINESS_EXTENSION.md)
- [docs/SECURITY_AND_SCAN_SAFETY.md](docs/SECURITY_AND_SCAN_SAFETY.md)
