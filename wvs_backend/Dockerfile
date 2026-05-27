FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        default-libmysqlclient-dev \
        libmagic1 \
        npm \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.5.30 /uv /uvx /usr/local/bin/

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev \
    && uv run playwright install --with-deps chromium \
    && npm install -g lighthouse@12 \
    && rm -rf /root/.cache /tmp/*

COPY . .

RUN mkdir -p /app/instance /app/reports /app/reports/screenshots /app/reports/malware

EXPOSE 5001

CMD ["sh", "-c", "uv run flask --app manage.py db upgrade && uv run gunicorn --bind 0.0.0.0:${PORT:-5001} --workers ${WEB_CONCURRENCY:-2} --threads ${WEB_THREADS:-4} --timeout ${WEB_TIMEOUT:-120} wsgi:app"]
