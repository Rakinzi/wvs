FROM python:2.7-slim AS nosqlmap-runtime

WORKDIR /opt/nosqlmap

RUN sed -i 's|http://deb.debian.org/debian|http://archive.debian.org/debian|g; s|http://security.debian.org/debian-security|http://archive.debian.org/debian-security|g; /buster-updates/d' /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
    && curl -fsSL https://codeload.github.com/codingo/NoSQLMap/tar.gz/master -o /tmp/nosqlmap.tgz \
    && tar -xzf /tmp/nosqlmap.tgz -C /opt/nosqlmap --strip-components=1 \
    && python -m pip install --no-cache-dir \
        "CouchDB==1.0" \
        "httplib2==0.19.0" \
        "ipcalc==1.1.3" \
        "pbkdf2==1.3" \
        "pymongo==2.7.2" \
        "requests<2.28" \
        "certifi<=2020.4.5.1" \
    && chmod +x /opt/nosqlmap/nosqlmap.py \
    && rm -rf /tmp/nosqlmap.tgz /var/lib/apt/lists/*

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
        ruby \
        ruby-dev \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libjson-perl \
        libio-socket-ssl-perl \
        libnet-ssleay-perl \
        libxml-writer-perl \
    && for pkg in nmap nikto whatweb wafw00f sslscan sqlmap ffuf; do \
        if apt-cache show "$pkg" >/dev/null 2>&1; then \
            apt-get install -y --no-install-recommends "$pkg"; \
        fi; \
    done \
    && curl -fsSL https://codeload.github.com/sullo/nikto/tar.gz/main -o /tmp/nikto.tgz \
    && mkdir -p /opt/nikto \
    && tar -xzf /tmp/nikto.tgz -C /opt/nikto --strip-components=1 \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && gem install wpscan --no-document \
    && rm -rf /var/lib/apt/lists/*

COPY --from=nosqlmap-runtime /usr/local/bin/python2.7 /usr/local/bin/python2.7
COPY --from=nosqlmap-runtime /usr/local/lib/libpython2.7.so.1.0 /usr/local/lib/
COPY --from=nosqlmap-runtime /usr/local/lib/python2.7 /usr/local/lib/python2.7
COPY --from=nosqlmap-runtime /usr/lib/x86_64-linux-gnu/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/
COPY --from=nosqlmap-runtime /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/
COPY --from=nosqlmap-runtime /opt/nosqlmap /opt/nosqlmap

RUN printf '%s\n' \
        '#!/bin/sh' \
        'export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}' \
        'cd /opt/nosqlmap' \
        'exec /usr/local/bin/python2.7 /opt/nosqlmap/nosqlmap.py "$@"' \
        > /usr/local/bin/nosqlmap \
    && chmod +x /usr/local/bin/nosqlmap

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
