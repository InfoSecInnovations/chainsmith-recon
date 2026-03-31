# ─────────────────────────────────────────────────────────────────
# Chainsmith Recon — Standalone Runtime Image
#
# Provides the Python/FastAPI runtime used by both the recon agent
# and the demo-domain target. App code is mounted at runtime via
# docker-compose volumes — do NOT bake app code into this image.
#
# Build:
#   docker build -t chainsmith/runtime:latest .
# ─────────────────────────────────────────────────────────────────

FROM python:3.11-slim

# ── System deps ───────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        dnsutils \
        netcat-openbsd \
        gcc \
        pkg-config \
        libcairo2-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Python deps ───────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Entrypoint ────────────────────────────────────────────────────
# APP_MODULE, HOST, and PORT are injected by docker-compose.
# Uvicorn is used directly — no Caddy/nginx layer in standalone mode.
CMD uvicorn ${APP_MODULE} \
        --host ${HOST:-0.0.0.0} \
        --port ${PORT:-8000} \
        --reload \
        --log-level info
