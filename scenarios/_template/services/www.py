"""
scenarios/_template/services/www.py

Minimal example service. Copy and customize for your scenario.

This service demonstrates:
- Basic FastAPI setup with health check
- Intentional security issues for Chainsmith to discover
- How to structure a scenario service
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(
    title="Template Service",
    description="Minimal scenario service template",
    version="1.0.0",
)


# ─── Health Check ────────────────────────────────────────────────
# Required for Docker health checks

@app.get("/health")
async def health():
    return {"status": "ok"}


# ─── Root Endpoint ───────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": "template",
        "message": "Welcome to the template scenario",
        "endpoints": ["/", "/health", "/api/info", "/robots.txt"],
    }


# ─── Example API Endpoint ────────────────────────────────────────
# Intentionally exposes version info (finding: version disclosure)

@app.get("/api/info")
async def api_info():
    return {
        "version": "1.0.0",
        "framework": "FastAPI",
        "python": "3.11",
        # Intentional disclosure for demo purposes
        "internal_endpoint": "http://internal-api:8080",
    }


# ─── robots.txt ──────────────────────────────────────────────────
# Intentionally exposes sensitive paths (finding: sensitive paths)

@app.get("/robots.txt")
async def robots():
    content = """User-agent: *
Disallow: /admin
Disallow: /internal
Disallow: /api/debug
Disallow: /backup
"""
    return PlainTextResponse(content, media_type="text/plain")


# ─── Missing Security Headers ────────────────────────────────────
# Middleware that intentionally omits security headers

@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    # Intentionally adding version header (finding: version disclosure)
    response.headers["X-Powered-By"] = "FastAPI/0.100.0"
    response.headers["Server"] = "uvicorn/0.23.0"
    # Note: Missing security headers like X-Content-Type-Options,
    # X-Frame-Options, Content-Security-Policy (finding: missing headers)
    return response
