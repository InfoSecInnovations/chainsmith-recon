"""
app/scenario_services/corporate/admin.py

Administrative panel service template.

This service provides an admin interface with debug endpoints and
configuration exposure findings. It's designed to simulate an
improperly secured admin panel.

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    ADMIN_VERSION       Service version (default: 1.5.0)

Planted findings:
    debug_mode_enabled      X-Debug-Mode header
    stack_trace_leak        Full stack traces on errors
    debug_endpoints_enabled /debug endpoint accessible
    config_dump_endpoint    /debug/dump with credentials

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.corporate.admin:app
      --host 0.0.0.0 --port 8086
    environment:
      - BRAND_NAME=Fakobanko
"""

import os
import traceback

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.scenario_services.common.config import (
    get_brand_name,
    get_or_create_session,
    is_finding_active,
)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

ADMIN_VERSION = os.getenv("ADMIN_VERSION", "1.5.0")


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Admin Panel",
    description="Administrative interface",
    version=ADMIN_VERSION,
)


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════


@app.exception_handler(Exception)
async def verbose_exception_handler(request: Request, exc: Exception):
    """
    Finding: stack_trace_leak
    When active, returns full stack traces with server info.
    """
    if is_finding_active("stack_trace_leak"):
        tb = traceback.format_exc()
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "exception": str(exc),
                "type": type(exc).__name__,
                "traceback": tb.split("\n"),
                "server_info": {
                    "python_version": "3.11.4",
                    "framework": "FastAPI 0.109.0",
                },
            },
        )
    return JSONResponse(status_code=500, content={"error": "Internal Server Error"})


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════


@app.middleware("http")
async def add_headers(request: Request, call_next):
    """Add headers based on active findings."""
    response = await call_next(request)

    response.headers["X-Admin-Panel"] = "true"

    # Finding: debug_mode_enabled - leak debug status
    if is_finding_active("debug_mode_enabled"):
        response.headers["X-Debug-Mode"] = "enabled"

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/", response_class=HTMLResponse)
async def root():
    """Admin panel landing page."""
    brand = get_brand_name()
    return f"""<!DOCTYPE html>
<html>
<head><title>{brand} Admin</title></head>
<body style="font-family: Arial; margin: 40px; background: #1a1a2e; color: #eee;">
    <h1>🔐 {brand} Admin Panel</h1>
    <p>Administrative access required.</p>
    <ul>
        <li><a href="/dashboard" style="color: #4da6ff;">Dashboard</a></li>
        <li><a href="/users" style="color: #4da6ff;">User Management</a></li>
        <li><a href="/settings" style="color: #4da6ff;">Settings</a></li>
    </ul>
</body>
</html>"""


@app.get("/health")
async def health():
    """Health check endpoint."""
    session = get_or_create_session()
    brand = get_brand_name().lower().replace(" ", "-")

    return {
        "status": "healthy",
        "service": f"{brand}-admin",
        "session_id": session.session_id,
    }


@app.get("/dashboard")
async def dashboard():
    """Admin dashboard."""
    return {
        "stats": {
            "active_users": 1247,
            "daily_transactions": 8432,
            "ai_queries_today": 2156,
            "error_rate": "0.02%",
        },
        "alerts": [
            {"level": "info", "message": "System update scheduled for tonight"},
            {"level": "warning", "message": "Elevated login failures from IP range 192.168.1.x"},
        ],
    }


@app.get("/users")
async def list_users():
    """User management - requires auth (not implemented in lab)."""
    return {
        "message": "Authentication required",
        "total_users": 1247,
    }


@app.get("/settings")
async def get_settings():
    """System settings - sanitized view."""
    return {
        "rate_limiting": True,
        "waf_enabled": False,
        "debug_mode": is_finding_active("debug_mode_enabled"),
        "maintenance_window": "Sunday 2:00-4:00 AM EST",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# DEBUG ENDPOINTS (findings)
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/debug")
async def debug_info():
    """
    Debug endpoint.

    Finding: debug_endpoints_enabled
    Only accessible when this finding is active.
    """
    if not is_finding_active("debug_endpoints_enabled"):
        raise HTTPException(404, "Not found")

    brand = get_brand_name().lower().replace(" ", "-")

    return {
        "debug_mode": True,
        "environment": "production",
        "server": {
            "hostname": f"admin-prod-01.{brand}.internal",
            "ip": "10.0.5.12",
        },
    }


@app.get("/debug/dump")
async def debug_dump():
    """
    Full debug dump - very sensitive!

    Finding: config_dump_endpoint
    Returns fake but realistic credentials.
    """
    if not is_finding_active("config_dump_endpoint"):
        raise HTTPException(403, "Access denied")

    brand = get_brand_name().lower().replace(" ", "-")

    return {
        "environment_variables": {
            "DATABASE_URL": f"postgresql://admin:{brand.title()}_Pr0d!@db-prod.{brand}.internal:5432/{brand}",
            "JWT_SECRET": f"{brand[:3]}-jwt-secret-do-not-share-v2",
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "REDIS_URL": f"redis://{brand}-cache.internal:6379",
        },
        "internal_services": {
            "ml_endpoint": f"http://ml.{brand}.internal:8084",
            "vector_db": f"http://vector.{brand}.internal:8087",
            "mcp_server": f"http://mcp.{brand}.internal:8089",
        },
    }


@app.get("/trigger-error")
async def trigger_error():
    """
    Endpoint to trigger an error for stack trace testing.

    Used for demonstrating stack_trace_leak finding.
    """
    raise ValueError("Intentional error for debugging")


@app.get("/debug/env")
async def debug_env():
    """
    Environment variable dump.

    Finding: config_dump_endpoint
    """
    if not is_finding_active("config_dump_endpoint"):
        raise HTTPException(403, "Access denied")

    # Return selected (fake) env vars
    return {
        "env": {
            "NODE_ENV": "production",
            "LOG_LEVEL": "debug",
            "ENABLE_METRICS": "true",
            "SENTRY_DSN": "https://fake@sentry.internal/123",
        }
    }


@app.get("/debug/routes")
async def debug_routes():
    """
    List all registered routes.

    Finding: debug_endpoints_enabled
    """
    if not is_finding_active("debug_endpoints_enabled"):
        raise HTTPException(404, "Not found")

    routes = []
    for route in app.routes:
        if hasattr(route, "path") and hasattr(route, "methods"):
            routes.append(
                {
                    "path": route.path,
                    "methods": list(route.methods) if route.methods else [],
                }
            )

    return {"routes": routes, "total": len(routes)}
