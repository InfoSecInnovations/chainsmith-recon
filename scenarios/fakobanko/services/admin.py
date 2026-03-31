"""
Fakobanko Admin Panel

Administrative interface with debug and configuration exposure findings.
"""

import traceback
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse

from fakobanko.config import is_finding_active, get_or_create_session


app = FastAPI(
    title="Fakobanko Admin Panel",
    description="Administrative interface",
    version="1.5.0",
)


# ─── Exception Handler ─────────────────────────────────────────

@app.exception_handler(Exception)
async def verbose_exception_handler(request: Request, exc: Exception):
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
                }
            }
        )
    return JSONResponse(status_code=500, content={"error": "Internal Server Error"})


# ─── Middleware ────────────────────────────────────────────────

@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Admin-Panel"] = "true"
    
    if is_finding_active("debug_mode_enabled"):
        response.headers["X-Debug-Mode"] = "enabled"
    
    return response


# ─── Endpoints ─────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
<!DOCTYPE html>
<html>
<head><title>Fakobanko Admin</title></head>
<body style="font-family: Arial; margin: 40px; background: #1a1a2e; color: #eee;">
    <h1>🔐 Fakobanko Admin Panel</h1>
    <p>Administrative access required.</p>
</body>
</html>
"""


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {"status": "healthy", "service": "fakobanko-admin", "session_id": session.session_id}


@app.get("/debug")
async def debug_info():
    """Debug endpoint - may expose sensitive info."""
    if not is_finding_active("debug_endpoints_enabled"):
        raise HTTPException(404, "Not found")
    
    return {
        "debug_mode": True,
        "environment": "production",
        "server": {"hostname": "admin-prod-01.fakobanko.internal", "ip": "10.0.5.12"}
    }


@app.get("/debug/dump")
async def debug_dump():
    """Full debug dump - very sensitive!"""
    if not is_finding_active("config_dump_endpoint"):
        raise HTTPException(403, "Access denied")
    
    return {
        "environment_variables": {
            "DATABASE_URL": "postgresql://admin:Fak0bank0_Pr0d!@db-prod.fakobanko.internal:5432/fakobanko",
            "JWT_SECRET": "fkb-jwt-secret-do-not-share-v2",
            "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        }
    }


@app.get("/trigger-error")
async def trigger_error():
    """Endpoint to trigger an error for stack trace testing."""
    raise ValueError("Intentional error for debugging")
