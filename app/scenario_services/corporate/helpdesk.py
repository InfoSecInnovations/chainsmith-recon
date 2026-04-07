"""
app/scenario_services/corporate/helpdesk.py

IT helpdesk landing page service template.

This service provides an internal IT support portal with version disclosure
and security header observations. It simulates a typical corporate helpdesk.

Configurable via environment variables:
    BRAND_NAME          Display name (default: HelpDesk Portal)
    HELPDESK_VERSION    Service version (default: 2.4.1)
    CHAT_URL            URL to chat service (default: http://localhost:8201)

Planted observations:
    version_disclosure          X-Powered-By and Server headers
    missing_security_headers    No CSP, X-Frame-Options, HSTS
    robots_sensitive_paths      robots.txt exposes internal paths
    verbose_errors              Full stack traces
    unauthed_docs               /docs and /openapi.json accessible

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.corporate.helpdesk:app
      --host 0.0.0.0 --port 8200
"""

import os
import traceback

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from app.scenario_services.common.config import (
    SERVICE_NAME,
    VERBOSE_ERRORS,
    get_brand_name,
    get_or_create_session,
    is_observation_active,
)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

HELPDESK_VERSION = os.getenv("HELPDESK_VERSION", "2.4.1")
CHAT_URL = os.getenv("CHAT_URL", "http://localhost:8201")


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="HelpDesk Portal",
    description="IT support portal",
    version=HELPDESK_VERSION,
    # /docs and /openapi.json intentionally enabled - unauthed_docs observation
)


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════


@app.middleware("http")
async def add_response_headers(request: Request, call_next):
    """Add headers based on active observations."""
    try:
        response = await call_next(request)
    except Exception as exc:
        if VERBOSE_ERRORS:
            return JSONResponse(
                status_code=500,
                content={
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                    "service": SERVICE_NAME or "helpdesk-www",
                    "path": str(request.url.path),
                },
            )
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

    # Observation: version_disclosure - leak versions in headers
    if is_observation_active("version_disclosure"):
        response.headers["X-Powered-By"] = "FastAPI/0.111.0"
        response.headers["Server"] = f"helpdesk-portal/{HELPDESK_VERSION}"

    # Observation: missing_security_headers - intentionally NOT adding these
    # CSP, X-Frame-Options, HSTS are missing

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/", response_class=HTMLResponse)
async def home():
    """Main portal page."""
    brand = get_brand_name() or "IT HelpDesk"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{brand}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; margin: 0; padding: 0; background: #f0f2f5; }}
        .header {{ background: #2563eb; color: white; padding: 24px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .nav {{ background: #1d4ed8; padding: 12px; text-align: center; }}
        .nav a {{ color: white; margin: 0 16px; text-decoration: none; }}
        .content {{ max-width: 900px; margin: 32px auto; padding: 24px; }}
        .card {{ background: white; padding: 24px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 16px; }}
        .footer {{ text-align: center; padding: 24px; color: #6b7280; font-size: 14px; }}
        .btn {{ display: inline-block; background: #2563eb; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛠️ {brand}</h1>
        <p>Internal IT Support Portal</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/tickets">My Tickets</a>
        <a href="/kb">Knowledge Base</a>
        <a href="/status">Service Status</a>
        <a href="/contact">Contact</a>
    </div>
    <div class="content">
        <div class="card">
            <h2>Welcome to IT Support</h2>
            <p>Get help with passwords, VPN, hardware, software, and more.</p>
            <p><a href="{CHAT_URL}" class="btn">Chat with AI Assistant</a></p>
        </div>
        <div class="card">
            <h3>Quick Links</h3>
            <ul>
                <li><a href="/kb/password-reset">Password Reset Guide</a></li>
                <li><a href="/kb/vpn-setup">VPN Setup Instructions</a></li>
                <li><a href="/kb/software-request">Request New Software</a></li>
                <li><a href="/tickets/new">Submit a Ticket</a></li>
            </ul>
        </div>
    </div>
    <div class="footer">
        <p>&copy; 2024 IT Department. Internal Use Only.</p>
    </div>
</body>
</html>"""


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots():
    """
    Observation: robots_sensitive_paths
    Discloses internal and admin paths.
    """
    return """User-agent: *
Allow: /
Disallow: /internal/
Disallow: /admin/
Disallow: /api/internal/
Disallow: /debug/
Disallow: /metrics/
"""


@app.get("/health")
async def health():
    """Health check endpoint."""
    session = get_or_create_session()
    return {
        "status": "healthy",
        "service": SERVICE_NAME or "helpdesk-www",
        "version": HELPDESK_VERSION,
        "session_id": session.session_id,
    }


@app.get("/tickets", response_class=HTMLResponse)
async def tickets():
    """Tickets page stub."""
    return """<html><body><h1>My Tickets</h1><p>Authentication required.</p></body></html>"""


@app.get("/kb", response_class=HTMLResponse)
async def knowledge_base():
    """Knowledge base page."""
    return """<html><body><h1>Knowledge Base</h1>
<ul>
<li><a href="/kb/password-reset">Password Reset</a></li>
<li><a href="/kb/vpn-setup">VPN Setup</a></li>
<li><a href="/kb/software-request">Software Requests</a></li>
</ul></body></html>"""


@app.get("/status")
async def status():
    """Service status page."""
    return {
        "services": [
            {"name": "Email", "status": "operational"},
            {"name": "VPN", "status": "operational"},
            {"name": "Active Directory", "status": "operational"},
            {"name": "File Shares", "status": "degraded"},
        ],
        "last_updated": "2024-01-15T12:00:00Z",
    }


@app.get("/contact", response_class=HTMLResponse)
async def contact():
    """Contact page."""
    return """<html><body><h1>Contact IT</h1>
<p><strong>Email:</strong> helpdesk@corp.internal</p>
<p><strong>Phone:</strong> x4357 (HELP)</p>
<p><strong>Hours:</strong> Mon-Fri 8am-6pm</p>
</body></html>"""
