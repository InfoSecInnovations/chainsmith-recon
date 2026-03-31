"""
app/scenario_services/common/docs.py

API documentation portal service template.

This service provides a documentation landing page with links to
OpenAPI/Swagger documentation. It can expose internal endpoints
and authentication schemes based on active findings.

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    DOCS_VERSION        Documentation version (default: 2.0.0)
    API_BASE_URL        Base URL for API references (default: http://localhost:8080)

Planted findings:
    openapi_exposed             Adds internal servers to OpenAPI spec
    internal_endpoints_documented   Documents internal/admin endpoints
    auth_schemes_revealed       X-Auth-Schemes header leak

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.common.docs:app
      --host 0.0.0.0 --port 8083
    environment:
      - BRAND_NAME=Fakobanko
      - DOCS_VERSION=2.0.0
"""

import os

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.openapi.utils import get_openapi

from app.scenario_services.common.config import (
    SERVICE_NAME,
    is_finding_active,
    get_or_create_session,
    get_brand_name,
    get_brand_domain,
)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

DOCS_VERSION = os.getenv("DOCS_VERSION", "2.0.0")
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8080")


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="API Documentation",
    description="Developer documentation portal",
    version=DOCS_VERSION,
)


# ═══════════════════════════════════════════════════════════════════════════════
# OPENAPI CUSTOMIZATION
# ═══════════════════════════════════════════════════════════════════════════════

def custom_openapi():
    """
    Generate customized OpenAPI schema with optional internal info.
    
    Findings:
        openapi_exposed: Adds internal server URLs
        internal_endpoints_documented: Documents admin endpoints
    """
    if app.openapi_schema:
        return app.openapi_schema

    brand = get_brand_name()
    domain = get_brand_domain()

    openapi_schema = get_openapi(
        title=f"{brand} API",
        version=DOCS_VERSION,
        description=f"{brand} API - Documentation",
        routes=app.routes,
    )

    # Finding: openapi_exposed - leak internal server info
    if is_finding_active("openapi_exposed"):
        openapi_schema["info"]["x-internal"] = True
        openapi_schema["servers"] = [
            {"url": f"https://api.{domain}", "description": "Production"},
            {"url": f"https://api-staging.{domain.replace('.local', '.internal')}", "description": "Staging"},
            {"url": "http://localhost:8080", "description": "Development"},
        ]

    # Finding: internal_endpoints_documented - expose admin routes
    if is_finding_active("internal_endpoints_documented"):
        openapi_schema["paths"]["/internal/admin"] = {
            "get": {
                "summary": "Admin endpoint",
                "description": "Internal admin access - requires VPN",
                "responses": {"200": {"description": "Admin panel"}},
            }
        }
        openapi_schema["paths"]["/internal/metrics"] = {
            "get": {
                "summary": "Metrics endpoint",
                "description": "Prometheus metrics",
                "responses": {"200": {"description": "Metrics"}},
            }
        }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

@app.middleware("http")
async def add_headers(request: Request, call_next):
    """Add headers based on active findings."""
    response = await call_next(request)

    response.headers["X-Docs-Version"] = DOCS_VERSION

    # Finding: auth_schemes_revealed - leak authentication methods
    if is_finding_active("auth_schemes_revealed"):
        response.headers["X-Auth-Schemes"] = "Bearer, API-Key, Internal-Token"

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def root():
    """Documentation landing page."""
    brand = get_brand_name()

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>{brand} API Docs</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; }}
        h1 {{ color: #1a365d; }}
        a {{ color: #2c5282; }}
        .endpoint {{ background: #edf2f7; padding: 12px; margin: 8px 0; border-radius: 4px; }}
        .method {{ font-weight: bold; color: #2b6cb0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🏦 {brand} API Documentation</h1>
        <p>Welcome to the {brand} API documentation portal.</p>
        
        <h2>Quick Links</h2>
        <ul>
            <li><a href="/docs">Interactive API Docs (Swagger UI)</a></li>
            <li><a href="/redoc">API Reference (ReDoc)</a></li>
            <li><a href="/openapi.json">OpenAPI Specification</a></li>
        </ul>
        
        <h2>Available APIs</h2>
        <div class="endpoint"><span class="method">GET</span> /api/v1/accounts - List accounts</div>
        <div class="endpoint"><span class="method">GET</span> /api/v1/transactions - Get transactions</div>
        <div class="endpoint"><span class="method">POST</span> /api/v1/transfers - Initiate transfer</div>
        <div class="endpoint"><span class="method">GET</span> /api/v1/customers - Customer lookup</div>
        
        <h2>Authentication</h2>
        <p>All API requests require authentication via Bearer token or API key.</p>
    </div>
</body>
</html>"""


@app.get("/health")
async def health():
    """Health check endpoint."""
    session = get_or_create_session()
    brand = get_brand_name()

    return {
        "status": "healthy",
        "service": SERVICE_NAME or "docs",
        "brand": brand,
        "session_id": session.session_id,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# STUB API ENDPOINTS (for OpenAPI documentation)
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/api/v1/accounts")
async def list_accounts():
    """List accounts - requires authentication."""
    return {"accounts": [], "message": "Authentication required"}


@app.get("/api/v1/transactions")
async def get_transactions():
    """Get transactions - requires authentication."""
    return {"transactions": [], "message": "Authentication required"}


@app.post("/api/v1/transfers")
async def create_transfer():
    """Create transfer - requires authentication."""
    return {"error": "Authentication required"}


@app.get("/api/v1/customers")
async def list_customers():
    """List customers - requires authentication."""
    return {"customers": [], "message": "Authentication required"}
