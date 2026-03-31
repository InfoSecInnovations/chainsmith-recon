"""
Fakobanko API Documentation Service

API documentation portal with OpenAPI exposure findings.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.openapi.utils import get_openapi

from fakobanko.config import is_finding_active, get_or_create_session


app = FastAPI(
    title="Fakobanko API Documentation",
    description="Developer documentation for Fakobanko APIs",
    version="2.0.0",
)


# ─── Custom OpenAPI Schema ─────────────────────────────────────

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="Fakobanko API",
        version="2.0.0",
        description="Fakobanko Banking API - Internal Documentation",
        routes=app.routes,
    )
    
    # Add extra info if finding active
    if is_finding_active("openapi_exposed"):
        openapi_schema["info"]["x-internal"] = True
        openapi_schema["servers"] = [
            {"url": "https://api.fakobanko.local", "description": "Production"},
            {"url": "https://api-staging.fakobanko.internal", "description": "Staging"},
            {"url": "http://localhost:8080", "description": "Development"},
        ]
    
    if is_finding_active("internal_endpoints_documented"):
        openapi_schema["paths"]["/internal/admin"] = {
            "get": {
                "summary": "Admin endpoint",
                "description": "Internal admin access - requires VPN",
                "responses": {"200": {"description": "Admin panel"}}
            }
        }
        openapi_schema["paths"]["/internal/metrics"] = {
            "get": {
                "summary": "Metrics endpoint",
                "description": "Prometheus metrics",
                "responses": {"200": {"description": "Metrics"}}
            }
        }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# ─── Middleware ────────────────────────────────────────────────

@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    
    response.headers["X-Docs-Version"] = "2.0.0"
    
    if is_finding_active("auth_schemes_revealed"):
        response.headers["X-Auth-Schemes"] = "Bearer, API-Key, Internal-Token"
    
    return response


# ─── Endpoints ─────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Fakobanko API Docs</title>
    <style>
        body { font-family: -apple-system, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; }
        h1 { color: #1a365d; }
        a { color: #2c5282; }
        .endpoint { background: #edf2f7; padding: 12px; margin: 8px 0; border-radius: 4px; }
        .method { font-weight: bold; color: #2b6cb0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🏦 Fakobanko API Documentation</h1>
        <p>Welcome to the Fakobanko API documentation portal.</p>
        
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
</html>
"""


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {
        "status": "healthy",
        "service": "fakobanko-docs",
        "session_id": session.session_id
    }


# Fake API endpoints for documentation
@app.get("/api/v1/accounts")
async def list_accounts():
    return {"accounts": [], "message": "Authentication required"}


@app.get("/api/v1/transactions")
async def get_transactions():
    return {"transactions": [], "message": "Authentication required"}


@app.post("/api/v1/transfers")
async def create_transfer():
    return {"error": "Authentication required"}


@app.get("/api/v1/customers")
async def list_customers():
    return {"customers": [], "message": "Authentication required"}
