"""
app/scenario_services/corporate/internal.py

Internal employee portal service template.

This service provides an internal-facing portal with employee directory,
announcements, and administrative features. It includes CORS misconfigurations
and access control bypass findings.

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    PORTAL_VERSION      Service version (default: 3.2.1)

Planted findings:
    cors_wildcard               Wildcard CORS with credentials
    no_auth_internal            Authentication bypass
    internal_endpoints_exposed  Endpoint list in headers
    employee_directory_exposed  Full employee details visible

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.corporate.internal:app
      --host 0.0.0.0 --port 8085
    environment:
      - BRAND_NAME=Fakobanko
"""

import os

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

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

PORTAL_VERSION = os.getenv("PORTAL_VERSION", "3.2.1")


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Internal Portal",
    description="Employee internal services",
    version=PORTAL_VERSION,
)


# ═══════════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class Announcement(BaseModel):
    id: str
    title: str
    content: str
    author: str
    created_at: str
    priority: str


class Employee(BaseModel):
    id: str
    name: str
    email: str
    department: str
    title: str


# ═══════════════════════════════════════════════════════════════════════════════
# FAKE DATA
# ═══════════════════════════════════════════════════════════════════════════════

def _get_announcements() -> list[Announcement]:
    """Generate announcements with brand-specific content."""
    brand = get_brand_name()
    return [
        Announcement(
            id="ann-001",
            title="Q4 All-Hands Meeting",
            content="Join us for the quarterly all-hands meeting next Friday at 2pm.",
            author="Sarah Chen, CEO",
            created_at="2026-02-15T10:00:00Z",
            priority="normal",
        ),
        Announcement(
            id="ann-002",
            title="New AI Assistant Launch",
            content=f"We're excited to announce the launch of our new AI customer assistant at {brand}.",
            author="Mike Johnson, CTO",
            created_at="2026-02-20T14:30:00Z",
            priority="high",
        ),
        Announcement(
            id="ann-003",
            title="Security Awareness Training",
            content="Mandatory security training due by end of month. Check your email for the link.",
            author="James Wilson, CISO",
            created_at="2026-02-22T09:00:00Z",
            priority="high",
        ),
    ]


def _get_employees() -> list[Employee]:
    """Generate employee list with brand-specific email domain."""
    domain = get_brand_domain()
    return [
        Employee(id="emp-001", name="Sarah Chen", email=f"schen@{domain}", department="Executive", title="CEO"),
        Employee(id="emp-002", name="Mike Johnson", email=f"mjohnson@{domain}", department="Technology", title="CTO"),
        Employee(id="emp-003", name="Lisa Park", email=f"lpark@{domain}", department="Technology", title="VP Engineering"),
        Employee(id="emp-004", name="James Wilson", email=f"jwilson@{domain}", department="Security", title="CISO"),
        Employee(id="emp-005", name="Maria Garcia", email=f"mgarcia@{domain}", department="HR", title="VP Human Resources"),
        Employee(id="emp-006", name="David Lee", email=f"dlee@{domain}", department="Finance", title="CFO"),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# CORS CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

@app.on_event("startup")
async def configure_cors():
    """
    Finding: cors_wildcard
    When active, adds dangerous CORS configuration with credentials.
    """
    if is_finding_active("cors_wildcard"):
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

@app.middleware("http")
async def add_headers(request: Request, call_next):
    """Add headers based on active findings."""
    response = await call_next(request)

    response.headers["X-Internal-Service"] = "true"
    response.headers["X-Portal-Version"] = PORTAL_VERSION

    # Finding: internal_endpoints_exposed - leak endpoint list
    if is_finding_active("internal_endpoints_exposed"):
        response.headers["X-Debug-Endpoints"] = "/api/employees,/api/announcements,/api/directory"

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH CHECK
# ═══════════════════════════════════════════════════════════════════════════════

def check_internal_auth(request: Request) -> bool:
    """
    Check if request is authorized for internal access.
    
    Finding: no_auth_internal
    When active, all requests are authorized (auth bypass).
    """
    if is_finding_active("no_auth_internal"):
        return True  # Auth bypass!

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return True

    return False


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def root():
    """Portal landing page."""
    brand = get_brand_name()
    return f"""<!DOCTYPE html>
<html>
<head><title>{brand} Internal Portal</title></head>
<body style="font-family: Arial, sans-serif; margin: 40px;">
    <h1>🏦 {brand} Internal Portal</h1>
    <p>Welcome to the employee portal. Please authenticate to continue.</p>
    <ul>
        <li><a href="/api/announcements">Announcements</a></li>
        <li><a href="/api/directory">Employee Directory</a></li>
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
        "service": f"{brand}-internal",
        "session_id": session.session_id,
    }


@app.get("/api/announcements")
async def get_announcements(request: Request):
    """
    Get internal announcements.
    
    Requires authentication unless no_auth_internal is active.
    """
    if not check_internal_auth(request):
        raise HTTPException(403, "Access denied. Internal network required.")

    announcements = _get_announcements()
    return {
        "announcements": [a.model_dump() for a in announcements],
        "total": len(announcements),
    }


@app.get("/api/directory")
async def get_directory(request: Request):
    """
    Employee directory.
    
    Finding: employee_directory_exposed
    When active, returns full employee details including email.
    Otherwise, returns limited info (name and department only).
    """
    if not check_internal_auth(request):
        raise HTTPException(403, "Access denied. Internal network required.")

    employees = _get_employees()

    if is_finding_active("employee_directory_exposed"):
        return {
            "employees": [e.model_dump() for e in employees],
            "total": len(employees),
        }

    # Limited info only
    return {
        "employees": [{"name": e.name, "department": e.department} for e in employees],
        "total": len(employees),
    }


@app.get("/api/employees")
async def get_employees(request: Request):
    """Alias for directory endpoint."""
    return await get_directory(request)


@app.get("/api/org-chart")
async def get_org_chart(request: Request):
    """
    Organization chart.
    
    Finding: employee_directory_exposed
    When active, includes reporting structure.
    """
    if not check_internal_auth(request):
        raise HTTPException(403, "Access denied. Internal network required.")

    if not is_finding_active("employee_directory_exposed"):
        raise HTTPException(404, "Not found")

    return {
        "org": {
            "ceo": {"name": "Sarah Chen", "reports": ["CTO", "CFO", "CISO", "VP HR"]},
            "departments": [
                {"name": "Technology", "head": "Mike Johnson", "headcount": 45},
                {"name": "Finance", "head": "David Lee", "headcount": 12},
                {"name": "Security", "head": "James Wilson", "headcount": 8},
                {"name": "HR", "head": "Maria Garcia", "headcount": 6},
            ],
        }
    }
