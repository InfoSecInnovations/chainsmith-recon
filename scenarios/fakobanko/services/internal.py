"""
Fakobanko Internal Employee Portal

Internal-facing service with CORS and access control findings.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from fakobanko.config import get_or_create_session, is_finding_active

app = FastAPI(
    title="Fakobanko Internal Portal",
    description="Employee internal services",
    version="3.2.1",
)


# ─── CORS Configuration (potentially misconfigured) ────────────


# Note: CORS middleware must be added after app creation but needs finding check
# We'll handle this in the startup event
@app.on_event("startup")
async def configure_cors():
    if is_finding_active("cors_wildcard"):
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )


# ─── Models ────────────────────────────────────────────────────


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


# ─── Fake Data ─────────────────────────────────────────────────

ANNOUNCEMENTS = [
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
        content="We're excited to announce the launch of FakoBot, our new AI customer assistant.",
        author="Mike Johnson, CTO",
        created_at="2026-02-20T14:30:00Z",
        priority="high",
    ),
]

EMPLOYEES = [
    Employee(
        id="emp-001",
        name="Sarah Chen",
        email="schen@fakobanko.local",
        department="Executive",
        title="CEO",
    ),
    Employee(
        id="emp-002",
        name="Mike Johnson",
        email="mjohnson@fakobanko.local",
        department="Technology",
        title="CTO",
    ),
    Employee(
        id="emp-003",
        name="Lisa Park",
        email="lpark@fakobanko.local",
        department="Technology",
        title="VP Engineering",
    ),
    Employee(
        id="emp-004",
        name="James Wilson",
        email="jwilson@fakobanko.local",
        department="Security",
        title="CISO",
    ),
]


# ─── Middleware ────────────────────────────────────────────────


@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Internal-Service"] = "true"
    response.headers["X-Portal-Version"] = "3.2.1"

    if is_finding_active("internal_endpoints_exposed"):
        response.headers["X-Debug-Endpoints"] = "/api/employees,/api/announcements,/api/directory"

    return response


# ─── Auth Check ────────────────────────────────────────────────


def check_internal_auth(request: Request) -> bool:
    """Check if request is authorized for internal access."""
    if is_finding_active("no_auth_internal"):
        return True  # Auth bypass!

    auth_header = request.headers.get("Authorization")
    return bool(auth_header and auth_header.startswith("Bearer "))


# ─── Endpoints ─────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse)
async def root():
    return """
<!DOCTYPE html>
<html>
<head><title>Fakobanko Internal Portal</title></head>
<body style="font-family: Arial, sans-serif; margin: 40px;">
    <h1>🏦 Fakobanko Internal Portal</h1>
    <p>Welcome to the employee portal. Please authenticate to continue.</p>
</body>
</html>
"""


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {"status": "healthy", "service": "fakobanko-internal", "session_id": session.session_id}


@app.get("/api/announcements")
async def get_announcements(request: Request):
    """Get internal announcements."""
    if not check_internal_auth(request):
        raise HTTPException(403, "Access denied. Internal network required.")

    return {"announcements": [a.model_dump() for a in ANNOUNCEMENTS], "total": len(ANNOUNCEMENTS)}


@app.get("/api/directory")
async def get_directory(request: Request):
    """Employee directory."""
    if not check_internal_auth(request):
        raise HTTPException(403, "Access denied. Internal network required.")

    if is_finding_active("employee_directory_exposed"):
        return {"employees": [e.model_dump() for e in EMPLOYEES], "total": len(EMPLOYEES)}

    return {
        "employees": [{"name": e.name, "department": e.department} for e in EMPLOYEES],
        "total": len(EMPLOYEES),
    }
