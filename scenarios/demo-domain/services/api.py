"""
demo_domain.services.api

REST API backend for the helpdesk portal.

Planted findings:
    cors_wildcard            Access-Control-Allow-Origin: *
    unauthed_user_endpoint   GET /api/v1/users accessible without auth
    unauthed_docs            /docs and /openapi.json public (FastAPI default)
    api_key_in_error         Error responses include internal service URLs
    verbose_errors           Full tracebacks in 500 responses
    version_disclosure       Headers leak stack versions
"""

import random
import traceback as tb
from datetime import datetime

from demo_domain.config import VERBOSE_ERRORS, get_or_create_session, is_finding_active
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

app = FastAPI(
    title="HelpDesk API",
    description="Internal helpdesk REST API",
    version="1.3.0",
    # /docs intentionally left enabled — unauthed_docs finding
)


# ── CORS — wildcard ───────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # cors_wildcard finding
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth scheme ───────────────────────────────────────────────────

security = HTTPBearer(auto_error=False)

VALID_TOKENS = {
    "demo-token-alice": "USR-001",
    "demo-token-bob": "USR-002",
    "demo-token-admin": "USR-ADM",
}


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> str | None:
    if credentials and credentials.credentials in VALID_TOKENS:
        return VALID_TOKENS[credentials.credentials]
    return None


def require_auth(user: str | None = Depends(get_current_user)) -> str:
    if not user:
        raise HTTPException(401, "Authentication required")
    return user


# ── Fake data ─────────────────────────────────────────────────────

USERS = [
    {
        "id": "USR-001",
        "name": "Alice Morgan",
        "email": "alice@corp.internal",
        "department": "Engineering",
        "title": "SRE",
        "active": True,
    },
    {
        "id": "USR-002",
        "name": "Bob Nguyen",
        "email": "bob@corp.internal",
        "department": "IT Operations",
        "title": "Sysadmin",
        "active": True,
    },
    {
        "id": "USR-003",
        "name": "Carol Davis",
        "email": "carol@corp.internal",
        "department": "Security",
        "title": "SOC Analyst",
        "active": True,
    },
    {
        "id": "USR-004",
        "name": "Dan Reyes",
        "email": "dan@corp.internal",
        "department": "IT Operations",
        "title": "IT Manager",
        "active": True,
    },
    {
        "id": "USR-005",
        "name": "Eve Collins",
        "email": "eve@corp.internal",
        "department": "HR",
        "title": "HRBP",
        "active": True,
    },
]

TICKETS = [
    {
        "id": "TKT-1001",
        "status": "open",
        "subject": "VPN not connecting",
        "priority": "high",
        "owner": "USR-002",
        "created": "2026-03-01",
    },
    {
        "id": "TKT-1002",
        "status": "resolved",
        "subject": "Password reset",
        "priority": "low",
        "owner": "USR-001",
        "created": "2026-03-02",
    },
    {
        "id": "TKT-1003",
        "status": "in_progress",
        "subject": "Laptop won't boot",
        "priority": "high",
        "owner": "USR-002",
        "created": "2026-03-03",
    },
    {
        "id": "TKT-1004",
        "status": "open",
        "subject": "Email sync issue",
        "priority": "medium",
        "owner": "USR-001",
        "created": "2026-03-04",
    },
]


# ── Middleware ────────────────────────────────────────────────────


@app.middleware("http")
async def add_headers_and_catch(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception as exc:
        if VERBOSE_ERRORS:
            return JSONResponse(
                status_code=500,
                content={
                    "error": str(exc),
                    "traceback": tb.format_exc(),
                    "service": "demo-domain-api",
                    # api_key_in_error finding — internal URL in error
                    "internal_services": {
                        "chat": "http://demo-domain-chat:8201",
                        "agent": "http://demo-domain-agent:8203",
                    },
                },
            )
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

    if is_finding_active("version_disclosure"):
        response.headers["X-Powered-By"] = "FastAPI/0.111.0"
        response.headers["X-API-Version"] = "helpdesk-api/1.3.0"
        response.headers["Server"] = "uvicorn/0.29.0"

    return response


# ── Public endpoints ──────────────────────────────────────────────


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {"status": "healthy", "service": "demo-domain-api", "session_id": session.session_id}


@app.get("/api/v1/status")
async def status():
    """Public service status — no auth required."""
    return {
        "status": "operational",
        "version": "1.3.0",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ── Unauthenticated user endpoint — finding ───────────────────────


@app.get("/api/v1/users")
async def list_users(request: Request, user: str | None = Depends(get_current_user)):
    """
    unauthed_user_endpoint finding — accessible without authentication.
    Should require auth but the check is bypassed when finding is active.
    """
    if not is_finding_active("unauthed_user_endpoint") and not user:
        raise HTTPException(401, "Authentication required")

    return {
        "users": USERS,
        "total": len(USERS),
        # api_key_in_error finding — internal detail in normal response too
        "_source": "http://demo-domain-api:8202/api/v1/users"
        if is_finding_active("api_key_in_error")
        else None,
    }


@app.get("/api/v1/users/{user_id}")
async def get_user(user_id: str, user: str | None = Depends(get_current_user)):
    """Get a single user. Auth required — unless unauthed_user_endpoint active."""
    if not is_finding_active("unauthed_user_endpoint") and not user:
        raise HTTPException(401, "Authentication required")

    found = next((u for u in USERS if u["id"] == user_id), None)
    if not found:
        raise HTTPException(404, f"User {user_id} not found")
    return found


# ── Ticket endpoints — authenticated ─────────────────────────────


@app.get("/api/v1/tickets")
async def list_tickets(user: str = Depends(require_auth)):
    return {"tickets": TICKETS, "total": len(TICKETS)}


@app.get("/api/v1/tickets/{ticket_id}")
async def get_ticket(ticket_id: str, user: str = Depends(require_auth)):
    found = next((t for t in TICKETS if t["id"] == ticket_id.upper()), None)
    if not found:
        raise HTTPException(404, f"Ticket {ticket_id} not found")
    return found


class NewTicket(BaseModel):
    subject: str
    description: str
    priority: str = "medium"


@app.post("/api/v1/tickets")
async def create_ticket(body: NewTicket, user: str = Depends(require_auth)):
    ticket_id = f"TKT-{random.randint(2000, 9999)}"
    ticket = {
        "id": ticket_id,
        "status": "open",
        "subject": body.subject,
        "description": body.description,
        "priority": body.priority,
        "owner": user,
        "created": datetime.utcnow().strftime("%Y-%m-%d"),
    }
    TICKETS.append(ticket)
    return {"created": True, "ticket": ticket}


# ── Admin endpoint — should require auth, weak check ─────────────


@app.get("/api/v1/admin/config")
async def admin_config(request: Request, user: str | None = Depends(get_current_user)):
    """
    api_key_in_error finding — exposes internal config to authenticated users.
    Auth check present but easy to bypass with a valid demo token.
    """
    if not user:
        if VERBOSE_ERRORS:
            raise HTTPException(
                401,
                detail={
                    "error": "Authentication required",
                    "hint": "Use Authorization: Bearer <token>",
                    "valid_demo_tokens": list(VALID_TOKENS.keys()),  # token leak
                },
            )
        raise HTTPException(401, "Authentication required")

    return {
        "service": "demo-domain-api",
        "version": "1.3.0",
        "internal_endpoints": {
            "chat": "http://demo-domain-chat:8201",
            "agent": "http://demo-domain-agent:8203",
            "web": "http://demo-domain-web:8200",
        },
        "database": "sqlite:///data/helpdesk.db",
        "session_state": "/data/demo_session.json",
    }


# ── Embedding endpoint — embedding_endpoint_discovery surface ─────


@app.post("/api/v1/embeddings")
async def create_embedding(request: Request):
    """
    Simulated embedding endpoint. Returns fake vectors.
    Exposed without auth — embedding_endpoint_discovery finding surface.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON") from None

    text = body.get("input", "")
    if not text:
        raise HTTPException(422, "Missing 'input' field")

    # Return a deterministic fake 8-dim embedding
    import hashlib

    seed = int(hashlib.md5(str(text).encode()).hexdigest()[:8], 16)
    rng = random.Random(seed)
    vector = [round(rng.uniform(-1, 1), 6) for _ in range(8)]

    return {
        "object": "list",
        "data": [{"object": "embedding", "embedding": vector, "index": 0}],
        "model": "demo-embed-v1",
        "usage": {"prompt_tokens": len(str(text).split()), "total_tokens": len(str(text).split())},
    }
