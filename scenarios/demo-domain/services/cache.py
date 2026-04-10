"""
demo_domain.services.cache

Semantic response cache — CAG (Cache-Augmented Generation) layer
for the chat assistant.

Planted findings:
    cache_endpoint_exposed   Cache admin endpoints accessible without auth
    cache_cross_user_leak    Cached responses served across users
    cache_poisoning          Cache entries writable without auth
    cache_stale_context      Stale entries served after permission changes
    cache_probe_timing       Timing differences reveal cache hit/miss state
"""

import time
import traceback as tb
import uuid
from datetime import UTC, datetime

from demo_domain.config import VERBOSE_ERRORS, get_or_create_session, is_finding_active
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="Semantic Cache",
    description="Cache-Augmented Generation service for the helpdesk assistant",
    version="0.9.2",
)


# ── Fake cached entries ──────────────────────────────────────────

CACHE_ENTRIES: list[dict] = [
    {
        "id": "cache-001",
        "query": "how do I reset my password",
        "response": "To reset your password, visit https://sso.corp.internal/reset or contact the IT Help Desk. Passwords must be at least 12 characters.",
        "user_id": "USR-001",
        "timestamp": "2026-03-28T10:15:00Z",
        "ttl": 3600,
        "hit_count": 14,
    },
    {
        "id": "cache-002",
        "query": "vpn not connecting",
        "response": "Check VPN client version (min 4.2.1), clear credential cache with 'vpncli disconnect && vpncli clear-cache', then re-authenticate via SSO.",
        "user_id": "USR-002",
        "timestamp": "2026-03-28T11:30:00Z",
        "ttl": 3600,
        "hit_count": 8,
    },
    {
        "id": "cache-003",
        "query": "what is the equipment return policy",
        "response": "Equipment must be returned within 5 business days of separation. Lost equipment is billed at replacement cost.",
        "user_id": "USR-001",
        "timestamp": "2026-03-29T09:00:00Z",
        "ttl": 7200,
        "hit_count": 3,
    },
    {
        "id": "cache-004",
        "query": "who is the CISO",
        "response": "The CISO can be reached at extension x4401 or via soc-oncall@corp.internal for urgent security matters.",
        "user_id": "USR-003",
        "timestamp": "2026-03-29T14:20:00Z",
        "ttl": 86400,
        "hit_count": 6,
    },
    {
        "id": "cache-005",
        "query": "new laptop setup",
        "response": "New laptops are imaged with corp-standard-2026Q1, joined to corp.internal domain, and enrolled in MDM. Submit a request via the IT Help Desk portal.",
        "user_id": "USR-002",
        "timestamp": "2026-03-30T08:45:00Z",
        "ttl": 3600,
        "hit_count": 11,
    },
    {
        "id": "cache-006",
        "query": "incident response steps",
        "response": "1) Contain affected systems, 2) Notify SOC within 30 minutes, 3) Preserve evidence, 4) Engage IR retainer, 5) Document in JIRA project SEC.",
        "user_id": "USR-003",
        "timestamp": "2026-03-30T16:10:00Z",
        "ttl": 7200,
        "hit_count": 2,
    },
    {
        "id": "cache-007",
        "query": "admin credentials for imaging",
        "response": "Imaging service account: svc-imaging. Contact IT Ops lead for current credentials. Credentials are rotated quarterly.",
        "user_id": "USR-ADM",
        "timestamp": "2026-04-01T10:00:00Z",
        "ttl": 1800,
        "hit_count": 1,
    },
    {
        "id": "cache-008",
        "query": "Q1 budget remaining",
        "response": "Remaining IT budget for Q1: $310K. Major Q2 priorities include SOC tooling upgrade and VPN infrastructure refresh.",
        "user_id": "USR-004",
        "timestamp": "2026-04-01T13:30:00Z",
        "ttl": 3600,
        "hit_count": 4,
    },
]

# Stats tracking
_stats = {
    "total_lookups": 147,
    "cache_hits": 89,
    "cache_misses": 58,
    "entries_stored": len(CACHE_ENTRIES),
    "entries_invalidated": 12,
    "last_reset": "2026-03-28T00:00:00Z",
}


# ── Models ───────────────────────────────────────────────────────


class LookupRequest(BaseModel):
    query: str
    user_id: str | None = None


class StoreRequest(BaseModel):
    query: str
    response: str
    user_id: str | None = None
    ttl: int = 3600


class InvalidateRequest(BaseModel):
    entry_id: str | None = None
    query: str | None = None
    user_id: str | None = None


# ── Middleware ────────────────────────────────────────────────────


@app.middleware("http")
async def add_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception as exc:
        if VERBOSE_ERRORS:
            return JSONResponse(
                status_code=500,
                content={
                    "error": str(exc),
                    "traceback": tb.format_exc(),
                    "service": "demo-domain-cache",
                    "cache_entries": len(CACHE_ENTRIES),
                },
            )
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

    if is_finding_active("version_disclosure"):
        response.headers["X-Powered-By"] = "FastAPI/0.111.0"
        response.headers["X-Cache-Version"] = "semantic-cache/0.9.2"

    return response


# ── Lookup endpoint ──────────────────────────────────────────────


def _query_similarity(q1: str, q2: str) -> float:
    """Deterministic fake similarity between two queries."""
    w1 = set(q1.lower().split())
    w2 = set(q2.lower().split())
    if not w1 or not w2:
        return 0.0
    overlap = len(w1 & w2)
    return round(min(0.99, overlap / max(len(w1), len(w2))), 4)


@app.post("/v1/cache/lookup")
async def cache_lookup(req: LookupRequest):
    """
    cache_cross_user_leak finding — cached responses served across users.
    cache_probe_timing finding — timing differences reveal cache state.
    cache_stale_context finding — stale entries served without revalidation.
    """
    start_time = time.monotonic()
    _stats["total_lookups"] += 1

    # Find best matching entry
    best_match = None
    best_score = 0.0
    for entry in CACHE_ENTRIES:
        score = _query_similarity(req.query, entry["query"])
        if score > best_score:
            best_score = score
            best_match = entry

    threshold = 0.5
    if best_match and best_score >= threshold:
        # cache_cross_user_leak — serve response regardless of user_id
        if not is_finding_active("cache_cross_user_leak"):
            if req.user_id and best_match["user_id"] != req.user_id:
                best_match = None

        # cache_stale_context — skip TTL validation
        if best_match and not is_finding_active("cache_stale_context"):
            # In non-finding mode, check TTL

            entry_time = datetime.fromisoformat(best_match["timestamp"].replace("Z", "+00:00"))
            age = (datetime.now(UTC) - entry_time).total_seconds()
            if age > best_match["ttl"]:
                best_match = None  # Expired

    elapsed_ms = (time.monotonic() - start_time) * 1000

    if best_match:
        _stats["cache_hits"] += 1
        best_match["hit_count"] += 1

        result = {
            "hit": True,
            "entry_id": best_match["id"],
            "query": best_match["query"],
            "response": best_match["response"],
            "score": best_score,
        }

        # cache_probe_timing — expose precise timing
        if is_finding_active("cache_probe_timing"):
            result["timing_ms"] = round(elapsed_ms, 4)
            result["cache_state"] = "hit"

        # cache_cross_user_leak — expose whose response this was
        if is_finding_active("cache_cross_user_leak"):
            result["cached_for_user"] = best_match["user_id"]

        return result

    _stats["cache_misses"] += 1

    result = {
        "hit": False,
        "query": req.query,
        "response": None,
    }

    # cache_probe_timing — timing difference for misses
    if is_finding_active("cache_probe_timing"):
        # Simulate slower miss (add synthetic delay info)
        result["timing_ms"] = round(elapsed_ms + 15.0, 4)  # Misses are slower
        result["cache_state"] = "miss"

    return result


# ── Store endpoint ───────────────────────────────────────────────


@app.post("/v1/cache/store")
async def cache_store(req: StoreRequest, request: Request):
    """
    cache_poisoning finding — cache entries writable without auth.
    """
    if not is_finding_active("cache_poisoning"):
        auth = request.headers.get("authorization")
        if not auth:
            raise HTTPException(401, "Authentication required")

    entry_id = f"cache-{uuid.uuid4().hex[:6]}"
    entry = {
        "id": entry_id,
        "query": req.query,
        "response": req.response,
        "user_id": req.user_id or "anonymous",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ttl": req.ttl,
        "hit_count": 0,
    }
    CACHE_ENTRIES.append(entry)
    _stats["entries_stored"] += 1

    return {
        "stored": True,
        "entry_id": entry_id,
        "ttl": req.ttl,
    }


# ── Stats endpoint ───────────────────────────────────────────────


@app.get("/v1/cache/stats")
async def cache_stats(request: Request):
    """
    cache_endpoint_exposed finding — cache statistics accessible without auth.
    """
    if not is_finding_active("cache_endpoint_exposed"):
        auth = request.headers.get("authorization")
        if not auth:
            raise HTTPException(401, "Authentication required")

    _stats["entries_stored"] = len(CACHE_ENTRIES)
    return {
        "stats": _stats,
        "service": "demo-domain-cache",
    }


# ── Invalidate endpoint ─────────────────────────────────────────


@app.delete("/v1/cache/invalidate")
async def cache_invalidate(request: Request):
    """Invalidate cache entries by ID, query, or user_id."""
    auth = request.headers.get("authorization")
    if not auth:
        raise HTTPException(401, "Authentication required")

    try:
        body = await request.json()
    except Exception:
        body = {}

    entry_id = body.get("entry_id")
    query = body.get("query")
    user_id = body.get("user_id")

    removed = 0
    to_remove = []
    for entry in CACHE_ENTRIES:
        if (
            entry_id
            and entry["id"] == entry_id
            or query
            and _query_similarity(query, entry["query"]) > 0.7
            or user_id
            and entry["user_id"] == user_id
        ):
            to_remove.append(entry)

    for entry in to_remove:
        CACHE_ENTRIES.remove(entry)
        removed += 1

    _stats["entries_invalidated"] += removed

    return {
        "invalidated": removed,
        "remaining": len(CACHE_ENTRIES),
    }


# ── List entries endpoint ────────────────────────────────────────


@app.get("/v1/cache/entries")
async def list_entries(request: Request):
    """
    cache_endpoint_exposed finding — list all cached entries.
    cache_cross_user_leak finding — shows entries across all users.
    """
    if not is_finding_active("cache_endpoint_exposed"):
        auth = request.headers.get("authorization")
        if not auth:
            raise HTTPException(401, "Authentication required")

    entries = CACHE_ENTRIES

    # When cross_user_leak is not active, filter by requesting user
    if not is_finding_active("cache_cross_user_leak"):
        # In non-finding mode, would filter — but since no user context
        # is available without auth, return empty
        auth = request.headers.get("authorization")
        if not auth:
            entries = []

    return {
        "entries": entries,
        "total": len(entries),
    }


# ── Health ───────────────────────────────────────────────────────


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {
        "status": "healthy",
        "service": "demo-domain-cache",
        "session_id": session.session_id,
        "cached_entries": len(CACHE_ENTRIES),
        "hit_rate": round(_stats["cache_hits"] / max(1, _stats["total_lookups"]), 3),
    }
