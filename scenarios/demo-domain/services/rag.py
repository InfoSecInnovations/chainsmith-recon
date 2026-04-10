"""
demo_domain.services.rag

Internal knowledge base — RAG service for HR policies, IT runbooks,
security guidelines, and internal memos.

Planted findings:
    rag_endpoint_exposed     RAG search endpoint accessible without auth
    rag_indirect_injection   Context manipulation via crafted queries
    rag_document_exfil       Document content extraction via direct retrieval
    rag_collection_enum      Collection listing exposed
    rag_source_attribution   Source citations spoofable
    rag_corpus_poisoning     Document ingestion endpoint writable
"""

import hashlib
import traceback as tb
from datetime import datetime

from demo_domain.config import VERBOSE_ERRORS, get_or_create_session, is_finding_active
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="Knowledge Base RAG",
    description="Internal knowledge base retrieval-augmented generation service",
    version="1.1.0",
)


# ── Fake knowledge base ─────────────────────────────────────────

DOCUMENTS = [
    {
        "id": "DOC-001",
        "title": "Password Policy",
        "collection": "hr-policies",
        "content": (
            "All employees must change passwords every 90 days. Minimum length: 12 characters. "
            "Must include uppercase, lowercase, digit, and special character. Reuse of the last "
            "10 passwords is prohibited. Contact IT Help Desk for password resets."
        ),
        "metadata": {
            "author": "eve.collins@corp.internal",
            "last_updated": "2026-02-15",
            "classification": "internal",
        },
    },
    {
        "id": "DOC-002",
        "title": "Remote Work Equipment Policy",
        "collection": "hr-policies",
        "content": (
            "Employees approved for remote work receive a standard equipment package: laptop, "
            "monitor, keyboard, and headset. Equipment must be returned within 5 business days "
            "of separation. Lost equipment is billed at replacement cost. Submit requests via "
            "the IT Help Desk portal."
        ),
        "metadata": {
            "author": "eve.collins@corp.internal",
            "last_updated": "2026-01-20",
            "classification": "internal",
        },
    },
    {
        "id": "DOC-003",
        "title": "VPN Troubleshooting Runbook",
        "collection": "it-runbooks",
        "content": (
            "Step 1: Verify VPN client version (minimum 4.2.1). Step 2: Check connectivity to "
            "vpn-gateway.corp.internal:443. Step 3: Clear credential cache: 'vpncli disconnect && "
            "vpncli clear-cache'. Step 4: Re-authenticate using SSO. Step 5: If persistent, check "
            "firewall rules on 10.0.4.0/24 subnet. Escalate to Network Ops if unresolved."
        ),
        "metadata": {
            "author": "bob.nguyen@corp.internal",
            "last_updated": "2026-03-01",
            "classification": "internal",
            "internal_notes": "Gateway IP: 10.0.4.1, backup: 10.0.4.2",
        },
    },
    {
        "id": "DOC-004",
        "title": "Laptop Provisioning Runbook",
        "collection": "it-runbooks",
        "content": (
            "New hire laptop setup: 1) Image with corp-standard-2026Q1. 2) Join to domain "
            "corp.internal. 3) Install agent suite: EDR, DLP, VPN client. 4) Enroll in MDM. "
            "5) Configure BitLocker with recovery key escrowed to AD. Admin credentials for "
            "imaging: svc-imaging / Img2026$ecure (rotate quarterly)."
        ),
        "metadata": {
            "author": "bob.nguyen@corp.internal",
            "last_updated": "2026-02-28",
            "classification": "confidential",
        },
    },
    {
        "id": "DOC-005",
        "title": "Incident Response Playbook",
        "collection": "security-guidelines",
        "content": (
            "On detection of a security incident: 1) Contain — isolate affected systems. "
            "2) Notify SOC at soc-oncall@corp.internal and CISO within 30 minutes. 3) Preserve "
            "evidence — do not reboot or wipe. 4) Engage IR retainer (Mandiant, contract #IR-2026-042). "
            "5) Document timeline in JIRA project SEC. Escalation: CISO direct line x4401."
        ),
        "metadata": {
            "author": "carol.davis@corp.internal",
            "last_updated": "2026-03-05",
            "classification": "confidential",
        },
    },
    {
        "id": "DOC-006",
        "title": "Acceptable Use Policy",
        "collection": "security-guidelines",
        "content": (
            "Corporate systems are for business use. Personal use is permitted if it does not "
            "interfere with productivity or violate policy. Prohibited: crypto mining, torrenting, "
            "unauthorized cloud storage, bypassing DLP controls. Violations may result in "
            "disciplinary action up to termination."
        ),
        "metadata": {
            "author": "carol.davis@corp.internal",
            "last_updated": "2026-01-10",
            "classification": "internal",
        },
    },
    {
        "id": "DOC-007",
        "title": "Q1 2026 IT Budget Review",
        "collection": "internal-memos",
        "content": (
            "IT budget utilization at 73% through Q1. Major expenditures: cloud infrastructure "
            "migration ($420K), EDR platform renewal ($185K), new hire equipment ($92K). "
            "Remaining budget: $310K. Proposed Q2 priorities: SOC tooling upgrade, VPN "
            "infrastructure refresh, and AI assistant pilot expansion."
        ),
        "metadata": {
            "author": "dan.reyes@corp.internal",
            "last_updated": "2026-03-28",
            "classification": "confidential",
        },
    },
    {
        "id": "DOC-008",
        "title": "AI Assistant Deployment Memo",
        "collection": "internal-memos",
        "content": (
            "The IT Help Desk AI assistant (codename: HelpBot) is deployed across 4 services: "
            "web (port 8200), chat (port 8201), api (port 8202), agent (port 8203). Backend LLM "
            "is routed via demo-domain-llm-router. RAG knowledge base on port 8204. Cache layer "
            "on port 8205. Documentation portal on port 8206. All services share a session state "
            "file at /data/demo_session.json."
        ),
        "metadata": {
            "author": "dan.reyes@corp.internal",
            "last_updated": "2026-04-01",
            "classification": "restricted",
        },
    },
]

COLLECTIONS = {
    "hr-policies": {
        "name": "HR Policies",
        "description": "Human resources policies and procedures",
        "doc_count": 2,
        "owner": "eve.collins@corp.internal",
    },
    "it-runbooks": {
        "name": "IT Runbooks",
        "description": "Operational runbooks for IT support teams",
        "doc_count": 2,
        "owner": "bob.nguyen@corp.internal",
    },
    "security-guidelines": {
        "name": "Security Guidelines",
        "description": "Information security policies and incident response",
        "doc_count": 2,
        "owner": "carol.davis@corp.internal",
    },
    "internal-memos": {
        "name": "Internal Memos",
        "description": "Internal communications and planning documents",
        "doc_count": 2,
        "owner": "dan.reyes@corp.internal",
    },
}


# ── Models ───────────────────────────────────────────────────────


class SearchRequest(BaseModel):
    query: str
    collection: str | None = None
    top_k: int = 3


class IngestRequest(BaseModel):
    title: str
    content: str
    collection: str
    metadata: dict | None = {}


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
                    "service": "demo-domain-rag",
                    "collections": list(COLLECTIONS.keys()),
                },
            )
        return JSONResponse(status_code=500, content={"error": "Internal server error"})

    if is_finding_active("version_disclosure"):
        response.headers["X-Powered-By"] = "FastAPI/0.111.0"
        response.headers["X-RAG-Version"] = "knowledge-base/1.1.0"
        response.headers["X-Embedding-Model"] = "demo-embed-v1"

    return response


# ── Search endpoint ──────────────────────────────────────────────


def _fake_similarity(query: str, text: str) -> float:
    """Deterministic fake similarity score based on word overlap."""
    q_words = set(query.lower().split())
    t_words = set(text.lower().split())
    if not q_words:
        return 0.0
    overlap = len(q_words & t_words)
    return round(min(0.99, 0.3 + (overlap / len(q_words)) * 0.6), 4)


@app.post("/v1/search")
async def search(req: SearchRequest, request: Request):
    """
    rag_endpoint_exposed finding — search endpoint accessible without auth.
    rag_indirect_injection finding — crafted queries can manipulate context.
    rag_source_attribution finding — source citations can be spoofed.
    """
    if not is_finding_active("rag_endpoint_exposed"):
        auth = request.headers.get("authorization")
        if not auth:
            raise HTTPException(401, "Authentication required")

    docs = DOCUMENTS
    if req.collection:
        docs = [d for d in docs if d["collection"] == req.collection]

    # Score and rank
    scored = []
    for doc in docs:
        score = _fake_similarity(req.query, doc["content"] + " " + doc["title"])
        scored.append((score, doc))
    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[: req.top_k]

    results = []
    for score, doc in top:
        result = {
            "doc_id": doc["id"],
            "title": doc["title"],
            "collection": doc["collection"],
            "score": score,
            "snippet": doc["content"][:200] + "..."
            if len(doc["content"]) > 200
            else doc["content"],
        }

        # rag_source_attribution finding — include raw source that can be spoofed
        if is_finding_active("rag_source_attribution"):
            result["source"] = {
                "author": doc["metadata"].get("author"),
                "uri": f"rag://docs/{doc['id']}",
                "verified": False,  # Spoofable — no signature verification
            }

        # rag_indirect_injection finding — echo back query context
        if is_finding_active("rag_indirect_injection"):
            result["context_window"] = {
                "query": req.query,
                "augmented_prompt": f"Answer using this context:\n\n{doc['content']}\n\nUser query: {req.query}",
            }

        results.append(result)

    return {
        "results": results,
        "total_searched": len(docs),
        "query": req.query,
    }


# ── Collections endpoint ─────────────────────────────────────────


@app.get("/v1/collections")
async def list_collections(request: Request):
    """
    rag_collection_enum finding — collection listing exposed without auth.
    """
    if not is_finding_active("rag_collection_enum"):
        auth = request.headers.get("authorization")
        if not auth:
            raise HTTPException(401, "Authentication required")

    return {
        "collections": COLLECTIONS,
        "total": len(COLLECTIONS),
    }


# ── Ingest endpoint ─────────────────────────────────────────────


@app.post("/v1/ingest")
async def ingest(req: IngestRequest, request: Request):
    """
    rag_corpus_poisoning finding — document ingestion endpoint writable
    without auth. Allows injecting arbitrary content into the knowledge base.
    """
    if not is_finding_active("rag_corpus_poisoning"):
        auth = request.headers.get("authorization")
        if not auth:
            raise HTTPException(401, "Authentication required")
        raise HTTPException(403, "Write access requires admin role")

    doc_id = f"DOC-{hashlib.md5(req.title.encode()).hexdigest()[:6].upper()}"
    new_doc = {
        "id": doc_id,
        "title": req.title,
        "collection": req.collection,
        "content": req.content,
        "metadata": {
            **(req.metadata or {}),
            "ingested_at": datetime.utcnow().isoformat() + "Z",
            "source": "api-ingest",
        },
    }
    DOCUMENTS.append(new_doc)

    if req.collection in COLLECTIONS:
        COLLECTIONS[req.collection]["doc_count"] += 1

    return {
        "ingested": True,
        "doc_id": doc_id,
        "collection": req.collection,
        "title": req.title,
    }


# ── Document retrieval ───────────────────────────────────────────


@app.get("/v1/documents/{doc_id}")
async def get_document(doc_id: str, request: Request):
    """
    rag_document_exfil finding — full document content extraction.
    """
    doc = next((d for d in DOCUMENTS if d["id"] == doc_id.upper()), None)
    if not doc:
        raise HTTPException(404, f"Document {doc_id} not found")

    if not is_finding_active("rag_document_exfil"):
        auth = request.headers.get("authorization")
        if not auth:
            raise HTTPException(401, "Authentication required")
        # When finding is not active, return only snippet
        return {
            "id": doc["id"],
            "title": doc["title"],
            "collection": doc["collection"],
            "snippet": doc["content"][:100] + "...",
        }

    # Finding active — return full document including metadata
    return {
        "id": doc["id"],
        "title": doc["title"],
        "collection": doc["collection"],
        "content": doc["content"],
        "metadata": doc["metadata"],
    }


# ── Health ───────────────────────────────────────────────────────


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {
        "status": "healthy",
        "service": "demo-domain-rag",
        "session_id": session.session_id,
        "document_count": len(DOCUMENTS),
        "collections": len(COLLECTIONS),
    }
