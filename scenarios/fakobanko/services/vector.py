"""
Fakobanko Vector Database / RAG Service

Vector storage and retrieval service with RAG poisoning findings.
"""

import random

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from fakobanko.config import get_or_create_session, is_finding_active

app = FastAPI(
    title="Fakobanko Vector Service",
    description="Vector database and RAG retrieval",
    version="0.8.2",
)


# ─── Models ────────────────────────────────────────────────────


class Document(BaseModel):
    id: str
    content: str
    metadata: dict | None = {}
    namespace: str | None = "default"


class SearchRequest(BaseModel):
    query: str
    top_k: int | None = 5
    namespace: str | None = "default"


class UpsertRequest(BaseModel):
    documents: list[Document]
    namespace: str | None = "default"


# ─── Fake Vector Store ─────────────────────────────────────────

DOCUMENTS = {
    "default": [
        Document(
            id="doc-001",
            content="Fakobanko offers competitive mortgage rates starting at 6.5% APR.",
            metadata={"type": "product"},
        ),
        Document(
            id="doc-002",
            content="Our AI assistant FakoBot can help with account inquiries.",
            metadata={"type": "service"},
        ),
    ],
    "internal": [
        Document(
            id="int-001",
            content="Internal API endpoint: /api/v2/customers/{id}",
            metadata={"type": "api", "sensitive": True},
        ),
        Document(
            id="int-002",
            content="ML model uses vLLM on gpu cluster ml-gpu-01.",
            metadata={"type": "infrastructure", "sensitive": True},
        ),
    ],
}


# ─── Middleware ────────────────────────────────────────────────


@app.middleware("http")
async def add_headers(request: Request, call_next):
    response = await call_next(request)

    if is_finding_active("rag_endpoint_exposed"):
        response.headers["X-Vector-Service"] = "fakobanko-rag"

    return response


# ─── Endpoints ─────────────────────────────────────────────────


@app.get("/")
async def root():
    return {"service": "Fakobanko Vector Service", "version": "0.8.2"}


@app.get("/health")
async def health():
    session = get_or_create_session()
    return {"status": "healthy", "service": "fakobanko-vector", "session_id": session.session_id}


@app.get("/namespaces")
async def list_namespaces():
    """List available namespaces."""
    if is_finding_active("namespace_leak"):
        return {"namespaces": list(DOCUMENTS.keys())}
    return {"namespaces": ["default"]}


@app.post("/search")
async def search(request: SearchRequest):
    """Search for similar documents."""
    namespace = request.namespace

    if namespace == "internal" and not is_finding_active("namespace_leak"):
        raise HTTPException(403, "Access to internal namespace denied")

    docs = DOCUMENTS.get(namespace, [])
    results = [
        {"id": d.id, "content": d.content, "score": random.uniform(0.7, 1.0)}
        for d in docs[: request.top_k]
    ]

    return {"query": request.query, "results": results, "namespace": namespace}


@app.post("/documents")
async def upsert_documents(request: UpsertRequest):
    """Upsert documents - may be writable!"""
    if not is_finding_active("corpus_writable"):
        raise HTTPException(403, "Write access denied. Read-only mode.")

    namespace = request.namespace
    if namespace not in DOCUMENTS:
        DOCUMENTS[namespace] = []

    for doc in request.documents:
        DOCUMENTS[namespace].append(doc)

    return {"status": "success", "upserted": len(request.documents)}
