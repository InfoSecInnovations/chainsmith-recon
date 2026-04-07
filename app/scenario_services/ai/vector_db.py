"""
app/scenario_services/ai/vector_db.py

Vector database / RAG retrieval service template.

This service simulates a vector database with document storage and
semantic search capabilities. It includes configurable security observations.

Configurable via environment variables:
    BRAND_NAME          Display name (default: from scenario.json)
    VECTOR_VERSION      Service version (default: 0.8.2)

Planted observations:
    rag_endpoint_exposed    X-Vector-Service header added
    namespace_leak          Internal namespaces visible in listing
    corpus_writable         Documents can be upserted (RAG poisoning)

Usage in docker-compose.yml:
    command: >
      uvicorn app.scenario_services.ai.vector_db:app
      --host 0.0.0.0 --port 8087
    environment:
      - BRAND_NAME=Fakobanko
"""

import os
import random

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from app.scenario_services.common.config import (
    get_brand_name,
    get_or_create_session,
    is_observation_active,
)

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

VECTOR_VERSION = os.getenv("VECTOR_VERSION", "0.8.2")


# ═══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="Vector Database",
    description="Vector database and RAG retrieval",
    version=VECTOR_VERSION,
)


# ═══════════════════════════════════════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════════════════════════════════════


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


# ═══════════════════════════════════════════════════════════════════════════════
# FAKE VECTOR STORE
# ═══════════════════════════════════════════════════════════════════════════════

# In-memory document store
DOCUMENTS: dict[str, list[Document]] = {
    "default": [
        Document(
            id="doc-001",
            content="We offer competitive mortgage rates starting at 6.5% APR.",
            metadata={"type": "product"},
        ),
        Document(
            id="doc-002",
            content="Our AI assistant can help with account inquiries.",
            metadata={"type": "service"},
        ),
        Document(
            id="doc-003",
            content="Branch locations available across the Southeast region.",
            metadata={"type": "location"},
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
        Document(
            id="int-003",
            content="Admin credentials stored in vault-prod:/secrets/admin",
            metadata={"type": "credentials", "sensitive": True},
        ),
    ],
}


# ═══════════════════════════════════════════════════════════════════════════════
# MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════


@app.middleware("http")
async def add_headers(request: Request, call_next):
    """Add headers based on active observations."""
    response = await call_next(request)

    # Observation: rag_endpoint_exposed - reveal service identity
    if is_observation_active("rag_endpoint_exposed"):
        brand = get_brand_name().lower().replace(" ", "-")
        response.headers["X-Vector-Service"] = f"{brand}-rag"

    return response


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════


@app.get("/")
async def root():
    """Service info endpoint."""
    brand = get_brand_name()
    return {
        "service": f"{brand} Vector Service",
        "version": VECTOR_VERSION,
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    session = get_or_create_session()
    brand = get_brand_name().lower().replace(" ", "-")

    return {
        "status": "healthy",
        "service": f"{brand}-vector",
        "session_id": session.session_id,
    }


@app.get("/namespaces")
async def list_namespaces():
    """
    List available namespaces.

    Observation: namespace_leak
    When active, internal namespaces are visible.
    """
    if is_observation_active("namespace_leak"):
        return {"namespaces": list(DOCUMENTS.keys())}
    return {"namespaces": ["default"]}


@app.post("/search")
async def search(request: SearchRequest):
    """
    Search for similar documents.

    Observation: namespace_leak
    When active, internal namespace is accessible.
    """
    namespace = request.namespace

    if namespace == "internal" and not is_observation_active("namespace_leak"):
        raise HTTPException(403, "Access to internal namespace denied")

    docs = DOCUMENTS.get(namespace, [])

    # Simulate semantic search with random scores
    results = [
        {
            "id": d.id,
            "content": d.content,
            "metadata": d.metadata,
            "score": round(random.uniform(0.7, 1.0), 4),
        }
        for d in docs[: request.top_k]
    ]

    return {
        "query": request.query,
        "results": results,
        "namespace": namespace,
        "total_results": len(results),
    }


@app.post("/documents")
async def upsert_documents(request: UpsertRequest):
    """
    Upsert documents to the vector store.

    Observation: corpus_writable
    When active, allows writing documents (enables RAG poisoning).
    """
    if not is_observation_active("corpus_writable"):
        raise HTTPException(403, "Write access denied. Read-only mode.")

    namespace = request.namespace
    if namespace not in DOCUMENTS:
        DOCUMENTS[namespace] = []

    for doc in request.documents:
        # Check if document already exists
        existing = next((d for d in DOCUMENTS[namespace] if d.id == doc.id), None)
        if existing:
            DOCUMENTS[namespace].remove(existing)
        DOCUMENTS[namespace].append(doc)

    return {
        "status": "success",
        "upserted": len(request.documents),
        "namespace": namespace,
    }


@app.delete("/documents/{document_id}")
async def delete_document(document_id: str, namespace: str = "default"):
    """
    Delete a document from the vector store.

    Observation: corpus_writable
    When active, allows deletion.
    """
    if not is_observation_active("corpus_writable"):
        raise HTTPException(403, "Write access denied. Read-only mode.")

    if namespace not in DOCUMENTS:
        raise HTTPException(404, f"Namespace not found: {namespace}")

    docs = DOCUMENTS[namespace]
    doc = next((d for d in docs if d.id == document_id), None)

    if not doc:
        raise HTTPException(404, f"Document not found: {document_id}")

    docs.remove(doc)

    return {"status": "deleted", "id": document_id, "namespace": namespace}


@app.get("/stats")
async def get_stats():
    """Get vector store statistics."""
    stats = {}

    for namespace, docs in DOCUMENTS.items():
        if namespace == "internal" and not is_observation_active("namespace_leak"):
            continue
        stats[namespace] = {
            "document_count": len(docs),
            "types": list({d.metadata.get("type", "unknown") for d in docs}),
        }

    return {"namespaces": stats, "version": VECTOR_VERSION}
