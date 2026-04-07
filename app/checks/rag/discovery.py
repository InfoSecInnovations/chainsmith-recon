"""
app/checks/rag/discovery.py - RAG Pipeline Discovery

Detect Retrieval-Augmented Generation (RAG) endpoints and identify
vector store backends.

Discovery methods:
- Common RAG endpoint paths (/query, /search, /retrieve, /ask)
- Vector store API signatures (Chroma, Pinecone, Weaviate, Qdrant, pgvector)
- Response patterns indicating retrieval (sources, citations, chunks)
- Embedding endpoint detection

Vector store signatures:
- Chroma: /api/v1/collections, chromadb patterns
- Pinecone: pinecone-api-version header
- Weaviate: /v1/objects, /v1/graphql
- Qdrant: /collections, qdrant patterns
- Milvus: /v1/vector, milvus patterns
- pgvector: PostgreSQL with vector extension indicators

References:
  https://arxiv.org/abs/2402.16893 (Indirect Prompt Injection)
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

# Vector store detection signatures
VECTOR_STORE_SIGNATURES = {
    "chroma": {
        "paths": ["/api/v1/collections", "/api/v1/heartbeat", "/.well-known/chroma"],
        "headers": ["x-chroma-version"],
        "body_patterns": ["chromadb", "chroma", "collection", "embeddings"],
    },
    "pinecone": {
        "paths": ["/describe_index_stats", "/query", "/vectors"],
        "headers": ["pinecone-api-version", "x-pinecone"],
        "body_patterns": ["pinecone", "namespace", "vectors", "matches"],
    },
    "weaviate": {
        "paths": ["/v1/objects", "/v1/graphql", "/v1/schema", "/v1/.well-known"],
        "headers": ["x-weaviate-version"],
        "body_patterns": ["weaviate", "objects", "graphql", "nearVector"],
    },
    "qdrant": {
        "paths": ["/collections", "/points", "/cluster"],
        "headers": ["x-qdrant-version"],
        "body_patterns": ["qdrant", "points", "vectors", "payload"],
    },
    "milvus": {
        "paths": ["/v1/vector", "/api/v1/collections", "/api/v1/entities"],
        "headers": [],
        "body_patterns": ["milvus", "collection", "entities", "vectors"],
    },
    "pgvector": {
        "paths": [],
        "headers": [],
        "body_patterns": ["pgvector", "pg_vector", "vector_store", "postgresql"],
    },
    "faiss": {
        "paths": [],
        "headers": [],
        "body_patterns": ["faiss", "IndexFlatL2", "index_factory"],
    },
}

# Common RAG endpoint paths
RAG_PATHS = [
    # Query/search endpoints
    "/query",
    "/search",
    "/retrieve",
    "/ask",
    "/chat",
    "/rag",
    "/rag/query",
    "/rag/search",
    "/v1/query",
    "/v1/search",
    "/api/query",
    "/api/search",
    "/api/rag",
    # Document/knowledge endpoints
    "/documents",
    "/knowledge",
    "/knowledge/search",
    "/kb/query",
    "/kb/search",
    # Embedding endpoints
    "/embed",
    "/embeddings",
    "/v1/embeddings",
    "/api/embed",
    # LangChain/LlamaIndex patterns
    "/invoke",
    "/retriever/invoke",
    "/chain/invoke",
]

# Response patterns indicating RAG
RAG_RESPONSE_PATTERNS = [
    "sources",
    "citations",
    "chunks",
    "documents",
    "retrieved",
    "context",
    "references",
    "passages",
    "snippets",
    "similarity",
    "score",
    "distance",
    "metadata",
    "source_documents",
]


class RAGDiscoveryCheck(ServiceIteratingCheck):
    """
    Discover RAG pipeline endpoints and identify vector store backends.

    Probes common RAG paths and fingerprints responses to identify
    the underlying vector store and retrieval infrastructure.
    """

    name = "rag_discovery"
    description = "Detect RAG pipeline endpoints and vector store backends"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["rag_endpoints", "vector_stores"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 90.0
    delay_between_targets = 0.2

    reason = "RAG pipelines can be exploited for indirect prompt injection, document exfiltration, and corpus poisoning attacks"
    references = [
        "https://arxiv.org/abs/2402.16893",
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["endpoint discovery", "vector store fingerprinting", "API enumeration"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        rag_endpoints = []
        detected_stores = set()

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        try:
            async with AsyncHttpClient(cfg) as client:
                # First, check for vector store APIs directly
                store_results = await self._detect_vector_stores(client, service)
                for store_info in store_results:
                    detected_stores.add(store_info["store_type"])
                    rag_endpoints.append(store_info)

                    result.observations.append(
                        build_observation(
                            check_name=self.name,
                            title=f"Vector store detected: {store_info['store_type']}",
                            description=self._build_store_description(store_info),
                            severity="medium" if not store_info.get("auth_required") else "info",
                            evidence=self._build_evidence(store_info),
                            host=service.host,
                            discriminator=f"store-{store_info['store_type']}",
                            target=service,
                            target_url=store_info.get("url"),
                            raw_data=store_info,
                            references=self.references,
                        )
                    )

                # Then check RAG query endpoints
                for path in RAG_PATHS:
                    url = service.with_path(path)

                    # Try GET for discovery
                    get_resp = await client.get(url)
                    endpoint_info = self._analyze_rag_response(get_resp, path, "GET", service)

                    if not endpoint_info:
                        # Try POST with query payload
                        post_resp = await client.post(
                            url,
                            json={"query": "test", "question": "test"},
                            headers={"Content-Type": "application/json"},
                        )
                        endpoint_info = self._analyze_rag_response(post_resp, path, "POST", service)

                    if endpoint_info:
                        rag_endpoints.append(endpoint_info)

                        severity = self._determine_severity(endpoint_info)

                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"RAG endpoint: {path}",
                                description=self._build_endpoint_description(endpoint_info),
                                severity=severity,
                                evidence=self._build_evidence(endpoint_info),
                                host=service.host,
                                discriminator=f"rag-{path.strip('/').replace('/', '-')}",
                                target=service,
                                target_url=url,
                                raw_data=endpoint_info,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if rag_endpoints:
            result.outputs["rag_endpoints"] = rag_endpoints
        if detected_stores:
            result.outputs["vector_stores"] = list(detected_stores)

        return result

    async def _detect_vector_stores(self, client: AsyncHttpClient, service: Service) -> list[dict]:
        """Detect vector store backends by probing their APIs."""
        detected = []

        for store_name, sigs in VECTOR_STORE_SIGNATURES.items():
            for path in sigs.get("paths", []):
                url = service.with_path(path)
                resp = await client.get(url)

                if resp.error or resp.status_code == 404:
                    continue

                # Check headers
                headers_match = False
                resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
                for header in sigs.get("headers", []):
                    if header in resp_headers_lower:
                        headers_match = True
                        break

                # Check body patterns
                body_match = False
                body_lower = (resp.body or "").lower()
                for pattern in sigs.get("body_patterns", []):
                    if pattern in body_lower:
                        body_match = True
                        break

                if headers_match or body_match or resp.status_code == 200:
                    detected.append(
                        {
                            "store_type": store_name,
                            "url": url,
                            "path": path,
                            "status_code": resp.status_code,
                            "auth_required": resp.status_code == 401,
                            "indicators": {
                                "headers_match": headers_match,
                                "body_match": body_match,
                            },
                            "service": service.to_dict(),
                            "endpoint_type": "vector_store",
                        }
                    )
                    break  # Found this store, move to next

        return detected

    def _analyze_rag_response(self, resp, path: str, method: str, service: Service) -> dict | None:
        """Analyze response for RAG pipeline indicators."""
        if resp.error or resp.status_code in (404, 405, 502, 503):
            return None

        indicators = []
        body = resp.body or ""
        body_lower = body.lower()

        # Check for RAG response patterns
        for pattern in RAG_RESPONSE_PATTERNS:
            if pattern in body_lower:
                indicators.append(f"pattern:{pattern}")

        # Check for JSON structure with RAG fields
        if resp.status_code == 200:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    rag_fields = [
                        "sources",
                        "documents",
                        "chunks",
                        "context",
                        "citations",
                        "references",
                        "source_documents",
                    ]
                    for field in rag_fields:
                        if field in data:
                            indicators.append(f"field:{field}")

                    # Check for nested results with scores
                    if "results" in data or "matches" in data or "hits" in data:
                        indicators.append("field:search_results")
            except json.JSONDecodeError:
                pass

        # Check headers for embedding/retrieval indicators
        resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        if "x-embedding-model" in resp_headers_lower:
            indicators.append("header:embedding-model")
        if "x-retrieval-count" in resp_headers_lower:
            indicators.append("header:retrieval-count")

        # Need indicators to consider this a RAG endpoint
        if not indicators:
            # Check if it's a query-like endpoint that returned successfully
            query_keywords = ["query", "search", "retrieve", "ask", "rag"]
            if any(kw in path.lower() for kw in query_keywords) and resp.status_code == 200:
                indicators.append("path:query-endpoint")
            else:
                return None

        return {
            "url": service.with_path(path),
            "path": path,
            "method": method,
            "status_code": resp.status_code,
            "indicators": indicators,
            "auth_required": resp.status_code == 401,
            "service": service.to_dict(),
            "endpoint_type": "rag_query",
        }

    def _determine_severity(self, endpoint_info: dict) -> str:
        """Determine observation severity."""
        if endpoint_info.get("auth_required"):
            return "info"

        # Query endpoints without auth are medium severity
        if endpoint_info.get("endpoint_type") == "rag_query":
            return "medium"

        return "low"

    def _build_store_description(self, store_info: dict) -> str:
        """Build description for vector store observation."""
        parts = [f"Vector store '{store_info['store_type']}' detected at {store_info['path']}."]

        if store_info.get("auth_required"):
            parts.append("Authentication required.")
        else:
            parts.append("No authentication required - potential data exposure.")

        return " ".join(parts)

    def _build_endpoint_description(self, endpoint_info: dict) -> str:
        """Build description for RAG endpoint observation."""
        parts = [f"RAG query endpoint discovered at {endpoint_info['path']}."]

        if endpoint_info.get("auth_required"):
            parts.append("Authentication required.")
        else:
            parts.append("No authentication required - potential for indirect injection attacks.")

        indicator_count = len(endpoint_info.get("indicators", []))
        if indicator_count > 0:
            parts.append(f"Detected {indicator_count} RAG indicators in response.")

        return " ".join(parts)

    def _build_evidence(self, info: dict) -> str:
        """Build evidence string."""
        lines = [
            f"Path: {info.get('path', 'unknown')}",
            f"Status: {info.get('status_code', 'unknown')}",
        ]

        if info.get("store_type"):
            lines.append(f"Vector store: {info['store_type']}")

        if info.get("indicators"):
            if isinstance(info["indicators"], dict):
                lines.append(f"Indicators: {info['indicators']}")
            else:
                lines.append(f"Indicators: {', '.join(info['indicators'][:5])}")

        return "\n".join(lines)
