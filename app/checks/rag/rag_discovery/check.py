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

**Probe/grade.** The probe walks the vector-store signature
paths and the RAG paths (GET, then POST on a miss), recording every exchange;
`grade()` re-reads them, rebuilds both endpoint lists, and emits one verdict per
store and per RAG endpoint. `_reading()` is the one parser both halves call
(§0.12): each exchange is attributed to its path by the recorded request URL, and
GET-vs-POST for a RAG path is told apart by the recorded request method — never a
remembered list. This is the `agent_discovery` pattern applied to RAG.

**Fixed**: severity is categorical — a store or query
endpoint reachable without auth is `medium`, one behind auth `info` — so no
grader above the rule tier is called. The discriminator embeds the store type or
path (`store-chroma`, `rag-query`), so — like `ai_model_info_check` — the
contract declares **no `observations:` map**, `provisional_for()` falls to
`default: info`, and `grade()` places the real severity. Confidence is where the
split pays: a version *header* (`x-chroma-version`) is the store naming itself,
whereas a body substring like `collection` or `score` recurs across unrelated
JSON APIs, and a query endpoint recognised only by its path name is barely
narrowed at all.

References:
  https://arxiv.org/abs/2402.16893 (Indirect Prompt Injection)
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}
QUERY_BODY = {"query": "test", "question": "test"}

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

    conditions = [CheckCondition("services", "truthy"), CheckCondition("services_probed", "truthy")]
    produces = ["rag_endpoints", "vector_stores"]
    service_types = ["ai", "api", "http"]

    reason = "RAG pipelines can be exploited for indirect prompt injection, document exfiltration, and corpus poisoning attacks"
    references = [
        "https://arxiv.org/abs/2402.16893",
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["endpoint discovery", "vector store fingerprinting", "API enumeration"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        candidate = self.create_candidate(host=service.host, target=service, target_url=service.url)

        def record(resp, method: str) -> None:
            kwargs: dict[str, Any] = {"method": method}
            if method == "POST":
                kwargs["request_headers"] = JSON_HEADERS
                kwargs["request_json"] = QUERY_BODY
            candidate.attach(
                exchange_from_response(
                    resp, check_name=self.name, scan_id=scan_id, host=service.host, **kwargs
                )
            )

        try:
            async with AsyncHttpClient(cfg) as client:
                # Vector store detection: signature paths, break per store on a hit.
                for _store_name, sigs in VECTOR_STORE_SIGNATURES.items():
                    for path in sigs.get("paths", []):
                        resp = await client.get(service.with_path(path))
                        record(resp, "GET")
                        if resp.error or resp.status_code == 404:
                            continue
                        if self._store_matches(sigs, resp.headers, resp.body, resp.status_code):
                            break

                # RAG query endpoints: GET, then POST on a miss.
                for path in RAG_PATHS:
                    url = service.with_path(path)
                    get_resp = await client.get(url)
                    record(get_resp, "GET")
                    if (
                        self._analyze_rag_resp(
                            get_resp.error,
                            get_resp.status_code,
                            get_resp.headers,
                            get_resp.body,
                            path,
                        )
                        is None
                    ):
                        record(
                            await client.post(url, json=QUERY_BODY, headers=JSON_HEADERS), "POST"
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.candidates.append(candidate)
        reading = self._reading(candidate.exchanges, service)
        rag_endpoints = reading["stores"] + reading["endpoints"]
        if rag_endpoints:
            result.outputs["rag_endpoints"] = rag_endpoints
        if reading["store_types"]:
            result.outputs["vector_stores"] = reading["store_types"]

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        service = ctx.target
        if service is None:
            return []
        reading = self._reading(list(evidence), service)
        ids = evidence.ids()
        verdicts: list[Verdict] = []

        for store_info in reading["stores"]:
            store_type = store_info["store_type"]
            severity = "medium" if not store_info.get("auth_required") else "info"
            confidence, why = self._store_confidence(store_info)
            verdicts.append(
                Verdict(
                    severity=severity,
                    confidence=confidence,
                    discriminator=f"store-{store_type}",
                    title=f"Vector store detected: {store_type}",
                    description=self._build_store_description(store_info),
                    evidence=self._build_evidence(store_info),
                    reasoning=why,
                    signals={
                        "store_type": store_type,
                        "indicators": store_info.get("indicators"),
                        "auth_required": store_info.get("auth_required"),
                    },
                    references=self.references,
                    raw_data=store_info,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            )

        for endpoint_info in reading["endpoints"]:
            path = endpoint_info["path"]
            severity = self._determine_severity(endpoint_info)
            confidence, why = self._endpoint_confidence(endpoint_info)
            verdicts.append(
                Verdict(
                    severity=severity,
                    confidence=confidence,
                    discriminator=f"rag-{path.strip('/').replace('/', '-')}",
                    title=f"RAG endpoint: {path}",
                    description=self._build_endpoint_description(endpoint_info),
                    evidence=self._build_evidence(endpoint_info),
                    reasoning=why,
                    signals={
                        "indicators": endpoint_info.get("indicators"),
                        "auth_required": endpoint_info.get("auth_required"),
                    },
                    references=self.references,
                    raw_data=endpoint_info,
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            )

        return verdicts

    def _store_confidence(self, store_info: dict) -> tuple[float, str]:
        ind = store_info.get("indicators", {})
        if ind.get("headers_match"):
            return 0.9, (
                "a store-specific version header (x-chroma-version, pinecone-api-version, …) is the "
                "backend naming itself, not an inference"
            )
        if ind.get("body_match"):
            return 0.5, (
                "attribution rests on a body substring (collection, points, vectors); these recur "
                "across unrelated JSON APIs, so the store type is a best guess"
            )
        return 0.35, (
            "the signature path merely returned a non-404 status with no header or body match — a "
            "store-shaped endpoint is plausible, its identity unconfirmed"
        )

    def _endpoint_confidence(self, endpoint_info: dict) -> tuple[float, str]:
        indicators = endpoint_info.get("indicators", [])
        if any(i.startswith("field:") for i in indicators):
            return 0.75, (
                "the JSON response carried a RAG field (sources, documents, source_documents), which "
                "is a retrieval pipeline's own output shape — strong, though a field named `metadata` "
                "or `score` appears in plenty of non-RAG APIs too"
            )
        if any(i.startswith("header:") for i in indicators):
            return (
                0.7,
                "a retrieval/embedding response header was set, declaring the pipeline directly",
            )
        if any(i.startswith("pattern:") for i in indicators):
            return 0.4, (
                "only free-text substrings matched (sources, context, score, …) anywhere in the "
                "body; ordinary prose and unrelated JSON trip these, so retrieval is weakly inferred"
            )
        return 0.3, (
            "recognised only because a query-shaped path answered 200 with no RAG indicator at all — "
            "the weakest signal this check emits"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], service: Service) -> dict:
        """Rebuild the store list + RAG endpoint list off the recorded exchanges."""
        stores: list[dict] = []
        store_types: list[str] = []
        for store_name, sigs in VECTOR_STORE_SIGNATURES.items():
            for path in sigs.get("paths", []):
                ex = self._first(exchanges, "GET", path)
                if ex is None or ex.error or ex.response_status == 404:
                    continue
                if self._store_matches(
                    sigs, ex.response_headers or {}, ex.response_body or "", ex.response_status
                ):
                    stores.append(
                        {
                            "store_type": store_name,
                            "url": service.with_path(path),
                            "path": path,
                            "status_code": ex.response_status,
                            "auth_required": ex.response_status == 401,
                            "indicators": {
                                "headers_match": self._headers_match(
                                    sigs, ex.response_headers or {}
                                ),
                                "body_match": self._body_match(sigs, ex.response_body or ""),
                            },
                            "service": service.to_dict(),
                            "endpoint_type": "vector_store",
                        }
                    )
                    if store_name not in store_types:
                        store_types.append(store_name)
                    break

        endpoints: list[dict] = []
        for path in RAG_PATHS:
            get_ex = self._first(exchanges, "GET", path)
            info = None
            if get_ex is not None:
                info = self._analyze_rag_resp(
                    get_ex.error,
                    get_ex.response_status,
                    get_ex.response_headers or {},
                    get_ex.response_body or "",
                    path,
                )
            if info is None:
                post_ex = self._first(exchanges, "POST", path)
                if post_ex is not None:
                    info = self._analyze_rag_resp(
                        post_ex.error,
                        post_ex.response_status,
                        post_ex.response_headers or {},
                        post_ex.response_body or "",
                        path,
                        method="POST",
                    )
            if info:
                info["url"] = service.with_path(path)
                info["service"] = service.to_dict()
                endpoints.append(info)

        return {"stores": stores, "store_types": store_types, "endpoints": endpoints}

    @staticmethod
    def _first(exchanges: list[Exchange], method: str, path: str) -> Exchange | None:
        for exchange in exchanges:
            if exchange.request_method != method:
                continue
            if urlparse(exchange.request_url or "").path == path:
                return exchange
        return None

    @staticmethod
    def _headers_match(sigs: dict, headers: dict) -> bool:
        resp_headers_lower = {k.lower(): v for k, v in headers.items()}
        return any(h in resp_headers_lower for h in sigs.get("headers", []))

    @staticmethod
    def _body_match(sigs: dict, body: str) -> bool:
        body_lower = (body or "").lower()
        return any(p in body_lower for p in sigs.get("body_patterns", []))

    def _store_matches(self, sigs: dict, headers, body, status_code) -> bool:
        return (
            self._headers_match(sigs, headers or {})
            or self._body_match(sigs, body or "")
            or status_code == 200
        )

    def _analyze_rag_resp(
        self, error, status_code, headers, body, path: str, method: str = "GET"
    ) -> dict | None:
        """Analyze recorded response fields for RAG pipeline indicators."""
        if error or status_code in (404, 405, 502, 503):
            return None

        indicators = []
        body = body or ""
        body_lower = body.lower()

        for pattern in RAG_RESPONSE_PATTERNS:
            if pattern in body_lower:
                indicators.append(f"pattern:{pattern}")

        if status_code == 200:
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
                    if "results" in data or "matches" in data or "hits" in data:
                        indicators.append("field:search_results")
            except json.JSONDecodeError:
                pass

        resp_headers_lower = {k.lower(): v for k, v in (headers or {}).items()}
        if "x-embedding-model" in resp_headers_lower:
            indicators.append("header:embedding-model")
        if "x-retrieval-count" in resp_headers_lower:
            indicators.append("header:retrieval-count")

        if not indicators:
            query_keywords = ["query", "search", "retrieve", "ask", "rag"]
            if any(kw in path.lower() for kw in query_keywords) and status_code == 200:
                indicators.append("path:query-endpoint")
            else:
                return None

        return {
            "path": path,
            "method": method,
            "status_code": status_code,
            "indicators": indicators,
            "auth_required": status_code == 401,
            "endpoint_type": "rag_query",
        }

    def _determine_severity(self, endpoint_info: dict) -> str:
        """Determine observation severity."""
        if endpoint_info.get("auth_required"):
            return "info"
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
