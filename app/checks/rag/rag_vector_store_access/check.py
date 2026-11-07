"""
app/checks/rag/vector_store_access.py - Vector Store Direct Access

Probe detected vector store APIs to determine what operations are
permitted. Direct access bypasses all RAG-level access controls,
input validation, and output filtering.

Per-store tests:
  Chroma:   collection listing, document dump, count, query
  Qdrant:   collection listing, point scroll, info, search
  Weaviate: schema, object listing, GraphQL
  Pinecone: index stats, query, vector listing
  Milvus:   collection listing, entity query

**Probe/grade.** For each detected store the probe discovers
collection names, then probes the store's operations, recording every exchange
onto one candidate per store; `grade()` re-reads them, rebuilds the store result,
and emits one verdict. `_reading()` is the one parser both halves call (§0.12):
each operation's exchange is found by its recorded request URL (and body, for the
POST probes), and which store the evidence belongs to is recovered from those
same request paths — no probe-time flag survives to grade.

**Fixed**: the discriminator embeds the store type
(`store-access-chroma`), so — like `ai_model_info_check` — the contract declares
**no `observations:` map**, `provisional_for()` falls to `default: info`, and
`grade()` places the real severity. Confidence is where the split pays: a 200 to
a dump/scroll operation is direct, unauthenticated data access — near-certain —
whereas a 200 that returns an empty body or an error document is
`accessible`-shaped without actually exposing anything, and the doc-count is a
best effort over shapes that vary by store.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import contextlib
import json
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Per-store probes: (path, method, body_or_none, description)
STORE_PROBES = {
    "chroma": [
        ("/api/v1/collections", "GET", None, "list_collections"),
        ("/api/v1/collections/{id}/count", "GET", None, "document_count"),
        ("/api/v1/collections/{id}/get", "GET", None, "dump_documents"),
        (
            "/api/v1/collections/{id}/query",
            "POST",
            {"query_embeddings": [[0.0] * 3], "n_results": 2},
            "arbitrary_query",
        ),
    ],
    "qdrant": [
        ("/collections", "GET", None, "list_collections"),
        ("/collections/{name}", "GET", None, "collection_info"),
        ("/collections/{name}/points/scroll", "POST", {"limit": 5}, "enumerate_points"),
        (
            "/collections/{name}/points/search",
            "POST",
            {"vector": [0.0] * 3, "limit": 2},
            "arbitrary_search",
        ),
    ],
    "weaviate": [
        ("/v1/schema", "GET", None, "full_schema"),
        ("/v1/objects", "GET", None, "list_objects"),
        ("/v1/graphql", "POST", {"query": "{ Aggregate { __typename } }"}, "graphql_query"),
    ],
    "pinecone": [
        ("/describe_index_stats", "POST", {}, "index_stats"),
        ("/query", "POST", {"vector": [0.0] * 3, "topK": 2}, "arbitrary_query"),
        ("/vectors/list", "GET", None, "list_vectors"),
    ],
    "milvus": [
        ("/api/v1/collections", "GET", None, "list_collections"),
        (
            "/api/v1/entities/query",
            "POST",
            {"collection_name": "test", "expr": "id > 0", "limit": 5},
            "entity_query",
        ),
    ],
}

# Discovery request per store: (path, how-to-parse). Used both to send (probe)
# and to find + parse the recorded exchange (grade).
DISCOVERY = {
    "chroma": "/api/v1/collections",
    "qdrant": "/collections",
    "weaviate": "/v1/schema",
    "milvus": "/api/v1/collections",
}


class RAGVectorStoreAccessCheck(ServiceIteratingCheck):
    """
    Test if detected vector store APIs are directly accessible and
    what operations are permitted.
    """

    name = "rag_vector_store_access"
    description = "Probe vector store APIs for direct data access"

    conditions = [CheckCondition("vector_stores", "truthy")]
    produces = ["accessible_stores", "vector_store_collections"]
    service_types = ["ai", "api", "http"]

    reason = (
        "Direct vector store access bypasses all RAG-level access controls, "
        "input validation, and output filtering — raw document chunks with "
        "metadata are returned without LLM processing"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["vector store enumeration", "direct data access", "API probing"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        detected_stores = context.get("vector_stores", [])
        rag_endpoints = context.get("rag_endpoints", [])

        # Build store→base_url mapping from rag_endpoints
        store_urls: dict[str, str] = {}
        for ep in rag_endpoints:
            if (
                ep.get("endpoint_type") == "vector_store"
                and ep.get("service", {}).get("host") == service.host
            ):
                store_urls.setdefault(ep["store_type"], ep.get("url", service.url))

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        accessible = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for store_type in detected_stores:
                    probes = STORE_PROBES.get(store_type, [])
                    if not probes:
                        continue

                    base_url = store_urls.get(store_type, service.url)
                    if "://" in base_url:
                        base_url = "/".join(base_url.split("/")[:3])

                    candidate = self.create_candidate(
                        host=service.host, target=service, target_url=base_url
                    )

                    def record(resp, method: str, body: dict | None, _c=candidate) -> None:
                        kwargs: dict[str, Any] = {"method": method}
                        if method == "POST":
                            kwargs["request_headers"] = JSON_HEADERS
                            kwargs["request_json"] = body or {}
                        _c.attach(
                            exchange_from_response(
                                resp,
                                check_name=self.name,
                                scan_id=scan_id,
                                host=service.host,
                                **kwargs,
                            )
                        )

                    await self._run_discovery(client, record, store_type, base_url)
                    collections = self._discover_collections(
                        candidate.exchanges, store_type, base_url
                    )
                    await self._run_probes(client, record, base_url, probes, collections)

                    result.candidates.append(candidate)
                    store_result = self._reading(candidate.exchanges, store_type, base_url)
                    if store_result["accessible_ops"]:
                        accessible.append(store_result)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if accessible:
            result.outputs["accessible_stores"] = accessible
            all_collections = []
            for s in accessible:
                all_collections.extend(s.get("collections", []))
            if all_collections:
                result.outputs["vector_store_collections"] = all_collections

        return result

    async def _run_discovery(self, client, record, store_type: str, base_url: str) -> None:
        path = DISCOVERY.get(store_type)
        if path:
            with contextlib.suppress(Exception):
                record(await client.get(f"{base_url}{path}"), "GET", None)

    async def _run_probes(self, client, record, base_url, probes, collections) -> None:
        """Send each store probe, breaking on the first success per probe type —
        the same control flow as before, deciding on the exchange just recorded."""
        for path_tmpl, method, body, _op_name in probes:
            for path in self._resolve_paths(path_tmpl, collections):
                url = f"{base_url}{path}"
                try:
                    if method == "GET":
                        resp = await client.get(url)
                        record(resp, "GET", None)
                    else:
                        resp = await client.post(url, json=body or {}, headers=JSON_HEADERS)
                        record(resp, "POST", body or {})
                except Exception:
                    continue
                if resp.error or resp.status_code in (404, 405, 502, 503):
                    continue
                if resp.status_code in (200, 201) or resp.status_code == 401:
                    break  # One recorded outcome per probe type.

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchanges = list(evidence)
        base_url = ctx.target_url or ""
        store_type = self._infer_store_type(exchanges)
        if not store_type or not base_url:
            return []

        store_result = self._reading(exchanges, store_type, base_url)
        if not store_result["accessible_ops"]:
            return []

        severity = self._determine_severity(store_result)
        confidence, why = self._confidence(store_result)

        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=f"store-access-{store_type}",
                title=f"Vector store directly accessible: {store_type}",
                description=self._build_description(store_result),
                evidence=self._build_evidence(store_result),
                reasoning=why,
                signals={
                    "store_type": store_type,
                    "operations": [o["operation"] for o in store_result["accessible_ops"]],
                    "doc_count": store_result["doc_count"],
                },
                references=self.references,
                raw_data=store_result,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    def _confidence(self, store_result: dict) -> tuple[float, str]:
        ops = store_result["accessible_ops"]
        success_ops = [o for o in ops if o.get("status") in (200, 201)]
        auth_ops = [o for o in ops if o.get("auth_required")]
        if not success_ops and auth_ops:
            return 0.75, (
                "the store answered 401 — it is reachable and enforcing auth, which is the finding, "
                "but no data was exposed, so this is access-controlled rather than open"
            )
        dump_ops = {"dump_documents", "enumerate_points", "list_objects"} & {
            o["operation"] for o in success_ops
        }
        if dump_ops:
            return 0.85, (
                f"a bulk-read operation ({', '.join(sorted(dump_ops))}) returned 200 without auth — "
                "direct access to raw chunks. Held below certainty only because a 200 with an empty "
                "or error-shaped body would read the same, and the doc-count is inferred from "
                "store-specific fields that may be absent"
            )
        return 0.7, (
            "an operation returned 200 without auth, so the endpoint is reachable and answering; "
            "whether it exposed real content or an empty/permission-shaped 200 is not distinguished "
            "beyond the status code"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange], store_type: str, base_url: str) -> dict:
        """Rebuild one store's access result off the recorded exchanges."""
        collections = self._discover_collections(exchanges, store_type, base_url)
        probes = STORE_PROBES.get(store_type, [])
        accessible_ops: list[dict] = []
        doc_count = 0

        for path_tmpl, method, body, op_name in probes:
            for path in self._resolve_paths(path_tmpl, collections):
                url = f"{base_url}{path}"
                ex = self._find(exchanges, method, url, body)
                if ex is None:
                    continue
                if ex.error or ex.response_status in (404, 405, 502, 503):
                    continue
                if ex.response_status in (200, 201):
                    accessible_ops.append(
                        {
                            "operation": op_name,
                            "path": path,
                            "status": ex.response_status,
                            "preview": (ex.response_body or "")[:500],
                        }
                    )
                    doc_count += self._extract_count(ex.response_body, op_name)
                    break
                if ex.response_status == 401:
                    accessible_ops.append(
                        {
                            "operation": op_name,
                            "path": path,
                            "status": 401,
                            "auth_required": True,
                        }
                    )
                    break

        return {
            "store_type": store_type,
            "accessible_ops": accessible_ops,
            "collections": collections,
            "doc_count": doc_count,
        }

    def _discover_collections(
        self, exchanges: list[Exchange], store_type: str, base_url: str
    ) -> list[str]:
        """Collection/index names, off the recorded discovery response."""
        path = DISCOVERY.get(store_type)
        if not path:
            return []
        ex = self._find(exchanges, "GET", f"{base_url}{path}", None)
        if ex is None or ex.error or ex.response_status != 200:
            return []
        names: list[str] = []
        try:
            if store_type == "chroma":
                data = json.loads(ex.response_body or "[]")
                if isinstance(data, list):
                    names = [
                        c.get("name", c.get("id", "")) for c in data[:10] if isinstance(c, dict)
                    ]
            elif store_type == "qdrant":
                data = json.loads(ex.response_body or "{}")
                colls = data.get("result", {}).get("collections", [])
                names = [c.get("name", "") for c in colls[:10]]
            elif store_type == "weaviate":
                data = json.loads(ex.response_body or "{}")
                classes = data.get("classes", [])
                names = [c.get("class", "") for c in classes[:10]]
            elif store_type == "milvus":
                data = json.loads(ex.response_body or "{}")
                names = data.get("collection_names", [])[:10]
        except (json.JSONDecodeError, AttributeError, TypeError):
            return []
        return [n for n in names if n]

    def _resolve_paths(self, path_tmpl: str, collections: list[str]) -> list[str]:
        """Expand template paths with discovered collection names."""
        if "{id}" not in path_tmpl and "{name}" not in path_tmpl:
            return [path_tmpl]
        paths = []
        for coll in collections[:3]:
            paths.append(path_tmpl.replace("{id}", coll).replace("{name}", coll))
        if not paths:
            paths.append(path_tmpl.replace("{id}", "default").replace("{name}", "default"))
        return paths

    @staticmethod
    def _infer_store_type(exchanges: list[Exchange]) -> str:
        """Which store these exchanges probed, from their signature request paths.

        chroma and milvus share `/api/v1/collections`, so milvus is recognised
        first by its `/api/v1/entities/query`, and chroma by its
        `/api/v1/collections/{id}/...` operations.
        """
        paths = [urlparse(e.request_url or "").path for e in exchanges]
        joined = " ".join(paths)
        if "/api/v1/entities/query" in joined:
            return "milvus"
        if "/describe_index_stats" in joined or "/vectors/list" in joined:
            return "pinecone"
        if "/v1/schema" in joined or "/v1/graphql" in joined or "/v1/objects" in joined:
            return "weaviate"
        if "/api/v1/collections" in joined:
            return "chroma"
        if "/collections" in joined:
            return "qdrant"
        return ""

    @staticmethod
    def _find(
        exchanges: list[Exchange], method: str, url: str, body: dict | None
    ) -> Exchange | None:
        """The recorded exchange for method+path, matching the POST body too."""
        want_path = urlparse(url).path
        for exchange in exchanges:
            if exchange.request_method != method:
                continue
            if urlparse(exchange.request_url or "").path != want_path:
                continue
            if method == "POST":
                try:
                    got = json.loads(exchange.request_body or "{}")
                except (ValueError, TypeError):
                    got = None
                if got != (body or {}):
                    continue
            return exchange
        return None

    def _extract_count(self, body: str | None, op_name: str) -> int:
        """Try to extract document/vector count from response."""
        if not body:
            return 0
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for key in ("count", "total", "totalVectorCount", "vectors_count", "point_count"):
                    if key in data:
                        return int(data[key])
                result = data.get("result", {})
                if isinstance(result, dict):
                    for key in ("vectors_count", "points_count"):
                        if key in result:
                            return int(result[key])
            elif isinstance(data, list):
                return len(data)
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        return 0

    def _determine_severity(self, store_result: dict) -> str:
        ops = store_result["accessible_ops"]
        success_ops = [o for o in ops if o.get("status") == 200]
        auth_ops = [o for o in ops if o.get("auth_required")]

        if not success_ops:
            if auth_ops:
                return "low"
            return "info"

        op_names = {o["operation"] for o in success_ops}

        if (
            "dump_documents" in op_names
            or "enumerate_points" in op_names
            or "list_objects" in op_names
        ):
            return "critical"
        if (
            "arbitrary_query" in op_names
            or "arbitrary_search" in op_names
            or "graphql_query" in op_names
        ):
            return "high"
        if "list_collections" in op_names or "collection_info" in op_names:
            return "medium"
        return "low"

    def _build_description(self, store_result: dict) -> str:
        ops = store_result["accessible_ops"]
        success_ops = [o for o in ops if o.get("status") == 200]
        parts = [
            f"Vector store '{store_result['store_type']}' is directly accessible. "
            f"{len(success_ops)} operation(s) permitted without authentication."
        ]
        if store_result["collections"]:
            parts.append(f"Collections: {', '.join(store_result['collections'][:5])}.")
        if store_result["doc_count"]:
            parts.append(f"Approximately {store_result['doc_count']} documents.")
        return " ".join(parts)

    def _build_evidence(self, store_result: dict) -> str:
        lines = [f"Store: {store_result['store_type']}"]
        for op in store_result["accessible_ops"][:5]:
            status = "AUTH REQUIRED" if op.get("auth_required") else f"HTTP {op['status']}"
            lines.append(f"  {op['operation']}: {op['path']} -> {status}")
        if store_result["collections"]:
            lines.append(f"Collections: {', '.join(store_result['collections'][:5])}")
        if store_result["doc_count"]:
            lines.append(f"Document count: {store_result['doc_count']}")
        return "\n".join(lines)
