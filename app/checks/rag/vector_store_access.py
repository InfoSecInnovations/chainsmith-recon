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

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import json
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

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

    timeout_seconds = 90.0
    delay_between_targets = 0.3

    reason = (
        "Direct vector store access bypasses all RAG-level access controls, "
        "input validation, and output filtering — raw document chunks with "
        "metadata are returned without LLM processing"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["vector store enumeration", "direct data access", "API probing"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
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
                    # Strip any trailing path from the base
                    if "://" in base_url:
                        parts = base_url.split("/")
                        base_url = "/".join(parts[:3])

                    # First, discover collection names for template paths
                    collections = await self._discover_collections(client, store_type, base_url)

                    store_result = await self._probe_store(
                        client, store_type, base_url, probes, collections
                    )

                    if store_result["accessible_ops"]:
                        accessible.append(store_result)
                        severity = self._determine_severity(store_result)

                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Vector store directly accessible: {store_type}",
                                description=self._build_description(store_result),
                                severity=severity,
                                evidence=self._build_evidence(store_result),
                                host=service.host,
                                discriminator=f"store-access-{store_type}",
                                target=service,
                                target_url=base_url,
                                raw_data=store_result,
                                references=self.references,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if accessible:
            result.outputs["accessible_stores"] = accessible
            # Aggregate collections
            all_collections = []
            for s in accessible:
                all_collections.extend(s.get("collections", []))
            if all_collections:
                result.outputs["vector_store_collections"] = all_collections

        return result

    async def _discover_collections(
        self,
        client: AsyncHttpClient,
        store_type: str,
        base_url: str,
    ) -> list[str]:
        """Try to list collection/index names for template substitution."""
        names: list[str] = []
        try:
            if store_type == "chroma":
                resp = await client.get(f"{base_url}/api/v1/collections")
                if not resp.error and resp.status_code == 200:
                    data = json.loads(resp.body or "[]")
                    if isinstance(data, list):
                        names = [
                            c.get("name", c.get("id", "")) for c in data[:10] if isinstance(c, dict)
                        ]
            elif store_type == "qdrant":
                resp = await client.get(f"{base_url}/collections")
                if not resp.error and resp.status_code == 200:
                    data = json.loads(resp.body or "{}")
                    colls = data.get("result", {}).get("collections", [])
                    names = [c.get("name", "") for c in colls[:10]]
            elif store_type == "weaviate":
                resp = await client.get(f"{base_url}/v1/schema")
                if not resp.error and resp.status_code == 200:
                    data = json.loads(resp.body or "{}")
                    classes = data.get("classes", [])
                    names = [c.get("class", "") for c in classes[:10]]
            elif store_type == "milvus":
                resp = await client.get(f"{base_url}/api/v1/collections")
                if not resp.error and resp.status_code == 200:
                    data = json.loads(resp.body or "{}")
                    names = data.get("collection_names", [])[:10]
        except Exception:
            pass
        return [n for n in names if n]

    async def _probe_store(
        self,
        client: AsyncHttpClient,
        store_type: str,
        base_url: str,
        probes: list[tuple],
        collections: list[str],
    ) -> dict:
        """Probe a store with its specific endpoints."""
        accessible_ops: list[dict] = []
        doc_count = 0

        for path_tmpl, method, body, op_name in probes:
            # Resolve template placeholders
            paths_to_try = self._resolve_paths(path_tmpl, collections, store_type)

            for path in paths_to_try:
                url = f"{base_url}{path}"
                try:
                    if method == "GET":
                        resp = await client.get(url)
                    else:
                        resp = await client.post(
                            url,
                            json=body or {},
                            headers={"Content-Type": "application/json"},
                        )

                    if resp.error or resp.status_code in (404, 405, 502, 503):
                        continue

                    if resp.status_code in (200, 201):
                        preview = (resp.body or "")[:500]
                        accessible_ops.append(
                            {
                                "operation": op_name,
                                "path": path,
                                "status": resp.status_code,
                                "preview": preview,
                            }
                        )
                        # Try to count documents
                        doc_count += self._extract_count(resp.body, op_name)
                        break  # One success per probe type
                    elif resp.status_code == 401:
                        accessible_ops.append(
                            {
                                "operation": op_name,
                                "path": path,
                                "status": 401,
                                "auth_required": True,
                            }
                        )
                        break
                except Exception:
                    continue

        return {
            "store_type": store_type,
            "accessible_ops": accessible_ops,
            "collections": collections,
            "doc_count": doc_count,
        }

    def _resolve_paths(
        self,
        path_tmpl: str,
        collections: list[str],
        store_type: str,
    ) -> list[str]:
        """Expand template paths with discovered collection names."""
        if "{id}" not in path_tmpl and "{name}" not in path_tmpl:
            return [path_tmpl]

        paths = []
        for coll in collections[:3]:
            paths.append(path_tmpl.replace("{id}", coll).replace("{name}", coll))
        # Fallback: try "default" or index 0
        if not paths:
            paths.append(path_tmpl.replace("{id}", "default").replace("{name}", "default"))
        return paths

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
                # Nested result
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

        # Full dump = critical
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
