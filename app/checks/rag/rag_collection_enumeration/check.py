"""
app/checks/rag/collection_enumeration.py - Collection/Index Enumeration

Enumerate all collections/indexes, document counts, and metadata schemas
to map the full knowledge base structure. Flags collection names that
suggest sensitive content.

**Probe/grade.** The probe walks each accessible store's
collections, recording the per-store enumeration exchanges; `grade()` re-reads
them and emits one verdict per store. `_reading()` is the one parser both halves
call (§0.12): each collection's detail is rebuilt from the recorded response
matched by its request URL, and the store list itself is read from
`GradeContext.context` (`accessible_stores`) rather than a probe-time flag — the
same rule `agent_cross_injection` follows (§0.15), because the collection names
are upstream output, not something the responses carry back.

**Fixed**: the discriminator embeds the store type
(`enum-chroma`), so — like `ai_model_info_check` — the contract declares **no
`observations:` map**, `provisional_for()` falls to `default: info`, and
`grade()` places the real severity. Confidence is where the split pays: the
sensitivity flag is a substring match over collection *names* (`hr`, `internal`,
`private`), so a collection called `internally_sourced` or `hr` for
"high-relevance" trips it without being sensitive at all.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import contextlib
import json
import re
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Collection name patterns suggesting sensitive content
SENSITIVE_PATTERNS = [
    re.compile(r"(hr|human.?resource)", re.I),
    re.compile(r"payroll", re.I),
    re.compile(r"credential", re.I),
    re.compile(r"password", re.I),
    re.compile(r"secret", re.I),
    re.compile(r"internal", re.I),
    re.compile(r"(pii|personal)", re.I),
    re.compile(r"customer", re.I),
    re.compile(r"employee", re.I),
    re.compile(r"financial", re.I),
    re.compile(r"confidential", re.I),
    re.compile(r"private", re.I),
    re.compile(r"medical", re.I),
    re.compile(r"hipaa", re.I),
    re.compile(r"(ssn|social.?security)", re.I),
]


class RAGCollectionEnumerationCheck(ServiceIteratingCheck):
    """
    Enumerate vector store collections, document counts, and metadata
    schemas to map the knowledge base structure.
    """

    name = "rag_collection_enumeration"
    description = "Enumerate vector store collections and knowledge base structure"

    conditions = [CheckCondition("accessible_stores", "truthy")]
    produces = ["knowledge_base_structure"]
    service_types = ["ai", "api", "http"]

    reason = (
        "Collection enumeration reveals the structure and purpose of the "
        "knowledge base, identifying high-value targets for exfiltration"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["collection enumeration", "metadata analysis", "knowledge base mapping"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        accessible_stores = context.get("accessible_stores", [])

        # Filter to this service's stores
        service_stores = [
            s
            for s in accessible_stores
            if any(op.get("status") == 200 for op in s.get("accessible_ops", []))
        ]

        if not service_stores:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        kb_structure: list[dict] = []

        try:
            async with AsyncHttpClient(cfg) as client:
                for store_info in service_stores:
                    store_type = store_info["store_type"]
                    collections = store_info.get("collections", [])
                    if not collections:
                        continue

                    # One candidate per store: the discriminator is the store type
                    # and each store yields one verdict.
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=f"enum-{store_type}",
                        target=service,
                        target_url=service.url,
                    )

                    def record(resp, method: str, body: dict | None = None, _c=candidate) -> None:
                        kwargs: dict[str, Any] = {"method": method}
                        if body is not None:
                            kwargs["request_headers"] = JSON_HEADERS
                            kwargs["request_json"] = body
                        _c.attach(
                            exchange_from_response(
                                resp,
                                check_name=self.name,
                                scan_id=scan_id,
                                host=service.host,
                                **kwargs,
                            )
                        )

                    await self._enumerate_store(client, record, store_type, service, collections)
                    result.candidates.append(candidate)
                    kb_structure.append(
                        self._reading(candidate.exchanges, store_type, service, collections)
                    )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if kb_structure:
            result.outputs["knowledge_base_structure"] = kb_structure

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        service = ctx.target
        if service is None:
            return []

        # grade() is handed this candidate's evidence and the scan context, but
        # not the candidate's own discriminator. Every store shares one
        # service/host, so which store this evidence is for is recovered from the
        # recorded request URLs themselves (they carry each store's signature
        # paths), and the collection list is then read from the upstream
        # `accessible_stores` output (§0.15) — the responses never carry it.
        store_type = self._infer_store_type(list(evidence))
        accessible_stores = (ctx.context or {}).get("accessible_stores", [])
        store_info = next((s for s in accessible_stores if s.get("store_type") == store_type), None)
        if store_info is None:
            return []
        collections = store_info.get("collections", [])

        enum_result = self._reading(list(evidence), store_type, service, collections)
        sensitive = self._flag_sensitive(collections)
        severity = self._determine_severity(enum_result, sensitive)
        confidence, why = self._confidence(enum_result, sensitive)

        return [
            Verdict(
                severity=severity,
                confidence=confidence,
                discriminator=f"enum-{store_type}",
                title=f"Knowledge base structure exposed: {store_type}",
                description=self._build_description(enum_result, sensitive),
                evidence=self._build_evidence(enum_result, sensitive),
                reasoning=why,
                signals={
                    "store_type": store_type,
                    "collection_count": enum_result["collection_count"],
                    "total_documents": enum_result["total_documents"],
                    "sensitive_names": sensitive,
                },
                references=self.references,
                raw_data=enum_result,
                tier=ctx.tier,
                evidence_ids=evidence.ids(),
            )
        ]

    @staticmethod
    def _infer_store_type(exchanges: list[Exchange]) -> str:
        """Which store these exchanges probed, from their signature request paths.

        Each store type is enumerated through a distinct URL shape, so the
        recorded requests identify the store without a probe-time flag. Chroma is
        tested before qdrant because chroma's `/api/v1/collections/...` also
        contains the `/collections/` that marks qdrant.
        """
        for exchange in exchanges:
            path = urlparse(exchange.request_url or "").path
            if "/describe_index_stats" in path:
                return "pinecone"
            if "/api/v1/entities/query" in path:
                return "milvus"
            if "/v1/schema" in path:
                return "weaviate"
            if "/api/v1/collections/" in path:
                return "chroma"
            if "/collections/" in path:
                return "qdrant"
        return ""

    def _confidence(self, enum_result: dict, sensitive: list[str]) -> tuple[float, str]:
        if not sensitive:
            return 0.9, (
                "collection count and document totals are read straight from the store's own "
                "enumeration API, so the structure reported is fact, not inference"
            )
        return 0.5, (
            "the structure itself is read from the store's API and is solid; the *sensitivity* "
            "flag that raised the severity is a substring match over collection names "
            f"({', '.join(sensitive)}), which fires on names like `hr` or `internal` regardless "
            "of what the collection actually holds"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _reading(
        self,
        exchanges: list[Exchange],
        store_type: str,
        service: Service,
        collections: list[str],
    ) -> dict:
        """Rebuild one store's enumeration off the recorded exchanges."""
        base_url = self._base_url(service)
        collection_details: list[dict] = []

        for name in collections[:10]:
            detail = {"name": name, "doc_count": 0, "dimensions": None, "metadata_fields": []}
            with contextlib.suppress(Exception):
                if store_type == "chroma":
                    detail = self._read_chroma(exchanges, base_url, name, detail)
                elif store_type == "qdrant":
                    detail = self._read_qdrant(exchanges, base_url, name, detail)
                elif store_type == "weaviate":
                    detail = self._read_weaviate(exchanges, base_url, name, detail)
                elif store_type == "pinecone":
                    detail = self._read_pinecone(exchanges, base_url, name, detail)
                elif store_type == "milvus":
                    detail = self._read_milvus(exchanges, base_url, name, detail)
            collection_details.append(detail)

        total_docs = sum(c.get("doc_count", 0) for c in collection_details)
        return {
            "store_type": store_type,
            "collection_count": len(collection_details),
            "total_documents": total_docs,
            "collections": collection_details,
        }

    # ── Per-store enumeration: probe issues requests, reading parses them ──
    #
    # Each `_enum_*` awaits the client and records via `record`; each `_read_*`
    # finds the recorded exchange by URL/body and parses the same response.

    async def _enumerate_store(self, client, record, store_type, service, collections) -> None:
        base_url = self._base_url(service)
        for name in collections[:10]:
            with contextlib.suppress(Exception):
                if store_type == "chroma":
                    record(await client.get(f"{base_url}/api/v1/collections/{name}/count"), "GET")
                    record(
                        await client.get(f"{base_url}/api/v1/collections/{name}/get?limit=1"), "GET"
                    )
                elif store_type == "qdrant":
                    record(await client.get(f"{base_url}/collections/{name}"), "GET")
                elif store_type == "weaviate":
                    record(await client.get(f"{base_url}/v1/schema"), "GET")
                elif store_type == "pinecone":
                    record(
                        await client.post(
                            f"{base_url}/describe_index_stats", json={}, headers=JSON_HEADERS
                        ),
                        "POST",
                        {},
                    )
                elif store_type == "milvus":
                    body = {"collection_name": name, "expr": "id > 0", "limit": 1}
                    record(
                        await client.post(
                            f"{base_url}/api/v1/entities/query", json=body, headers=JSON_HEADERS
                        ),
                        "POST",
                        body,
                    )

    def _read_chroma(self, exchanges, base_url, name, detail):
        count_ex = self._find(exchanges, "GET", f"{base_url}/api/v1/collections/{name}/count")
        if count_ex and self._ok(count_ex):
            with contextlib.suppress(ValueError):
                detail["doc_count"] = int(count_ex.response_body or "0")
        get_ex = self._find(exchanges, "GET", f"{base_url}/api/v1/collections/{name}/get?limit=1")
        if get_ex and self._ok(get_ex):
            try:
                data = json.loads(get_ex.response_body or "{}")
                metadatas = data.get("metadatas", [])
                if metadatas and isinstance(metadatas[0], dict):
                    detail["metadata_fields"] = list(metadatas[0].keys())[:20]
            except (json.JSONDecodeError, IndexError):
                pass
        return detail

    def _read_qdrant(self, exchanges, base_url, name, detail):
        ex = self._find(exchanges, "GET", f"{base_url}/collections/{name}")
        if ex and self._ok(ex):
            try:
                data = json.loads(ex.response_body or "{}")
                r = data.get("result", {})
                detail["doc_count"] = r.get("vectors_count", r.get("points_count", 0))
                cfg = r.get("config", {}).get("params", {}).get("vectors", {})
                if isinstance(cfg, dict):
                    detail["dimensions"] = cfg.get("size")
            except (json.JSONDecodeError, KeyError):
                pass
        return detail

    def _read_weaviate(self, exchanges, base_url, name, detail):
        ex = self._find(exchanges, "GET", f"{base_url}/v1/schema")
        if ex and self._ok(ex):
            try:
                data = json.loads(ex.response_body or "{}")
                for cls in data.get("classes", []):
                    if cls.get("class") == name:
                        props = cls.get("properties", [])
                        detail["metadata_fields"] = [p.get("name", "") for p in props][:20]
                        break
            except json.JSONDecodeError:
                pass
        return detail

    def _read_pinecone(self, exchanges, base_url, name, detail):
        ex = self._find(exchanges, "POST", f"{base_url}/describe_index_stats")
        if ex and self._ok(ex):
            try:
                data = json.loads(ex.response_body or "{}")
                detail["doc_count"] = data.get("totalVectorCount", 0)
                detail["dimensions"] = data.get("dimension")
                namespaces = data.get("namespaces", {})
                detail["metadata_fields"] = list(namespaces.keys())[:20]
            except json.JSONDecodeError:
                pass
        return detail

    def _read_milvus(self, exchanges, base_url, name, detail):
        ex = self._find_milvus(exchanges, f"{base_url}/api/v1/entities/query", name)
        if ex and self._ok(ex):
            try:
                data = json.loads(ex.response_body or "{}")
                rows = data.get("data", [])
                if rows and isinstance(rows[0], dict):
                    detail["metadata_fields"] = list(rows[0].keys())[:20]
            except (json.JSONDecodeError, IndexError):
                pass
        return detail

    @staticmethod
    def _base_url(service: Service) -> str:
        base_url = service.url
        if "://" in base_url:
            base_url = "/".join(base_url.split("/")[:3])
        return base_url

    @staticmethod
    def _ok(exchange: Exchange) -> bool:
        return not exchange.error and exchange.response_status == 200

    @staticmethod
    def _find(exchanges: list[Exchange], method: str, url: str) -> Exchange | None:
        """The recorded exchange for an exact method+URL (ignoring host case)."""
        want = urlparse(url)
        for exchange in exchanges:
            if exchange.request_method != method:
                continue
            got = urlparse(exchange.request_url or "")
            if got.path == want.path and (got.query or "") == (want.query or ""):
                return exchange
        return None

    @staticmethod
    def _find_milvus(exchanges: list[Exchange], url: str, name: str) -> Exchange | None:
        """Milvus names the collection in the POST body, so match on that."""
        want = urlparse(url)
        for exchange in exchanges:
            if exchange.request_method != "POST":
                continue
            if urlparse(exchange.request_url or "").path != want.path:
                continue
            try:
                body = json.loads(exchange.request_body or "{}")
            except (ValueError, TypeError):
                continue
            if isinstance(body, dict) and body.get("collection_name") == name:
                return exchange
        return None

    def _flag_sensitive(self, collection_names: list[str]) -> list[str]:
        """Flag collection names matching sensitive patterns."""
        flagged = []
        for name in collection_names:
            for pattern in SENSITIVE_PATTERNS:
                if pattern.search(name):
                    flagged.append(name)
                    break
        return flagged

    def _determine_severity(self, enum_result: dict, sensitive_names: list[str]) -> str:
        if sensitive_names:
            return "medium" if enum_result["total_documents"] < 100 else "high"
        n = enum_result["collection_count"]
        if n == 0:
            return "info"
        return "high" if n > 3 else "medium" if n > 0 else "low"

    def _build_description(self, enum_result: dict, sensitive: list[str]) -> str:
        parts = [
            f"{enum_result['collection_count']} collection(s) enumerated in "
            f"{enum_result['store_type']} ({enum_result['total_documents']} total documents)."
        ]
        if sensitive:
            parts.append(f"Sensitive collection names: {', '.join(sensitive)}.")
        return " ".join(parts)

    def _build_evidence(self, enum_result: dict, sensitive: list[str]) -> str:
        lines = [f"Store: {enum_result['store_type']}"]
        for c in enum_result["collections"][:5]:
            dims = f", {c['dimensions']}d" if c.get("dimensions") else ""
            fields = f", fields: {c['metadata_fields'][:5]}" if c.get("metadata_fields") else ""
            lines.append(f"  {c['name']}: {c['doc_count']} docs{dims}{fields}")
        if sensitive:
            lines.append(f"Sensitive names: {', '.join(sensitive)}")
        return "\n".join(lines)
