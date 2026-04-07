"""
app/checks/rag/collection_enumeration.py - Collection/Index Enumeration

Enumerate all collections/indexes, document counts, and metadata schemas
to map the full knowledge base structure. Flags collection names that
suggest sensitive content.

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import contextlib
import json
import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation

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

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = (
        "Collection enumeration reveals the structure and purpose of the "
        "knowledge base, identifying high-value targets for exfiltration"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
    ]
    techniques = ["collection enumeration", "metadata analysis", "knowledge base mapping"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
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

                    enum_result = await self._enumerate_store(
                        client, store_type, service, collections
                    )
                    kb_structure.append(enum_result)

                    # Check for sensitive collection names
                    sensitive_names = self._flag_sensitive(collections)
                    severity = self._determine_severity(enum_result, sensitive_names)

                    result.observations.append(
                        build_observation(
                            check_name=self.name,
                            title=f"Knowledge base structure exposed: {store_type}",
                            description=self._build_description(enum_result, sensitive_names),
                            severity=severity,
                            evidence=self._build_evidence(enum_result, sensitive_names),
                            host=service.host,
                            discriminator=f"enum-{store_type}",
                            target=service,
                            raw_data=enum_result,
                            references=self.references,
                        )
                    )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if kb_structure:
            result.outputs["knowledge_base_structure"] = kb_structure

        return result

    async def _enumerate_store(
        self,
        client: AsyncHttpClient,
        store_type: str,
        service: Service,
        collections: list[str],
    ) -> dict:
        """Enumerate collection details for a store."""
        base_url = service.url
        if "://" in base_url:
            base_url = "/".join(base_url.split("/")[:3])

        collection_details: list[dict] = []

        for name in collections[:10]:
            detail = {"name": name, "doc_count": 0, "dimensions": None, "metadata_fields": []}

            try:
                if store_type == "chroma":
                    detail = await self._enum_chroma(client, base_url, name, detail)
                elif store_type == "qdrant":
                    detail = await self._enum_qdrant(client, base_url, name, detail)
                elif store_type == "weaviate":
                    detail = await self._enum_weaviate(client, base_url, name, detail)
                elif store_type == "pinecone":
                    detail = await self._enum_pinecone(client, base_url, name, detail)
                elif store_type == "milvus":
                    detail = await self._enum_milvus(client, base_url, name, detail)
            except Exception:
                pass

            collection_details.append(detail)

        total_docs = sum(c.get("doc_count", 0) for c in collection_details)

        return {
            "store_type": store_type,
            "collection_count": len(collection_details),
            "total_documents": total_docs,
            "collections": collection_details,
        }

    async def _enum_chroma(self, client, base_url, name, detail):
        resp = await client.get(f"{base_url}/api/v1/collections/{name}/count")
        if not resp.error and resp.status_code == 200:
            with contextlib.suppress(ValueError):
                detail["doc_count"] = int(resp.body or "0")
        # Get a sample to see metadata fields
        resp2 = await client.get(f"{base_url}/api/v1/collections/{name}/get?limit=1")
        if not resp2.error and resp2.status_code == 200:
            try:
                data = json.loads(resp2.body or "{}")
                metadatas = data.get("metadatas", [])
                if metadatas and isinstance(metadatas[0], dict):
                    detail["metadata_fields"] = list(metadatas[0].keys())[:20]
            except (json.JSONDecodeError, IndexError):
                pass
        return detail

    async def _enum_qdrant(self, client, base_url, name, detail):
        resp = await client.get(f"{base_url}/collections/{name}")
        if not resp.error and resp.status_code == 200:
            try:
                data = json.loads(resp.body or "{}")
                r = data.get("result", {})
                detail["doc_count"] = r.get("vectors_count", r.get("points_count", 0))
                cfg = r.get("config", {}).get("params", {}).get("vectors", {})
                if isinstance(cfg, dict):
                    detail["dimensions"] = cfg.get("size")
            except (json.JSONDecodeError, KeyError):
                pass
        return detail

    async def _enum_weaviate(self, client, base_url, name, detail):
        resp = await client.get(f"{base_url}/v1/schema")
        if not resp.error and resp.status_code == 200:
            try:
                data = json.loads(resp.body or "{}")
                for cls in data.get("classes", []):
                    if cls.get("class") == name:
                        props = cls.get("properties", [])
                        detail["metadata_fields"] = [p.get("name", "") for p in props][:20]
                        break
            except json.JSONDecodeError:
                pass
        return detail

    async def _enum_pinecone(self, client, base_url, name, detail):
        resp = await client.post(
            f"{base_url}/describe_index_stats",
            json={},
            headers={"Content-Type": "application/json"},
        )
        if not resp.error and resp.status_code == 200:
            try:
                data = json.loads(resp.body or "{}")
                detail["doc_count"] = data.get("totalVectorCount", 0)
                detail["dimensions"] = data.get("dimension")
                namespaces = data.get("namespaces", {})
                detail["metadata_fields"] = list(namespaces.keys())[:20]
            except json.JSONDecodeError:
                pass
        return detail

    async def _enum_milvus(self, client, base_url, name, detail):
        resp = await client.post(
            f"{base_url}/api/v1/entities/query",
            json={"collection_name": name, "expr": "id > 0", "limit": 1},
            headers={"Content-Type": "application/json"},
        )
        if not resp.error and resp.status_code == 200:
            try:
                data = json.loads(resp.body or "{}")
                rows = data.get("data", [])
                if rows and isinstance(rows[0], dict):
                    detail["metadata_fields"] = list(rows[0].keys())[:20]
            except (json.JSONDecodeError, IndexError):
                pass
        return detail

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
