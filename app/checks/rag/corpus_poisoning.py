"""
app/checks/rag/corpus_poisoning.py - Document/Corpus Poisoning

Test if documents containing embedded injection payloads can be written
into the RAG corpus via ingestion endpoints. This is persistent indirect
injection — the payload lives in the knowledge base and affects every
user who retrieves that document.

Gated behind intrusive=True. Uses a clearly identifiable canary document
and attempts cleanup after testing.

References:
  https://arxiv.org/abs/2402.16893 (Indirect Prompt Injection)
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import contextlib
import uuid
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

# Ingestion endpoint paths to probe
INGESTION_PATHS = [
    "/documents",
    "/ingest",
    "/upload",
    "/index",
    "/add",
    "/api/documents",
    "/api/ingest",
    "/v1/documents",
    "/api/v1/ingest",
    "/api/v1/documents",
]

# Collection-scoped paths (need collection name substitution)
COLLECTION_PATHS = [
    "/collections/{name}/add",
    "/collections/{name}/upsert",
    "/api/v1/collections/{name}/add",
    "/api/v1/collections/{name}/upsert",
]


class RAGCorpusPoisoningCheck(ServiceIteratingCheck):
    """
    Test for document ingestion endpoints that accept unauthenticated
    writes, enabling persistent corpus poisoning attacks.
    """

    name = "rag_corpus_poisoning"
    description = "Test for writable document ingestion endpoints (corpus poisoning)"
    intrusive = True

    conditions = [CheckCondition("rag_endpoints", "truthy")]
    produces = ["ingestion_endpoints"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 120.0
    delay_between_targets = 0.5

    reason = (
        "Corpus poisoning is persistent indirect injection — the payload lives "
        "in the knowledge base and affects every user who retrieves the "
        "poisoned document, unlike query-time injection which affects one session"
    )
    references = [
        "https://arxiv.org/abs/2402.16893",
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
    ]
    techniques = ["corpus poisoning", "document ingestion", "persistent injection"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        context.get("rag_endpoints", [])
        collections = context.get("vector_store_collections", [])
        collection_names = []
        if isinstance(collections, list):
            for c in collections:
                if isinstance(c, dict):
                    collection_names.append(c.get("name", "default"))
                elif isinstance(c, str):
                    collection_names.append(c)
        if not collection_names:
            collection_names = ["default"]

        cfg = HttpConfig(timeout_seconds=12.0, verify_ssl=False)
        ingestion_found: list[dict] = []
        canary_id = f"chainsmith-canary-{uuid.uuid4().hex[:8]}"

        try:
            async with AsyncHttpClient(cfg) as client:
                base_url = service.url
                if "://" in base_url:
                    base_url = "/".join(base_url.split("/")[:3])

                # Probe all ingestion paths
                all_paths = list(INGESTION_PATHS)
                for tmpl in COLLECTION_PATHS:
                    for name in collection_names[:3]:
                        all_paths.append(tmpl.replace("{name}", name))

                for path in all_paths:
                    url = f"{base_url}{path}"

                    # Try JSON format
                    json_result = await self._try_ingest_json(client, url, canary_id, path)
                    if json_result:
                        ingestion_found.append(json_result)
                        continue

                    # Try multipart upload
                    multi_result = await self._try_ingest_multipart(client, url, canary_id, path)
                    if multi_result:
                        ingestion_found.append(multi_result)

                # Attempt cleanup for any successfully ingested documents
                for ing in ingestion_found:
                    if ing.get("writable"):
                        await self._attempt_cleanup(client, base_url, canary_id, ing)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # Generate observations
        writable = [i for i in ingestion_found if i.get("writable")]
        accessible = [i for i in ingestion_found if not i.get("writable") and i.get("accessible")]

        if writable:
            no_auth = [i for i in writable if not i.get("auth_required")]
            if no_auth:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title="Corpus poisoning: ingestion endpoint accepts unauthenticated writes",
                        description=(
                            f"Document ingestion at {no_auth[0]['path']} accepts writes without "
                            f"authentication. Persistent indirect injection possible."
                        ),
                        severity="critical",
                        evidence=self._build_evidence(no_auth[0]),
                        host=service.host,
                        discriminator="corpus-poison-noauth",
                        target=service,
                        raw_data={"endpoints": no_auth, "canary_id": canary_id},
                        references=self.references,
                    )
                )
            else:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title="Document ingestion endpoint accessible with write access",
                        description=(
                            f"Ingestion at {writable[0]['path']} accepts document uploads. "
                            f"Write access to knowledge base confirmed."
                        ),
                        severity="high",
                        evidence=self._build_evidence(writable[0]),
                        host=service.host,
                        discriminator="corpus-poison-writable",
                        target=service,
                        raw_data={"endpoints": writable, "canary_id": canary_id},
                        references=self.references,
                    )
                )

        if accessible and not writable:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="Document ingestion endpoint found but writes rejected",
                    description="Ingestion endpoint exists but requires proper auth or rejected test document.",
                    severity="medium",
                    evidence=f"Path: {accessible[0]['path']}, Status: {accessible[0].get('status')}",
                    host=service.host,
                    discriminator="corpus-ingest-found",
                    target=service,
                )
            )

        if not ingestion_found:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title="No writable ingestion endpoints found",
                    description="No document ingestion endpoints detected.",
                    severity="info",
                    evidence=f"Probed {len(all_paths)} paths",
                    host=service.host,
                    discriminator="no-ingestion",
                    target=service,
                )
            )

        if ingestion_found:
            result.outputs["ingestion_endpoints"] = ingestion_found

        return result

    async def _try_ingest_json(
        self,
        client: AsyncHttpClient,
        url: str,
        canary_id: str,
        path: str,
    ) -> dict | None:
        """Try JSON API ingestion format."""
        canary_content = (
            f"Chainsmith security test document (ID: {canary_id}). "
            f"This is an authorized penetration test canary."
        )
        payloads = [
            {"documents": [canary_content], "ids": [canary_id]},
            {"content": canary_content, "id": canary_id, "metadata": {"source": "chainsmith-test"}},
            {"text": canary_content, "id": canary_id},
            {"documents": [{"content": canary_content, "id": canary_id}]},
        ]

        for payload in payloads:
            resp = await client.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.error:
                continue

            if resp.status_code in (200, 201, 202):
                return {
                    "path": path,
                    "format": "json",
                    "status": resp.status_code,
                    "writable": True,
                    "auth_required": False,
                    "canary_id": canary_id,
                }
            elif resp.status_code in (401, 403):
                return {
                    "path": path,
                    "format": "json",
                    "status": resp.status_code,
                    "writable": False,
                    "accessible": True,
                    "auth_required": True,
                }
            elif resp.status_code in (400, 422):
                return {
                    "path": path,
                    "format": "json",
                    "status": resp.status_code,
                    "writable": False,
                    "accessible": True,
                    "auth_required": False,
                }

        return None

    async def _try_ingest_multipart(
        self,
        client: AsyncHttpClient,
        url: str,
        canary_id: str,
        path: str,
    ) -> dict | None:
        """Try multipart file upload."""
        # Simple boundary-based multipart manually built
        content = f"Chainsmith test document (ID: {canary_id})"
        boundary = f"chainsmith-{canary_id[:8]}"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"{content}\r\n"
            f"--{boundary}--\r\n"
        )

        resp = await client.post(
            url,
            data=body.encode("utf-8"),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        if resp.error:
            return None

        if resp.status_code in (200, 201, 202):
            return {
                "path": path,
                "format": "multipart",
                "status": resp.status_code,
                "writable": True,
                "auth_required": False,
                "canary_id": canary_id,
            }
        elif resp.status_code in (401, 403):
            return {
                "path": path,
                "format": "multipart",
                "status": resp.status_code,
                "writable": False,
                "accessible": True,
                "auth_required": True,
            }
        return None

    async def _attempt_cleanup(
        self,
        client: AsyncHttpClient,
        base_url: str,
        canary_id: str,
        ing: dict,
    ):
        """Attempt to delete the canary document after testing."""
        cleanup_paths = [
            f"/documents/{canary_id}",
            f"/api/documents/{canary_id}",
            f"/v1/documents/{canary_id}",
            f"/api/v1/documents/{canary_id}",
        ]
        for path in cleanup_paths:
            with contextlib.suppress(Exception):
                await client.delete(f"{base_url}{path}")

    def _build_evidence(self, endpoint: dict) -> str:
        lines = [
            f"Path: {endpoint['path']}",
            f"Format: {endpoint.get('format', 'unknown')}",
            f"Status: {endpoint.get('status', 'unknown')}",
            f"Auth required: {endpoint.get('auth_required', 'unknown')}",
        ]
        if endpoint.get("canary_id"):
            lines.append(f"Canary ID: {endpoint['canary_id']}")
        return "\n".join(lines)
