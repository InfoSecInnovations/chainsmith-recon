"""
app/checks/rag/corpus_poisoning.py - Document/Corpus Poisoning

Test if documents containing embedded injection payloads can be written
into the RAG corpus via ingestion endpoints. This is persistent indirect
injection — the payload lives in the knowledge base and affects every
user who retrieves that document.

Gated behind intrusive=True. Uses a clearly identifiable canary document
and attempts cleanup after testing.

**Probe/grade.** The probe walks the ingestion paths, trying
JSON then multipart writes and recording every attempt; `grade()` re-reads them,
rebuilds the list of ingestion endpoints found, and emits one verdict — the
worst outcome across them. `_reading()` is the one parser both halves call
(§0.12): each attempt is attributed to its path and format by the recorded
request URL and body, the collection names come from the upstream
`vector_store_collections` output (§0.15), and the random per-run canary id is
recovered from the recorded request bodies so a re-grade reproduces it. Cleanup
DELETEs carry no graded payload and are not attached.

**Contextual**: whether an accepted write is a real
poisoning primitive is the attack-compliance question — a 200 can mean the
document was indexed, or that the endpoint accepted and dropped it — so the rule
logic runs at `GradingTier.RULE` and defers to the planned LLM grading tier. Confidence states the
gap: the canary write was never read back through retrieval, so "writable" rests
on the ingestion status code alone.

References:
  https://arxiv.org/abs/2402.16893 (Indirect Prompt Injection)
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import contextlib
import json
import re
import uuid
from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}
CANARY_RE = re.compile(r"chainsmith-canary-[0-9a-f]{8}")

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

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        cfg = HttpConfig(timeout_seconds=12.0, verify_ssl=False)
        canary_id = f"chainsmith-canary-{uuid.uuid4().hex[:8]}"
        candidate = self.create_candidate(host=service.host, target=service, target_url=service.url)

        def record(
            resp, *, data: Any = None, jbody: dict | None = None, headers: dict | None = None
        ) -> None:
            # Exactly what was handed to the client (B-8), so this copy hashes
            # the same as the one the capture interceptor stored.
            kwargs: dict[str, Any] = {"method": "POST"}
            if jbody is not None:
                kwargs["request_headers"] = JSON_HEADERS
                kwargs["request_json"] = jbody
            else:
                kwargs["request_headers"] = dict(headers or {})
                kwargs["request_data"] = data
            candidate.attach(
                exchange_from_response(
                    resp, check_name=self.name, scan_id=scan_id, host=service.host, **kwargs
                )
            )

        ingestion_found: list[dict] = []
        try:
            async with AsyncHttpClient(cfg) as client:
                base_url = self._base_url(service)
                all_paths = self._all_paths(context)

                for path in all_paths:
                    url = f"{base_url}{path}"
                    found = await self._probe_path(client, record, url, canary_id, path)
                    if found:
                        ingestion_found.append(found)

                # Cleanup for any successfully ingested documents (not attached).
                for ing in ingestion_found:
                    if ing.get("writable"):
                        await self._attempt_cleanup(client, base_url, canary_id)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.candidates.append(candidate)
        if ingestion_found:
            result.outputs["ingestion_endpoints"] = ingestion_found

        return result

    async def _probe_path(self, client, record, url: str, canary_id: str, path: str) -> dict | None:
        """Try JSON then multipart ingestion at one path, recording each attempt."""
        for payload in self._json_payloads(canary_id):
            resp = await client.post(url, json=payload, headers=JSON_HEADERS)
            record(resp, jbody=payload)
            if resp.error:
                continue
            classified = self._classify_json(path, resp.status_code, canary_id)
            if classified:
                return classified

        data = self._multipart_body(canary_id).encode("utf-8")
        headers = {"Content-Type": f"multipart/form-data; boundary={self._boundary(canary_id)}"}
        resp = await client.post(url, data=data, headers=headers)
        record(resp, data=data, headers=headers)
        if resp.error:
            return None
        return self._classify_multipart(path, resp.status_code, canary_id)

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchanges = list(evidence)
        ids = evidence.ids()
        context = ctx.context or {}
        canary_id = self._canary_from(exchanges)
        ingestion_found = self._reading(exchanges, context, canary_id)

        writable = [i for i in ingestion_found if i.get("writable")]
        accessible = [i for i in ingestion_found if not i.get("writable") and i.get("accessible")]

        if writable:
            no_auth = [i for i in writable if not i.get("auth_required")]
            if no_auth:
                return [
                    Verdict(
                        severity="critical",
                        confidence=0.45,
                        discriminator="corpus-poison-noauth",
                        title="Corpus poisoning: ingestion endpoint accepts unauthenticated writes",
                        description=(
                            f"Document ingestion at {no_auth[0]['path']} accepts writes without "
                            f"authentication. Persistent indirect injection possible."
                        ),
                        evidence=self._build_evidence(no_auth[0]),
                        reasoning=(
                            "an ingestion endpoint returned a write-success status (200/201/202) to "
                            "an unauthenticated canary — a strong primitive — but the canary was "
                            "never read back through retrieval, so whether it was actually indexed "
                            "into the corpus (versus accepted and dropped) needs model-based grading (not yet available)"
                        ),
                        signals={"endpoints": no_auth, "canary_id": canary_id},
                        references=self.references,
                        raw_data={"endpoints": no_auth, "canary_id": canary_id},
                        tier=ctx.tier,
                        evidence_ids=ids,
                    )
                ]
            return [
                Verdict(
                    severity="high",
                    confidence=0.45,
                    discriminator="corpus-poison-writable",
                    title="Document ingestion endpoint accessible with write access",
                    description=(
                        f"Ingestion at {writable[0]['path']} accepts document uploads. "
                        f"Write access to knowledge base confirmed."
                    ),
                    evidence=self._build_evidence(writable[0]),
                    reasoning=(
                        "the endpoint accepted a write, so a write path exists; the canary was not "
                        "retrieved back, so persistence into the corpus is inferred from the status "
                        "code rather than observed"
                    ),
                    signals={"endpoints": writable, "canary_id": canary_id},
                    references=self.references,
                    raw_data={"endpoints": writable, "canary_id": canary_id},
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        if accessible:
            return [
                Verdict(
                    severity="medium",
                    confidence=0.5,
                    discriminator="corpus-ingest-found",
                    title="Document ingestion endpoint found but writes rejected",
                    description="Ingestion endpoint exists but requires proper auth or rejected test document.",
                    evidence=f"Path: {accessible[0]['path']}, Status: {accessible[0].get('status')}",
                    reasoning=(
                        "the path answered like an ingestion endpoint (401/403, or 400/422 rejecting "
                        "the test document) rather than 404, so it exists; the write was refused, so "
                        "this is surface, not a confirmed poisoning primitive"
                    ),
                    signals={"endpoint": accessible[0]},
                    tier=ctx.tier,
                    evidence_ids=ids,
                )
            ]

        return [
            Verdict(
                severity="info",
                confidence=0.4,
                discriminator="no-ingestion",
                title="No writable ingestion endpoints found",
                description="No document ingestion endpoints detected.",
                evidence=f"Probed {len(self._all_paths(context))} paths",
                reasoning=(
                    "no probed path classified as an ingestion endpoint; the negative is bounded by "
                    "the fixed path list — a write route under a different name would be missed"
                ),
                tier=ctx.tier,
                evidence_ids=ids,
            )
        ]

    # ── The parser both halves share ─────────────────────────────────

    def _reading(
        self, exchanges: list[Exchange], context: dict[str, Any], canary_id: str
    ) -> list[dict]:
        """Rebuild the ingestion-endpoint list off the recorded exchanges."""
        ingestion_found: list[dict] = []
        for path in self._all_paths(context):
            found = self._classify_path(exchanges, path, canary_id)
            if found:
                ingestion_found.append(found)
        return ingestion_found

    def _classify_path(self, exchanges: list[Exchange], path: str, canary_id: str) -> dict | None:
        """The recorded outcome for one path: first classifying JSON attempt, else
        the multipart attempt."""
        for payload in self._json_payloads(canary_id):
            ex = self._find_json(exchanges, path, payload)
            if ex is None or ex.error:
                continue
            classified = self._classify_json(path, ex.response_status, canary_id)
            if classified:
                return classified

        ex = self._find_multipart(exchanges, path)
        if ex is None or ex.error:
            return None
        return self._classify_multipart(path, ex.response_status, canary_id)

    # ── Classification (shared by probe + reading) ────────────────────

    @staticmethod
    def _classify_json(path: str, status, canary_id: str) -> dict | None:
        if status in (200, 201, 202):
            return {
                "path": path,
                "format": "json",
                "status": status,
                "writable": True,
                "auth_required": False,
                "canary_id": canary_id,
            }
        if status in (401, 403):
            return {
                "path": path,
                "format": "json",
                "status": status,
                "writable": False,
                "accessible": True,
                "auth_required": True,
            }
        if status in (400, 422):
            return {
                "path": path,
                "format": "json",
                "status": status,
                "writable": False,
                "accessible": True,
                "auth_required": False,
            }
        return None

    @staticmethod
    def _classify_multipart(path: str, status, canary_id: str) -> dict | None:
        if status in (200, 201, 202):
            return {
                "path": path,
                "format": "multipart",
                "status": status,
                "writable": True,
                "auth_required": False,
                "canary_id": canary_id,
            }
        if status in (401, 403):
            return {
                "path": path,
                "format": "multipart",
                "status": status,
                "writable": False,
                "accessible": True,
                "auth_required": True,
            }
        return None

    # ── Request builders + lookups ────────────────────────────────────

    @staticmethod
    def _json_payloads(canary_id: str) -> list[dict]:
        canary_content = (
            f"Chainsmith security test document (ID: {canary_id}). "
            f"This is an authorized penetration test canary."
        )
        return [
            {"documents": [canary_content], "ids": [canary_id]},
            {"content": canary_content, "id": canary_id, "metadata": {"source": "chainsmith-test"}},
            {"text": canary_content, "id": canary_id},
            {"documents": [{"content": canary_content, "id": canary_id}]},
        ]

    @staticmethod
    def _boundary(canary_id: str) -> str:
        return f"chainsmith-{canary_id[:8]}"

    def _multipart_body(self, canary_id: str) -> str:
        content = f"Chainsmith test document (ID: {canary_id})"
        boundary = self._boundary(canary_id)
        return (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"{content}\r\n"
            f"--{boundary}--\r\n"
        )

    def _find_json(self, exchanges: list[Exchange], path: str, payload: dict) -> Exchange | None:
        for exchange in exchanges:
            if exchange.request_method != "POST":
                continue
            if urlparse(exchange.request_url or "").path != path:
                continue
            try:
                got = json.loads(exchange.request_body or "null")
            except (ValueError, TypeError):
                continue
            if got == payload:
                return exchange
        return None

    def _find_multipart(self, exchanges: list[Exchange], path: str) -> Exchange | None:
        for exchange in exchanges:
            if exchange.request_method != "POST":
                continue
            if urlparse(exchange.request_url or "").path != path:
                continue
            if (exchange.request_body or "").startswith("--chainsmith-"):
                return exchange
        return None

    @staticmethod
    def _canary_from(exchanges: list[Exchange]) -> str:
        """Recover the per-run canary id from any recorded request body."""
        for exchange in exchanges:
            match = CANARY_RE.search(exchange.request_body or "")
            if match:
                return match.group(0)
        return ""

    def _all_paths(self, context: dict[str, Any]) -> list[str]:
        collections = context.get("vector_store_collections", [])
        collection_names: list[str] = []
        if isinstance(collections, list):
            for c in collections:
                if isinstance(c, dict):
                    collection_names.append(c.get("name", "default"))
                elif isinstance(c, str):
                    collection_names.append(c)
        if not collection_names:
            collection_names = ["default"]

        all_paths = list(INGESTION_PATHS)
        for tmpl in COLLECTION_PATHS:
            for name in collection_names[:3]:
                all_paths.append(tmpl.replace("{name}", name))
        return all_paths

    async def _attempt_cleanup(self, client, base_url: str, canary_id: str) -> None:
        """Attempt to delete the canary document after testing (not attached)."""
        cleanup_paths = [
            f"/documents/{canary_id}",
            f"/api/documents/{canary_id}",
            f"/v1/documents/{canary_id}",
            f"/api/v1/documents/{canary_id}",
        ]
        for path in cleanup_paths:
            with contextlib.suppress(Exception):
                await client.delete(f"{base_url}{path}")

    @staticmethod
    def _base_url(service: Service) -> str:
        base_url = service.url
        if "://" in base_url:
            base_url = "/".join(base_url.split("/")[:3])
        return base_url

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
