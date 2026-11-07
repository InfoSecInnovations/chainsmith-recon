"""
app/checks/ai/ai_embedding_endpoint_discovery/check.py - AI Endpoint Discovery

Find embedding and vector endpoints on services.

**Probe/grade.** Same shape as its sibling
`ai_llm_endpoint_discovery`: the probe POSTs one embedding payload per candidate
path and records the answers, `grade()` re-reads them and decides which paths
are endpoints, and the path is read back off `Exchange.request_url` rather than
carried over from the loop. `_endpoints_from()` is the one parser both halves
call (§0.12), because the `embedding_endpoints` output has to exist by the time
the next check runs.

There is no `OPTIONS` pre-flight here — unlike the chat check this one POSTs
straight at each path — so every request the probe makes is evidence for a
judgement and all of them are handed over.
"""

from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.ai_helpers import fmt_endpoint_probe_evidence
from app.lib.datafiles import load_data
from app.lib.http import AsyncHttpClient, HttpConfig

PROBE_PAYLOAD = {"input": "test"}
JSON_HEADERS = {"Content-Type": "application/json"}

REJECTED_STATUSES = (404, 405)

#: What an embedding response actually looks like, in any of the dialects: a
#: float vector under one of these keys. `grade()` looks for one to tell a real
#: embedding endpoint from a path that merely answered.
VECTOR_KEYS = ("embedding", "embeddings", "data", "vector", "vectors", "dense_vecs")


class EmbeddingEndpointCheck(ServiceIteratingCheck):
    """Discover embedding and vector endpoints."""

    name = "ai_embedding_endpoint_discovery"
    description = "Find embedding and vector endpoints on AI services"

    conditions = [CheckCondition("services", "truthy"), CheckCondition("services_probed", "truthy")]
    produces = ["embedding_endpoints"]
    service_types = ["ai", "api", "http"]

    reason = "Embedding endpoints may leak training data or enable inference attacks"
    references = ["OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure"]
    techniques = ["endpoint discovery", "embedding extraction"]

    # Shipped list: app/data/endpoints/embedding_paths.yaml (operator-editable).
    # This inline copy is the fallback if missing.
    _FALLBACK_EMBEDDING_PATHS = [
        "/v1/embeddings",
        "/embeddings",
        "/api/embeddings",
        "/api/embed",
        "/embed",
        "/encode",
        "/api/encode",
        "/api/vectors",
        "/vectors",
        "/similarity",
        "/search",
        "/api/search",
        "/feature-extraction",
    ]
    EMBEDDING_PATHS = load_data("endpoints/embedding_paths.yaml", _FALLBACK_EMBEDDING_PATHS)

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        probed: list[Exchange] = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.EMBEDDING_PATHS:
                    url = service.with_path(path)

                    resp = await client.post(url, json=PROBE_PAYLOAD, headers=JSON_HEADERS)

                    exchange = exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=service.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json=PROBE_PAYLOAD,
                    )
                    probed.append(exchange)

                    # One candidate per path, following `web_path_probe`: each
                    # observation names its own `target_url`, and a Verdict
                    # cannot carry one.
                    candidate = self.create_candidate(
                        host=service.host,
                        discriminator=self._discriminator(path),
                        target=service,
                        target_url=url,
                    )
                    candidate.attach(exchange)
                    result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        embedding_endpoints = [
            {
                "url": endpoint["url"],
                "path": endpoint["path"],
                "service": service.to_dict(),
            }
            for endpoint in self._endpoints_from(probed)
        ]
        if embedding_endpoints:
            result.outputs["embedding_endpoints"] = embedding_endpoints

        return result

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """An `info` verdict for the probed path, if it accepted the payload.

        One exchange in, at most one verdict out — a path that answered
        `404`/`405` or errored yields none, which is where the original check's
        `continue` went.
        """
        verdicts: list[Verdict] = []

        for endpoint in self._endpoints_from(list(evidence)):
            path = endpoint["path"]
            status = endpoint["status_code"]
            confidence, why = self._confidence_for(path, status, endpoint["body"])

            verdicts.append(
                Verdict(
                    severity="info",
                    confidence=confidence,
                    discriminator=self._discriminator(path),
                    title=f"Embedding endpoint: {path}",
                    description="Embedding/vector endpoint discovered",
                    evidence=fmt_endpoint_probe_evidence(path, status),
                    reasoning=why,
                    signals={"path": path, "status_code": status},
                    references=["OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure"],
                    evidence_ids=[endpoint["exchange_id"]],
                )
            )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    @staticmethod
    def _discriminator(path: str) -> str:
        """The observation id suffix, unchanged from before the split."""
        return f"embed-{path.strip('/').replace('/', '-')}"

    def _endpoints_from(self, exchanges: list[Exchange]) -> list[dict]:
        """Every recorded POST that reads as a live embedding endpoint.

        The original check's inline judgement: neither an error nor a
        `404`/`405`. Preserved exactly, so a `401` still counts as a
        discovered endpoint.
        """
        endpoints = []
        for exchange in exchanges:
            if exchange.error or exchange.response_status is None:
                continue
            if exchange.response_status in REJECTED_STATUSES:
                continue

            path = urlparse(exchange.request_url).path or "/"
            endpoints.append(
                {
                    "url": exchange.request_url,
                    "path": path,
                    "status_code": exchange.response_status,
                    "body": exchange.response_body or "",
                    "exchange_id": exchange.id,
                }
            )
        return endpoints

    def _confidence_for(self, path: str, status: int, body: str) -> tuple[float, str]:
        """How sure the endpoint claim is, and why it is not 1.0.

        This check's path list is its own weak point, and it is weaker than the
        chat one: `/search` and `/similarity` are ordinary application routes on
        any site with a search box, so a 200 there says almost nothing about
        embeddings. So the body is read for a vector, which is the only thing
        that distinguishes the two, and the two ambiguous paths start lower.
        """
        body_lower = body.lower()
        has_vector = body.lstrip().startswith(("{", "[")) and any(
            f'"{key}"' in body_lower for key in VECTOR_KEYS
        )
        # A route that exists for humans rather than for models.
        generic_path = any(word in path.lower() for word in ("search", "similarity"))

        if status in (401, 403):
            return 0.85, f"HTTP {status} — the path exists and enforces auth on it"
        if has_vector:
            return 0.9, (
                f"HTTP {status} and the body carries a vector field, which only an embedding "
                "endpoint returns"
            )
        if generic_path:
            return 0.3, (
                f"HTTP {status} on {path}, which is an ordinary application route on any site "
                "with a search box — no vector in the response to distinguish the two"
            )
        if body.lstrip().startswith(("{", "[")):
            return 0.6, (
                f"HTTP {status} with a JSON body but no recognisable vector field; the payload "
                "may have been accepted and ignored"
            )
        return 0.35, (
            f"HTTP {status} with a non-JSON body; a catch-all route answering every path looks "
            "identical"
        )
