"""
app/checks/ai/ai_llm_endpoint_discovery/check.py - AI Endpoint Discovery

Find chat/completion endpoints on services.

**Probe/grade.** The probe POSTs a one-token chat payload
to each candidate path and records what came back; `grade()` re-reads those
exchanges and decides which of them is an endpoint. The path each verdict is
about is read back off `Exchange.request_url` rather than carried over from the
loop, which is the web suite's convention (§0.13) and the reason the two halves
cannot disagree about what was asked.

Discovery also `produces` the `chat_endpoints` output most of the suite depends
on, so this is a "one parser, called twice" check (§0.12): `_endpoints_from()`
runs over the live responses for the output and over the stored copies for the
verdicts.

One thing the probe does *not* hand over: the `OPTIONS` pre-flight. It is a
reachability gate on the probe's control flow, not evidence for any judgement,
and a grader that had to filter it back out would be carrying knowledge of how
the probe loops. When capture is on the interceptor records it anyway, so
nothing leaves the corpus — a skipped path simply has no POST to grade, which
is what "skipped" means here.
"""

from typing import Any
from urllib.parse import urlparse

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.ai_helpers import fmt_endpoint_probe_evidence
from app.lib.datafiles import load_data
from app.lib.http import AsyncHttpClient, HttpConfig

#: The payload the probe sends. Named because `grade()`'s "this was a real chat
#: endpoint" reasoning is only as strong as the request was representative.
PROBE_PAYLOAD = {"messages": [{"role": "user", "content": "test"}]}
JSON_HEADERS = {"Content-Type": "application/json"}

#: A path that answers with one of these did not accept the payload.
REJECTED_STATUSES = (404, 405)


class LLMEndpointCheck(ServiceIteratingCheck):
    """Discover LLM chat and completion endpoints."""

    name = "ai_llm_endpoint_discovery"
    description = "Find chat and completion endpoints on AI services"

    conditions = [CheckCondition("services", "truthy"), CheckCondition("services_probed", "truthy")]
    produces = ["chat_endpoints", "completion_endpoints"]
    service_types = ["ai", "api", "http"]

    reason = "Chat/completion endpoints are the primary interface for prompt injection and other AI attacks"
    references = ["OWASP LLM Top 10 - LLM01 Prompt Injection"]
    techniques = ["endpoint discovery", "API enumeration"]

    # Shipped list: app/data/endpoints/chat_paths.yaml (operator-editable). This
    # inline copy is the fallback if that file is missing.
    _FALLBACK_CHAT_PATHS = [
        "/v1/chat/completions",
        "/v1/completions",
        "/chat/completions",
        "/completions",
        "/v1/messages",
        "/messages",
        "/api/generate",
        "/api/chat",
        "/chat",
        "/inference",
        "/predict",
        "/api/inference",
        "/api/predict",
        "/invoke",
        "/stream",
        "/batch",
        "/generate",
        "/v1/generate",
        "/generate_stream",
    ]
    CHAT_PATHS = load_data("endpoints/chat_paths.yaml", _FALLBACK_CHAT_PATHS)

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        probed: list[Exchange] = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in self.CHAT_PATHS:
                    url = service.with_path(path)

                    opts = await client.options(url)
                    if opts.error or opts.status_code >= 500:
                        continue

                    post_resp = await client.post(url, json=PROBE_PAYLOAD, headers=JSON_HEADERS)

                    exchange = exchange_from_response(
                        post_resp,
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
                    # cannot carry one. Emitting a candidate for every path
                    # probed — not only the ones that answered — keeps the
                    # judgement itself on the grade side.
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

        # The output has to exist by the time the next check runs, so the probe
        # parses its own exchanges now — the same parser `grade()` calls later
        # over the stored copies.
        chat_endpoints = [
            {
                "url": endpoint["url"],
                "path": endpoint["path"],
                "service": service.to_dict(),
                "api_format": endpoint["api_format"],
                "status_code": endpoint["status_code"],
            }
            for endpoint in self._endpoints_from(probed)
        ]
        if chat_endpoints:
            result.outputs["chat_endpoints"] = chat_endpoints

        return result

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """A verdict for the probed path, if what came back reads as an endpoint.

        One exchange in, at most one verdict out — a path that answered
        `404`/`405` or errored yields none, which is where the original check's
        `continue` went. Every judgement is `info`: an endpoint existing is not
        itself a finding, it is the surface the rest of the suite attacks. So
        the confidence carries the whole of what is uncertain, and what is
        uncertain is whether a path that answered is an LLM at all.
        """
        verdicts: list[Verdict] = []

        for endpoint in self._endpoints_from(list(evidence)):
            path = endpoint["path"]
            api_format = endpoint["api_format"]
            status = endpoint["status_code"]
            confidence, why = self._confidence_for(api_format, status, endpoint["body"])

            verdicts.append(
                Verdict(
                    severity="info",
                    confidence=confidence,
                    discriminator=self._discriminator(path),
                    title=f"LLM endpoint: {path}",
                    description=f"Chat/completion endpoint discovered ({api_format} format)",
                    evidence=fmt_endpoint_probe_evidence(path, status, api_format),
                    reasoning=why,
                    signals={
                        "path": path,
                        "api_format": api_format,
                        "status_code": status,
                    },
                    references=["OWASP LLM Top 10 - LLM01 Prompt Injection"],
                    raw_data={"api_format": api_format},
                    evidence_ids=[endpoint["exchange_id"]],
                )
            )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    @staticmethod
    def _discriminator(path: str) -> str:
        """The observation id suffix, unchanged from before the split."""
        return f"chat-{path.strip('/').replace('/', '-')}"

    def _endpoints_from(self, exchanges: list[Exchange]) -> list[dict]:
        """Every recorded POST that reads as a live chat endpoint.

        The judgement the original check made inline: an endpoint is a path
        whose POST neither errored nor answered `404`/`405`. A `401` counts —
        an endpoint that demands a key is still an endpoint, and is exactly
        what the suite wants to know about.
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
                    "api_format": self._detect_api_format(path),
                    "status_code": exchange.response_status,
                    "body": exchange.response_body or "",
                    "exchange_id": exchange.id,
                }
            )
        return endpoints

    def _confidence_for(self, api_format: str, status: int, body: str) -> tuple[float, str]:
        """How sure the endpoint claim is, and why it is not 1.0.

        The check keys on a status code, and a catch-all route answers every
        path — the web suite's recurring false positive (§0.13) reaches here
        too, because a server that 200s `/predict` with its index page looks
        exactly like a langserve deployment. So the body is read for the shape
        of a model answer, and a path whose dialect the signature table does
        not recognise starts lower than one it does.
        """
        looks_like_json = body.lstrip().startswith(("{", "["))
        named_dialect = api_format != "unknown"

        if status in (401, 403):
            # Nothing answers a chat payload with 401 except something that
            # meant to handle it; this is the strongest signal in the check.
            return 0.9, f"HTTP {status} — the path exists and enforces auth on it"
        if named_dialect and looks_like_json:
            return 0.85, (
                f"path matches the {api_format} dialect and answered HTTP {status} with JSON"
            )
        if named_dialect:
            return 0.6, (
                f"path matches the {api_format} dialect but answered HTTP {status} with a "
                "non-JSON body, which a catch-all route also does"
            )
        if looks_like_json:
            return 0.5, (
                f"HTTP {status} with a JSON body, but the path matches no known dialect — "
                "the payload may simply have been ignored"
            )
        return 0.3, (
            f"HTTP {status} with a non-JSON body on an unrecognised path; a catch-all route "
            "answering every request looks identical"
        )

    def _detect_api_format(self, path: str) -> str:
        path_lower = path.lower()
        if "/v1/chat/completions" in path_lower or "/chat/completions" in path_lower:
            return "openai"
        elif "/messages" in path_lower:
            return "anthropic"
        elif "/api/generate" in path_lower or "/api/chat" in path_lower:
            return "ollama"
        elif "/invoke" in path_lower or "/stream" in path_lower:
            return "langserve"
        elif "generate" in path_lower:
            return "tgi"
        return "unknown"
