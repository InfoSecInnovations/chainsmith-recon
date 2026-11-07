"""
Service Probing Checks

Deep inspection of discovered services to determine type and gather fingerprints.

**Probe/grade.** `check_service()` connects, classifies, and
records; `grade()` re-reads the recorded response and places severity on what the
headers disclosed. The split is uneven here on purpose: `_classify_service` stays
on the probe side because `service_type` is what routes the rest of the scan —
every suite's conditions read it — so it cannot wait for a grader. This is §6.2's
"a probe that branches on a parsed value parses twice", and the two halves read
different things out of the same response: the probe asks *what is this*, the
grader asks *what did it give away*.
"""

from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig


class ServiceProbeCheck(ServiceIteratingCheck):
    """
    Probe discovered services to determine their type.

    Performs deep inspection:
    - HTTP vs HTTPS detection
    - Content type analysis
    - Header fingerprinting
    - AI/ML service detection
    """

    name = "network_service_probe"
    description = "Probe services to determine type and gather initial fingerprints"

    conditions = [
        CheckCondition("services", "truthy"),
    ]

    produces = ["services", "services_probed"]  # Enriches existing services

    sequential = True

    # Educational
    reason = "Understanding service types guides which checks to run next"
    references = ["OWASP WSTG-INFO-02"]
    techniques = ["service fingerprinting", "banner grabbing", "HTTP fingerprinting"]

    # Headers that indicate AI/ML services
    AI_HEADERS = ["x-model", "x-inference", "x-llm", "x-ai-", "x-ml-"]

    AI_POWERED_BY = [
        "vllm",
        "ollama",
        "tgi",
        "triton",
        "inference",
        "mlflow",
        "huggingface",
        "transformers",
        "langchain",
        "langserve",
    ]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        # Signal to downstream discovery checks that classification has run,
        # so they don't race ahead and see service_type="unknown".
        result.outputs["services_probed"] = True

        # Try HTTPS first, then HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{service.host}:{service.port}"

            try:
                async with AsyncHttpClient(
                    HttpConfig(timeout_seconds=10.0, verify_ssl=False)
                ) as client:
                    response = await client.get(url)

                    # Check if request actually succeeded (HTTP client returns error in response, not exception)
                    if response.error:
                        result.errors.append(f"{url}: {response.error}")
                        continue

                    # Connection succeeded — now safe to update service
                    service.scheme = scheme
                    service.url = url

                    headers = dict(response.headers)
                    content_type = headers.get("content-type", "").lower()

                    # Store headers in metadata for later checks
                    service.metadata["headers"] = headers
                    service.metadata["status_code"] = response.status_code
                    service.metadata["content_type"] = content_type

                    # Determine service type
                    service.service_type = self._classify_service(
                        headers, content_type, response.body[:2000]
                    )

                    # What the headers gave away is the grader's question. The
                    # exchange is handed over in memory as well as recorded,
                    # because capture is off by default (§0.4).
                    result.candidates.append(
                        self.create_candidate(host=service.host, target=service).attach(
                            exchange_from_response(
                                response,
                                check_name=self.name,
                                scan_id=context.get("scan_id") or "",
                                host=service.host,
                            )
                        )
                    )

                    result.services.append(service)
                    return result

            except Exception as e:
                result.errors.append(f"{url}: {e}")
                continue

        # Couldn't connect via HTTP(S) — preserve original scheme/url
        service.service_type = "tcp"
        result.services.append(service)
        return result

    def _classify_service(self, headers: dict, content_type: str, body: str) -> str:
        """Classify service type based on response characteristics."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        body_lower = body.lower()

        # Check for AI/ML indicators first
        for header in self.AI_HEADERS:
            if any(header in k for k in headers_lower):
                return "ai"

        powered_by = headers_lower.get("x-powered-by", "")
        server = headers_lower.get("server", "")

        for ai_tech in self.AI_POWERED_BY:
            if ai_tech in powered_by or ai_tech in server:
                return "ai"

        # Check body for AI indicators
        ai_body_indicators = [
            "/v1/chat/completions",
            "/v1/completions",
            "/v1/embeddings",
            "chatbot",
            "llm",
            "inference",
            "model",
            "/api/generate",
        ]
        if any(ind in body_lower for ind in ai_body_indicators):
            return "ai"

        # Check content type
        if "text/html" in content_type:
            return "html"
        elif "application/json" in content_type:
            # Could be API or AI - look for more clues
            if any(kw in body_lower for kw in ["openapi", "swagger"]):
                return "api"
            return "api"

        return "http"

    # ══ Grade ════════════════════════════════════════════════════

    #: Headers that are either standard or too common to be worth reporting as a
    #: custom one. `x-powered-by` is excluded because it has its own verdict.
    STANDARD_HEADERS = {
        "x-powered-by",
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
        "x-request-id",
        "x-correlation-id",
        "x-cache",
        "x-cache-hits",
        "x-served-by",
    }

    #: Substrings in a custom header's *name* that raise it from noise to a leak.
    SENSITIVE_HEADER_HINTS = ("model", "token", "key", "secret", "internal", "debug")

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on what one recorded response's headers disclosed."""
        exchange = next(iter(evidence.completed()), None)
        if exchange is None:
            return []

        headers = exchange.response_headers or {}
        headers_lower = {k.lower(): v for k, v in headers.items()}
        evidence_ids = [exchange.id]
        verdicts: list[Verdict] = []

        # ── Server version disclosure ─────────────────────
        server_value = headers_lower.get("server", "")
        if server_value and any(c.isdigit() for c in server_value):
            verdicts.append(
                Verdict(
                    severity="low",
                    # A digit in the Server header is usually a version and
                    # sometimes a CDN's build number, which discloses nothing.
                    confidence=0.8,
                    discriminator="server-version-disclosure",
                    title=f"Server version disclosed: {server_value}",
                    description=(
                        "Server header reveals version information that could aid targeted attacks"
                    ),
                    evidence=f"Server: {server_value}",
                    reasoning="Server header contains digits, read as a version",
                    signals={"server": server_value},
                    references=["CWE-200"],
                    evidence_ids=evidence_ids,
                )
            )

        # ── X-Powered-By ──────────────────────────────────
        powered_by = headers_lower.get("x-powered-by")
        if powered_by:
            ai_tech = [t for t in self.AI_POWERED_BY if t in powered_by.lower()]
            verdicts.append(
                Verdict(
                    # Naming an inference runtime is worth more than naming a web
                    # framework: it tells an attacker which model-layer attacks
                    # are even applicable.
                    severity="medium" if ai_tech else "low",
                    # The header is self-declared and unambiguous.
                    confidence=0.95,
                    discriminator="technology-disclosure",
                    title=f"Technology disclosed: {powered_by}",
                    description="X-Powered-By header reveals technology stack",
                    evidence=f"X-Powered-By: {powered_by}",
                    reasoning=(
                        f"X-Powered-By names an AI/ML runtime ({', '.join(ai_tech)})"
                        if ai_tech
                        else "X-Powered-By names the technology stack"
                    ),
                    signals={"powered_by": powered_by, "ai_tech": ai_tech},
                    references=["CWE-200"],
                    evidence_ids=evidence_ids,
                )
            )

        # ── Custom headers (potential info leaks) ─────────
        for key, value in headers.items():
            key_lower = key.lower()
            if not key_lower.startswith("x-") or key_lower in self.STANDARD_HEADERS:
                continue

            hints = [s for s in self.SENSITIVE_HEADER_HINTS if s in key_lower]
            verdicts.append(
                Verdict(
                    severity="medium" if hints else "info",
                    # The header's presence is certain; that its *name* implies a
                    # leak is an inference from a substring, and a weaker one —
                    # `x-model-version` on a CDN means nothing.
                    confidence=0.6 if hints else 0.9,
                    # Per-header, so several custom headers on one service stay
                    # distinct observations rather than collapsing onto one id.
                    discriminator=f"custom-header-{key_lower}",
                    title=f"Custom header: {key}",
                    description="Custom header may leak internal information",
                    evidence=f"{key}: {value[:100]}",
                    reasoning=(
                        f"Header name contains {', '.join(hints)}"
                        if hints
                        else "Non-standard X- header present"
                    ),
                    signals={"header": key, "hints": hints},
                    evidence_ids=evidence_ids,
                )
            )

        return verdicts
