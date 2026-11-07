"""
app/checks/ai/ai_framework_fingerprint/check.py - AI Framework Fingerprinting

Identify the AI/ML framework powering a service.

**Probe/grade.** The probe makes the eleven requests the
fingerprint rests on — the root page, nine well-known paths, and one
deliberately invalid POST to harvest an error message — and records them.
`grade()` re-reads those exchanges, rebuilds the evidence bundle the signature
table scores against, and returns the one verdict. The whole scoring engine
moved to the grade side unchanged, which is what §6.2 predicts for a check
whose probe does not branch on what it finds.

This is the check in the suite where the split has the most substance, because
the old code already had a notion of confidence and could not express it: it
graded its own score into the strings `"high"`, `"medium"` and `"low"`, wrote
that word into the description, and then asserted `medium` severity with no
measure attached. That string is now a real number on the verdict, and it is
computed from *which kinds* of signal matched rather than from their total —
a `x-vllm` response header and the substring `ollama` appearing somewhere in
5 KB of concatenated HTML both scored points before, and they are not
comparable evidence.
"""

import re
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict

#: The paths the probe asks for beyond the root. Kept as a module constant so
#: `grade()` can tell an "accessible endpoint" signal from the root page.
TEST_ENDPOINTS = [
    "/v1/models",
    "/api/tags",
    "/info",
    "/health",
    "/docs",
    "/invoke",
    "/generate",
    "/_stcore/health",
    "/v2/health",
]

#: Sent at the root to provoke a framework-shaped error message.
ERROR_PAYLOAD = {"invalid": "request"}
JSON_HEADERS = {"Content-Type": "application/json"}

#: Body caps, preserved exactly from before the split — the signature table
#: scores against this much text and no more, so changing them would change
#: which frameworks match.
ROOT_BODY_CAP = 5000
ENDPOINT_BODY_CAP = 1000
ERROR_BODY_CAP = 2000


class AIFrameworkFingerprintCheck(ServiceIteratingCheck):
    """Fingerprint AI/ML frameworks from response characteristics."""

    name = "ai_framework_fingerprint"
    description = "Identify AI framework (vLLM, Ollama, LangChain, etc.) from responses"

    conditions = [CheckCondition("services", "truthy"), CheckCondition("services_probed", "truthy")]
    produces = ["ai_framework"]
    service_types = ["ai", "api"]

    reason = "Knowing the AI framework enables targeted attacks against known vulnerabilities"
    references = ["MITRE ATLAS - ML Supply Chain Compromise"]
    techniques = ["fingerprinting", "technology identification", "version detection"]

    FRAMEWORK_SIGNATURES = {
        "vllm": {
            "headers": ["x-vllm", "vllm"],
            "body_patterns": [r"vllm", r"vllm_version"],
            "endpoints": ["/v1/models", "/v1/completions"],
            "error_patterns": [r"vLLM", r"AsyncLLMEngine"],
        },
        "ollama": {
            "headers": ["x-ollama"],
            "body_patterns": [r"ollama", r"modelfile"],
            "endpoints": ["/api/generate", "/api/tags", "/api/show"],
            "error_patterns": [r"ollama", r"Modelfile"],
        },
        "langserve": {
            "headers": ["x-langserve"],
            "body_patterns": [r"langserve", r"langchain"],
            "endpoints": ["/invoke", "/stream", "/batch", "/input_schema"],
            "error_patterns": [r"LangServe", r"LangChain", r"RunnableSequence"],
        },
        "huggingface_tgi": {
            "headers": ["x-inference-time"],
            "body_patterns": [r"text-generation-inference", r"generated_text"],
            "endpoints": ["/generate", "/generate_stream", "/info"],
            "error_patterns": [r"TGI", r"text-generation-inference"],
        },
        "triton": {
            "headers": ["x-triton"],
            "body_patterns": [r"triton", r"nvidia"],
            "endpoints": ["/v2/models", "/v2/health"],
            "error_patterns": [r"Triton", r"NVIDIA"],
        },
        "openai_compatible": {
            "headers": [],
            "body_patterns": [r'"object":\s*"(chat\.completion|list)"'],
            "endpoints": ["/v1/chat/completions", "/v1/models"],
            "error_patterns": [r"invalid_api_key", r"invalid_request_error"],
        },
        "fastapi_ml": {
            "headers": [],
            "body_patterns": [r"fastapi", r"starlette"],
            "endpoints": ["/docs", "/openapi.json", "/predict"],
            "error_patterns": [r"FastAPI", r"RequestValidationError"],
        },
        "gradio": {
            "headers": [],
            "body_patterns": [r"gradio", r"__gradio"],
            "endpoints": ["/api/predict", "/queue/join"],
            "error_patterns": [r"gradio", r"Gradio"],
        },
        "streamlit": {
            "headers": ["x-streamlit"],
            "body_patterns": [r"streamlit", r"_stcore"],
            "endpoints": ["/_stcore/health", "/_stcore/stream"],
            "error_patterns": [r"streamlit", r"Streamlit"],
        },
    }

    #: The score a framework needs before it is reported at all, and the two
    #: thresholds the old code turned into words. Unchanged.
    MIN_SCORE = 3
    HIGH_SCORE = 6
    MEDIUM_SCORE = 4

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        candidate = self.create_candidate(host=service.host, target=service)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                root = await client.get(service.url)
                candidate.attach(
                    exchange_from_response(
                        root, check_name=self.name, scan_id=scan_id, host=service.host
                    )
                )

                for endpoint in TEST_ENDPOINTS:
                    resp = await client.get(service.with_path(endpoint))
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

                err_resp = await client.post(service.url, json=ERROR_PAYLOAD, headers=JSON_HEADERS)
                candidate.attach(
                    exchange_from_response(
                        err_resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=service.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json=ERROR_PAYLOAD,
                    )
                )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")
            return result

        # `ai_framework_{port}` has to exist by the time the next check runs, so
        # the probe scores its own exchanges — the same two functions `grade()`
        # calls over the stored copies (§0.12).
        scores = self._score(self._evidence_from(candidate.exchanges, service.url))
        best = self._best(scores)
        if best:
            result.outputs[f"ai_framework_{service.port}"] = {
                "framework": best,
                "confidence": self._score_word(scores[best]["score"]),
                "all_detected": list(scores.keys()),
            }

        result.candidates.append(candidate)
        return result

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """One verdict: which framework the eleven recorded responses point at.

        A fingerprint is a single claim, so there is one verdict even though
        several frameworks may have scored — the runners-up go into `signals`,
        where they belong, and into the confidence, because a close second is
        precisely what makes the first uncertain.
        """
        root_url = ctx.target.url if ctx.target else (ctx.target_url or "")
        bundle = self._evidence_from(list(evidence), root_url)
        scores = self._score(bundle)

        best = self._best(scores)
        if not best:
            return []

        matches = scores[best]["matches"]
        score = scores[best]["score"]
        confidence, why = self._confidence_for(best, scores)

        return [
            Verdict(
                severity="medium",
                confidence=confidence,
                discriminator=f"framework-{best}",
                title=f"AI framework identified: {best}",
                description=(
                    f"Service appears to be running {best} ({self._score_word(score)} confidence)"
                ),
                evidence=f"Matches: {', '.join(matches[:5])}",
                reasoning=why,
                signals={
                    "framework": best,
                    "score": score,
                    "matches": matches,
                    "runners_up": {
                        name: detail["score"] for name, detail in scores.items() if name != best
                    },
                },
                references=["MITRE ATLAS - ML Supply Chain Compromise"],
                raw_data={
                    "framework": best,
                    "confidence": self._score_word(score),
                    "score": score,
                    "all_scores": scores,
                },
                evidence_ids=evidence.ids(),
            )
        ]

    # ── The parsers both halves share ────────────────────────────────

    def _evidence_from(self, exchanges: list[Exchange], root_url: str) -> dict:
        """Rebuild the evidence bundle from recorded exchanges.

        The same four fields `_gather_evidence` used to assemble live, and the
        same caps, so the signature table scores identically. Which exchange is
        which is read off the record rather than remembered from the loop: the
        POST is the error probe, the GET at the root is the root page, and every
        other GET is an endpoint test.
        """
        bundle: dict[str, Any] = {
            "headers": [],
            "body": "",
            "accessible_endpoints": [],
            "errors": "",
        }
        root = root_url.rstrip("/")

        for exchange in exchanges:
            body = exchange.response_body or ""

            if exchange.request_method == "POST":
                # The invalid-request probe: only a 4xx/5xx body is evidence,
                # because a framework that accepted the junk told us nothing.
                if not exchange.error and (exchange.response_status or 0) >= 400:
                    bundle["errors"] = body[:ERROR_BODY_CAP]
                continue

            if exchange.error:
                continue

            url = (exchange.request_url or "").rstrip("/")
            if url == root:
                bundle["headers"] = list(
                    extract_headers_dict(exchange.response_headers or {}).keys()
                )
                bundle["body"] = body[:ROOT_BODY_CAP] + bundle["body"]
                continue

            if (exchange.response_status or 500) < 500:
                endpoint = url[len(root) :] or "/"
                bundle["accessible_endpoints"].append(endpoint)
                bundle["body"] += body[:ENDPOINT_BODY_CAP]

        return bundle

    def _score(self, bundle: dict) -> dict[str, dict]:
        """Score every framework against the evidence bundle. Unchanged logic."""
        scores: dict[str, dict] = {}

        for framework, sigs in self.FRAMEWORK_SIGNATURES.items():
            score = 0
            matches = []
            kinds = set()

            for header_pattern in sigs["headers"]:
                if any(header_pattern.lower() in h for h in bundle["headers"]):
                    score += 3
                    matches.append(f"header: {header_pattern}")
                    kinds.add("header")

            for pattern in sigs["body_patterns"]:
                if re.search(pattern, bundle["body"], re.I):
                    score += 2
                    matches.append(f"body: {pattern}")
                    kinds.add("body")

            for endpoint in sigs["endpoints"]:
                if endpoint in bundle["accessible_endpoints"]:
                    score += 2
                    matches.append(f"endpoint: {endpoint}")
                    kinds.add("endpoint")

            for pattern in sigs["error_patterns"]:
                if re.search(pattern, bundle["errors"], re.I):
                    score += 2
                    matches.append(f"error: {pattern}")
                    kinds.add("error")

            if score > 0:
                scores[framework] = {"score": score, "matches": matches, "kinds": sorted(kinds)}

        return scores

    def _best(self, scores: dict[str, dict]) -> str | None:
        """The highest-scoring framework, if it clears `MIN_SCORE`."""
        if not scores:
            return None
        best = max(scores, key=lambda k: scores[k]["score"])
        return best if scores[best]["score"] >= self.MIN_SCORE else None

    def _score_word(self, score: int) -> str:
        """The old three-word confidence, kept because it is in the description
        text an operator has been reading since before this check was split."""
        if score >= self.HIGH_SCORE:
            return "high"
        return "medium" if score >= self.MEDIUM_SCORE else "low"

    def _confidence_for(self, best: str, scores: dict[str, dict]) -> tuple[float, str]:
        """How sure the fingerprint is, and why it is not 1.0.

        Derived from the *kind* of signal that matched rather than the total,
        because the three kinds are not comparable evidence and the score adds
        them as if they were. A vendor-specific response header is close to
        conclusive — nothing but vLLM emits `x-vllm`. An error message naming
        `AsyncLLMEngine` is nearly as good. A body regex is the weakest by a
        distance: the bundle is 5 KB of root page concatenated with nine other
        responses, so `ollama` or `nvidia` appearing *anywhere* in it scores,
        including in a link, a footer, or another framework's documentation.

        The second reason to be unsure is a close runner-up. The signature sets
        overlap by construction — `/v1/models` is both vLLM's and
        openai_compatible's, and anything OpenAI-shaped matches both — so a
        one-point margin means the table could not really separate them, and
        the verdict says so instead of picking silently.
        """
        kinds = set(scores[best]["kinds"])
        others = [detail["score"] for name, detail in scores.items() if name != best]
        margin = scores[best]["score"] - (max(others) if others else 0)

        if "header" in kinds:
            base, why = 0.9, f"a vendor-specific response header identifies {best} directly"
        elif "error" in kinds and "endpoint" in kinds:
            base, why = (
                0.85,
                (
                    f"{best}'s own error text plus at least one of its endpoints — two independent "
                    "signals"
                ),
            )
        elif "error" in kinds:
            base, why = 0.8, f"the error message names {best}, which only {best} emits"
        elif "endpoint" in kinds and "body" in kinds:
            base, why = 0.7, f"{best}'s endpoints answered and its markers appear in a body"
        elif "endpoint" in kinds:
            base, why = (
                0.6,
                (
                    f"only {best}'s endpoint paths matched; several frameworks share paths like "
                    "/v1/models and /health"
                ),
            )
        else:
            base, why = (
                0.45,
                (
                    f"only a body pattern matched, searched across 5 KB of root page concatenated "
                    f"with nine other responses — the string can be anywhere in it, including a "
                    f"link or a footer that merely mentions {best}"
                ),
            )

        if others and margin <= 1:
            runner = max(scores, key=lambda k: -1 if k == best else scores[k]["score"])
            return min(base, 0.4), (
                f"{why}; but {runner} scored within {margin} point of {best} and the signature "
                "sets overlap, so the table could not separate them"
            )

        return base, why
