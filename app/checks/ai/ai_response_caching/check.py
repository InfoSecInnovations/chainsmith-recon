"""
app/checks/ai/ai_response_caching/check.py - Response Caching Detection

Send identical requests and compare responses. If responses are identical
(content and timing), the service may be caching.

**Probe/grade.** The probe sends the same prompt three times
at temperature 0 and, when those come back identical, once more at temperature
2.0, recording all of them; `grade()` re-reads them, compares the bodies, and
returns the cache-header and caching verdicts. `_reading()` is the one parser
both halves call (§0.12). The temperature-2.0 exchange is told from the three
baseline ones by the `temperature` value on its own recorded request, not by
position.

The probe keeps its early exit — it only sends the hot request when the three
cold ones agree — because that decision is a control-flow gate, and it is taken
on the bodies it just recorded (§0.11), so `grade()` reaches the same conclusion
from the same bytes.
"""

from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Candidate, Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.ai_helpers import (
    dialect_from_request,
    format_chat_request_with_extra,
    response_text_from,
)
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json

JSON_HEADERS = {"Content-Type": "application/json"}


class ResponseCachingCheck(BaseCheck):
    """Detect response caching by comparing identical requests."""

    name = "ai_response_caching"
    description = (
        "Detect response caching by comparing identical requests for content and timing patterns"
    )
    intrusive = False

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["cache_detection_results"]

    sequential = True

    reason = "Cached responses may bypass content filters that operate on generation time"
    references = [
        "OWASP LLM Top 10 - LLM01 Prompt Injection",
    ]
    techniques = ["caching detection", "response analysis"]

    TEST_PROMPT = "What is the capital of France? Answer in one sentence."
    REPEAT_COUNT = 3

    # Cache-related headers to look for
    CACHE_HEADERS = [
        "x-cache",
        "x-cache-hit",
        "age",
        "cache-control",
        "cf-cache-status",
        "x-varnish",
        "x-proxy-cache",
        "x-fastly-request-id",
    ]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        for endpoint_info in context.get("chat_endpoints", []):
            url = endpoint_info.get("url")
            if not url:
                continue

            service = Service.from_dict(endpoint_info.get("service", {}))
            api_format = endpoint_info.get("api_format", "unknown")

            try:
                candidate = self.create_candidate(host=service.host, target=service, target_url=url)
                await self._probe_caching(url, api_format, candidate, scan_id)
                result.candidates.append(candidate)

                reading = self._reading(candidate.exchanges)
                if len(reading["cold_responses"]) >= 2:
                    result.outputs[f"cache_detection_{service.port}"] = reading["cache_info"]
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _probe_caching(
        self, url: str, api_format: str, candidate: Candidate, scan_id: str
    ) -> None:
        """Send REPEAT_COUNT cold requests, then a hot one if they agree."""
        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        async with AsyncHttpClient(cfg) as client:
            cold_texts: list[str] = []

            for _ in range(self.REPEAT_COUNT):
                await self._rate_limit()
                body = format_chat_request_with_extra(self.TEST_PROMPT, api_format, temperature=0)
                resp = await client.post(url, json=body, headers=JSON_HEADERS)
                exchange = exchange_from_response(
                    resp,
                    check_name=self.name,
                    scan_id=scan_id,
                    host=candidate.host,
                    method="POST",
                    request_headers=JSON_HEADERS,
                    request_json=body,
                )
                candidate.attach(exchange)
                if not exchange.error and exchange.response_status == 200:
                    cold_texts.append(response_text_from(exchange, api_format))

            # Only worth a hot request if the cold ones were identical — read
            # off the exchanges just recorded.
            if len(cold_texts) >= 2 and len(set(cold_texts)) == 1:
                await self._rate_limit()
                body_hot = format_chat_request_with_extra(
                    self.TEST_PROMPT, api_format, temperature=2.0
                )
                resp_hot = await client.post(url, json=body_hot, headers=JSON_HEADERS)
                candidate.attach(
                    exchange_from_response(
                        resp_hot,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=candidate.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json=body_hot,
                    )
                )

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Cache-header and caching verdicts over the recorded requests."""
        reading = self._reading(list(evidence))
        cold = reading["cold_responses"]
        if len(cold) < 2:
            return []

        ids = evidence.ids()
        cache_info = reading["cache_info"]
        all_identical = reading["all_identical"]
        temp_override_works = reading["temp_override_works"]
        verdicts: list[Verdict] = []

        if cache_info["cache_headers"]:
            header_str = ", ".join(f"{k}: {v}" for k, v in cache_info["cache_headers"].items())
            verdicts.append(
                Verdict(
                    severity="low",
                    # The headers are on the record; the only question is whether
                    # a caching header on an AI response actually means the
                    # completion was cached, or just the HTTP envelope.
                    confidence=0.75,
                    discriminator="cache-headers",
                    title=f"Cache headers present: {header_str[:80]}",
                    description=(
                        "Response includes cache-related headers indicating proxy/CDN caching"
                    ),
                    evidence=f"Headers: {header_str}",
                    reasoning=(
                        "cache-related headers are present verbatim; a CDN may cache the HTTP "
                        "response without the model layer caching the completion, so this reports "
                        "the header rather than concluding the answer was served from cache"
                    ),
                    signals={"cache_headers": cache_info["cache_headers"]},
                    raw_data=cache_info,
                    evidence_ids=ids,
                )
            )

        if all_identical and not temp_override_works:
            verdicts.append(
                Verdict(
                    severity="medium",
                    # Identical output at temperature 0 AND temperature 2.0 is a
                    # strong caching signal — a live model at temp 2.0 diverges.
                    # Short factual prompts are the weak spot: "Paris is the
                    # capital of France." is a near-deterministic completion even
                    # uncached, so the hot-request divergence is what carries it.
                    confidence=0.75,
                    discriminator="caching-detected",
                    title=(
                        "Response caching detected: identical responses override temperature "
                        "parameter"
                    ),
                    description=(
                        "Identical responses returned for same prompt regardless of temperature, "
                        "suggesting HTTP-level or semantic caching. "
                        "Content filter bypass risk if cached responses predate filter updates."
                    ),
                    evidence=(
                        f"Responses: {self.REPEAT_COUNT}/{self.REPEAT_COUNT} identical, "
                        "temperature=2.0 produced same output"
                    ),
                    reasoning=(
                        "output stayed byte-identical even at temperature 2.0, where a live model "
                        "diverges; the prompt is short and factual, so some of the sameness could "
                        "be near-determinism rather than a cache"
                    ),
                    signals=dict(cache_info),
                    references=self.references,
                    raw_data=cache_info,
                    evidence_ids=ids,
                )
            )
        elif all_identical:
            verdicts.append(
                Verdict(
                    severity="info",
                    confidence=0.7,
                    discriminator="no-cache",
                    title=(
                        "No caching detected (deterministic at temperature=0, varies at "
                        "temperature=2.0)"
                    ),
                    description=(
                        "Responses are deterministic at low temperature but vary with high "
                        "temperature, as expected"
                    ),
                    evidence=(
                        f"Responses: {self.REPEAT_COUNT}/{self.REPEAT_COUNT} identical at temp=0, "
                        "different at temp=2.0"
                    ),
                    reasoning=(
                        "identical at temperature 0 but divergent at temperature 2.0 is exactly "
                        "how an uncached model behaves"
                    ),
                    signals=dict(cache_info),
                    evidence_ids=ids,
                )
            )
        else:
            verdicts.append(
                Verdict(
                    severity="info",
                    confidence=0.8,
                    discriminator="no-cache",
                    title="No caching detected (responses vary as expected)",
                    description="Responses vary across identical requests, indicating no caching",
                    evidence=f"Unique responses: {len(set(cold))}/{len(cold)}",
                    reasoning="the same prompt drew different answers, which a cache would not do",
                    signals=dict(cache_info),
                    evidence_ids=ids,
                )
            )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """Split recorded requests into cold (temp 0) and hot (temp 2.0).

        The temperature each request set is read back off its own body, so the
        hot request is identified even if capture reordered the rows.
        """
        cold_responses: list[str] = []
        response_times: list[float] = []
        cache_headers: dict[str, str] = {}
        hot_text: str | None = None

        for exchange in exchanges:
            if exchange.error or exchange.response_status != 200:
                continue

            temperature = self._temperature_of(exchange)
            api_format = dialect_from_request(exchange.request_body or "")
            text = response_text_from(exchange, api_format)

            if temperature == 2.0:
                hot_text = text
                continue

            cold_responses.append(text)
            if exchange.elapsed_ms is not None:
                response_times.append(exchange.elapsed_ms)
            for header in self.CACHE_HEADERS:
                val = (exchange.response_headers or {}).get(header)
                if val:
                    cache_headers[header] = val

        all_identical = len(cold_responses) >= 2 and len(set(cold_responses)) == 1

        # `temp_override_works` is True only when the hot request diverged from
        # the identical cold ones — the original's meaning exactly.
        temp_override_works = bool(
            all_identical and hot_text is not None and hot_text != cold_responses[0]
        )

        cache_info = {
            "identical_responses": all_identical,
            "cache_headers": cache_headers,
            "avg_response_ms": (
                sum(response_times) / len(response_times) if response_times else None
            ),
            "temp_override_works": temp_override_works,
        }

        return {
            "cold_responses": cold_responses,
            "hot_text": hot_text,
            "all_identical": all_identical,
            "temp_override_works": temp_override_works,
            "cache_info": cache_info,
        }

    def _temperature_of(self, exchange: Exchange) -> float | None:
        """The temperature a recorded request set, if any."""
        body = safe_json(exchange.request_body or "")
        if isinstance(body, dict):
            temp = body.get("temperature")
            if isinstance(temp, (int, float)):
                return float(temp)
        return None
