"""
app/checks/ai/ai_rate_limit_check/check.py - Rate Limit Detection

Map rate limiting behavior and identify bypass opportunities.

**Probe/grade.** The probe sends twelve identical requests
as fast as the delay allows and records each; `grade()` re-reads the sequence
and decides whether anything throttled it. `_reading()` is the one parser both
halves call (§0.12), because `rate_limit_info` has to exist for downstream
checks.

**This is the one check in the suite where the order of the exchanges is the
measurement.** Everywhere else a grader reads each exchange's own request to
know what it is looking at; here the question is *how many requests in* the
429 arrived, so the threshold is the 429's position in the recorded sequence.
That is not positional pairing against a list the probe remembers — the
sequence itself is the evidence, and it is on the record.
"""

import asyncio
from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Candidate, Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.ai_helpers import fmt_rate_limit_evidence, format_chat_request
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict

JSON_HEADERS = {"Content-Type": "application/json"}

#: The headers that say a limiter exists even when it did not fire.
RATE_LIMIT_HEADERS = ("x-ratelimit-limit", "x-ratelimit-remaining", "retry-after")


class RateLimitCheck(BaseCheck):
    """Detect and map rate limiting behavior."""

    name = "ai_rate_limit_check"
    description = "Detect rate limiting thresholds and bypass opportunities"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["rate_limit_info"]

    sequential = True

    reason = "Understanding rate limits helps plan attacks and identify DoS vectors"
    references = ["OWASP API4:2023 - Unrestricted Resource Consumption"]
    techniques = ["rate limit testing", "resource exhaustion", "bypass techniques"]

    TEST_REQUESTS = 12
    REQUEST_DELAY = 0.08

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
                # No discriminator: which of the three judgements applies is the
                # grader's call, and an ungraded candidate should not claim one.
                candidate = self.create_candidate(host=service.host, target=service, target_url=url)
                await self._burst(url, api_format, candidate, scan_id)
                result.candidates.append(candidate)

                result.outputs[f"rate_limit_{service.port}"] = self._reading(candidate.exchanges)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _burst(self, url: str, api_format: str, candidate: Candidate, scan_id: str) -> None:
        """Send `TEST_REQUESTS` requests, recording each, stopping on a 429."""
        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        async with AsyncHttpClient(cfg) as client:
            for _ in range(self.TEST_REQUESTS):
                request = format_chat_request("Hi", api_format, max_tokens=5)
                resp = await client.post(url, json=request, headers=JSON_HEADERS)

                exchange = exchange_from_response(
                    resp,
                    check_name=self.name,
                    scan_id=scan_id,
                    host=candidate.host,
                    method="POST",
                    request_headers=JSON_HEADERS,
                    request_json=request,
                )
                candidate.attach(exchange)

                if not exchange.error and exchange.response_status == 429:
                    break

                await asyncio.sleep(self.REQUEST_DELAY)

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """One of three judgements about the recorded burst.

        The original ladder, unchanged: a 429 is `rate-limit-detected`, headers
        without a 429 are `rate-limit-headers`, and neither is `no-rate-limit`
        — the only one of the three that is not `info`, because an unthrottled
        model endpoint is a bill someone else can run up.
        """
        exchanges = list(evidence)
        reading = self._reading(exchanges)
        sent = len([e for e in exchanges if not e.error])

        if reading["detected"]:
            confidence, why = self._confidence_detected(reading)
            return [
                Verdict(
                    severity="info",
                    confidence=confidence,
                    discriminator="rate-limit-detected",
                    title=(f"Rate limiting detected (threshold: ~{reading['threshold']} requests)"),
                    description="Endpoint enforces rate limiting",
                    evidence=fmt_rate_limit_evidence(reading["threshold"], 429, reading["headers"]),
                    reasoning=why,
                    signals=dict(reading),
                    evidence_ids=evidence.ids(),
                )
            ]

        if reading["headers"]:
            return [
                Verdict(
                    severity="info",
                    confidence=0.9,
                    discriminator="rate-limit-headers",
                    title="Rate limit headers present",
                    description="Rate limiting configured but threshold not reached in testing",
                    evidence=fmt_rate_limit_evidence(self.TEST_REQUESTS, 200, reading["headers"]),
                    reasoning=(
                        "the endpoint advertises a limiter in its own headers "
                        f"({', '.join(sorted(reading['headers']))}) but did not reach it in "
                        f"{self.TEST_REQUESTS} requests — the headers are the claim, not the test"
                    ),
                    signals=dict(reading),
                    evidence_ids=evidence.ids(),
                )
            ]

        confidence, why = self._confidence_absent(sent)
        return [
            Verdict(
                severity="medium",
                confidence=confidence,
                discriminator="no-rate-limit",
                title="No rate limiting detected",
                description=(
                    f"No rate limiting after {self.TEST_REQUESTS} requests — potential DoS vector"
                ),
                evidence=fmt_rate_limit_evidence(self.TEST_REQUESTS, 200, {}),
                reasoning=why,
                signals=dict(reading, requests_completed=sent),
                references=["OWASP API4:2023"],
                evidence_ids=evidence.ids(),
            )
        ]

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """The `rate_limit_info` shape, read off the recorded burst.

        `threshold` is the 429's index in the sequence, which is what the
        original loop variable `i` held.
        """
        reading: dict[str, Any] = {"detected": False, "threshold": None, "headers": {}}

        for index, exchange in enumerate(exchanges):
            if exchange.error:
                continue

            headers_lower = extract_headers_dict(exchange.response_headers or {})
            for header in RATE_LIMIT_HEADERS:
                if header in headers_lower:
                    reading["headers"][header] = headers_lower[header]

            if exchange.response_status == 429:
                reading["detected"] = True
                reading["threshold"] = index
                break

        return reading

    def _confidence_detected(self, reading: dict) -> tuple[float, str]:
        """A 429 came back. The limiter exists; the *threshold* is the soft part."""
        if reading["headers"]:
            return 0.95, (
                "a 429 plus the endpoint's own rate-limit headers; the threshold is still only "
                f"the request count this burst reached ({reading['threshold']}), not a configured "
                "value, and it depends on whatever quota was already spent before the scan"
            )
        return 0.85, (
            f"a 429 at request {reading['threshold']} is a limiter firing, but with no "
            "rate-limit headers to corroborate it the 429 could also come from a shared "
            "gateway or WAF rather than this endpoint's own quota"
        )

    def _confidence_absent(self, sent: int) -> tuple[float, str]:
        """Nothing throttled twelve requests. This is the weakest claim here.

        An absence bounded by how small the search was — the web suite's other
        recurring softener (§0.13), and this search is very small. Twelve
        requests at 80 ms apart is under two seconds of traffic from one source
        address; a per-minute or per-hour quota, a per-key quota, or a limiter
        that only sheds load under real pressure all look exactly like no
        limiter at all from here.
        """
        if sent < self.TEST_REQUESTS:
            return 0.3, (
                f"only {sent} of {self.TEST_REQUESTS} requests completed, so the burst never "
                "reached full rate — an absence of throttling across a burst that did not "
                "happen says very little"
            )
        return 0.5, (
            f"{sent} requests in about {sent * self.REQUEST_DELAY:.1f}s from one address drew no "
            "429 and no rate-limit headers; a per-minute, per-hour or per-key quota would not "
            "have fired in that window either, so this bounds the limit rather than disproving one"
        )
