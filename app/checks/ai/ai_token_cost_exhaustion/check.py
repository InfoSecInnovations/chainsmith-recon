"""
app/checks/ai/ai_token_cost_exhaustion/check.py - Token/Cost Exhaustion Probes

Test if expensive operations can be triggered beyond simple rate limiting.

**Probe/grade.** The probe sends four cost-exhaustion
payloads and records the answers; `grade()` re-reads them, sorts accepted from
rejected, and walks the original ladder. Which of the four tests a recorded
exchange carried is identified from its own request — the `max_tokens` value it
set, or the oversized prompt of the input-cost test — rather than from the send
order. `_reading()` is the one parser both halves call (§0.12).
"""

from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Candidate, Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.ai_helpers import format_chat_request_with_extra, prompt_from_request
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json

JSON_HEADERS = {"Content-Type": "application/json"}

#: The tests whose acceptance means no output cap is enforced at all.
EXTREME_TESTS = ("max_tokens_extreme", "max_tokens_high")


class TokenCostExhaustionCheck(BaseCheck):
    """Test for missing output token limits and cost exhaustion vectors."""

    name = "ai_token_cost_exhaustion"
    description = "Test if expensive completions can be triggered without token limits"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["token_cost_info"]

    sequential = True

    reason = "On pay-per-token services, missing output caps allow cost exhaustion attacks"
    references = [
        "OWASP LLM Top 10 - LLM04 Model Denial of Service",
    ]
    techniques = ["denial of service", "cost exhaustion", "resource abuse"]

    # Tests: (name, extra_params, prompt, description)
    COST_TESTS = [
        (
            "max_tokens_extreme",
            {"max_tokens": 100000},
            "Say hello.",
            "Extreme max_tokens value accepted",
        ),
        (
            "max_tokens_high",
            {"max_tokens": 10000},
            "Say hello.",
            "High max_tokens value accepted",
        ),
        (
            "verbose_output",
            {"max_tokens": 4096},
            "Write an extremely detailed 5000 word essay about the history of paperclips. "
            "Include every possible detail.",
            "Verbose output request accepted without truncation",
        ),
        (
            "large_system_prompt",
            {},
            "A" * 8000 + " What is 2+2?",
            "Large input accepted (input token cost)",
        ),
    ]

    #: max_tokens value -> the test that uses it, for reading a recorded
    #: exchange's test back off its request. `large_system_prompt` sets no
    #: max_tokens and is identified by its oversized prompt instead.
    _TEST_BY_MAX_TOKENS = {
        params["max_tokens"]: name
        for name, params, _prompt, _desc in COST_TESTS
        if "max_tokens" in params
    }
    _DESC_BY_TEST = {name: desc for name, _p, _pr, desc in COST_TESTS}
    _LARGE_INPUT_TEST = "large_system_prompt"

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
                await self._probe_cost(url, api_format, candidate, scan_id)
                result.candidates.append(candidate)

                result.outputs[f"token_cost_{service.port}"] = self._reading(candidate.exchanges)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _probe_cost(
        self, url: str, api_format: str, candidate: Candidate, scan_id: str
    ) -> None:
        """Send each cost payload, recording every response."""
        cfg = HttpConfig(timeout_seconds=30.0, verify_ssl=False)
        async with AsyncHttpClient(cfg) as client:
            for _test_name, extra_params, prompt, _desc in self.COST_TESTS:
                await self._rate_limit()

                body = format_chat_request_with_extra(prompt, api_format, **extra_params)
                resp = await client.post(url, json=body, headers=JSON_HEADERS)

                candidate.attach(
                    exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=candidate.host,
                        method="POST",
                        request_headers=JSON_HEADERS,
                        request_json=body,
                    )
                )

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Walk the original cost-exhaustion ladder over the recorded attempts."""
        reading = self._reading(list(evidence))
        accepted = reading["accepted"]
        rejected = reading["rejected"]
        ids = evidence.ids()

        if any(t in EXTREME_TESTS for t in accepted):
            confidence, why = self._confidence_extreme(reading)
            return [
                Verdict(
                    severity="high",
                    confidence=confidence,
                    discriminator="no-token-limit",
                    title="No output token limit enforced",
                    description=(
                        "Endpoint accepted extreme max_tokens values — cost exhaustion possible"
                    ),
                    evidence=f"Accepted: {', '.join(accepted)}",
                    reasoning=why,
                    signals=dict(reading),
                    references=self.references,
                    raw_data=dict(reading),
                    evidence_ids=ids,
                )
            ]

        if accepted:
            return [
                Verdict(
                    severity="medium",
                    confidence=0.6,
                    discriminator="large-completions",
                    title=f"Large completions accepted ({len(accepted)} tests)",
                    description="Some expensive operations are possible",
                    evidence=f"Accepted: {', '.join(accepted)}",
                    reasoning=(
                        "the endpoint accepted a verbose or large-input request without an "
                        "extreme max_tokens; the cost is real but bounded by the model's own "
                        "output length, not by an operator-set cap"
                    ),
                    signals=dict(reading),
                    raw_data=dict(reading),
                    evidence_ids=ids,
                )
            ]

        return [
            Verdict(
                severity="info",
                confidence=0.75,
                discriminator="token-limits-ok",
                title="Token limits enforced",
                description="Cost exhaustion tests were rejected",
                evidence=f"Rejected: {', '.join(rejected)}",
                reasoning=(
                    "every cost payload drew a 400/413/422 or other non-200; the endpoint caps "
                    "expensive requests"
                ),
                signals=dict(reading),
                evidence_ids=ids,
            )
        ]

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """Sort recorded attempts into accepted (200) and rejected, per test."""
        accepted: list[str] = []
        rejected: list[str] = []
        usage_exposed = False

        for exchange in exchanges:
            test = self._test_of(exchange)
            if test is None or exchange.error:
                continue

            if exchange.response_status == 200:
                accepted.append(test)
                body = safe_json(exchange.response_body or "") or {}
                usage = body.get("usage")
                if isinstance(usage, dict):
                    usage_exposed = True
            else:
                # 400/413/422 or any other non-200 was a rejection before the
                # split, and stays one.
                rejected.append(test)

        return {"accepted": accepted, "rejected": rejected, "usage_exposed": usage_exposed}

    def _test_of(self, exchange: Exchange) -> str | None:
        """Which cost test a recorded request carried."""
        body = safe_json(exchange.request_body or "")
        if isinstance(body, dict):
            max_tokens = body.get("max_tokens")
            if max_tokens in self._TEST_BY_MAX_TOKENS:
                return self._TEST_BY_MAX_TOKENS[max_tokens]

        prompt = prompt_from_request(exchange.request_body or "")
        if prompt.count("A") >= 8000:
            return self._LARGE_INPUT_TEST
        return None

    def _confidence_extreme(self, reading: dict) -> tuple[float, str]:
        """How sure "no output cap" is, and why it is not 1.0.

        Accepting `max_tokens: 100000` with a 200 is close to conclusive: the
        endpoint took a value far above any real output and did not object.
        `usage` in the body strengthens it, because it confirms the request was
        actually served rather than queued and dropped. The residual doubt is
        that a 200 says the parameter was *accepted*, not that a 100k-token
        completion would actually be *generated and billed* — a gateway may
        clamp it downstream without saying so.
        """
        if reading["usage_exposed"]:
            return 0.9, (
                "an extreme max_tokens was accepted with 200 and the response reported usage, "
                "so the request was served; a downstream clamp is still possible but the cap is "
                "not enforced at the API"
            )
        return 0.8, (
            "an extreme max_tokens was accepted with 200; the parameter was not rejected, though "
            "a 200 does not prove a completion that large would actually be generated and billed"
        )
