"""
app/checks/ai/ai_context_window_check/check.py - Context Window Probing

Estimate context window limits and token handling behavior.

**Probe/grade.** The probe sends four prompts of increasing
size until one is refused and records every attempt; `grade()` re-reads them
and reports where the wall was. This is a "one parser, called twice" check
(§0.12): `_reading()` turns recorded exchanges into the `context_info` shape,
and `run()` calls it for the output while `grade()` calls it for the verdict.

The probe still stops early, because sending 4000 tokens to an endpoint that
refused 500 is wasted traffic — but the value it stops on is read off the
exchange it just recorded, not off the live response, so there is one
representation of what the target said (§0.11).

Which size a given exchange tested is recovered from the recorded request, not
from the loop that sent it: `_TOKENS_BY_PAYLOAD_LEN` is derived from
`TEST_SIZES` itself, so the prompt's own length identifies its row and editing
`TEST_SIZES` cannot put the two out of step.
"""

from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Candidate, Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.ai_helpers import (
    fmt_context_evidence,
    format_chat_request,
    prompt_from_request,
)
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import safe_json

JSON_HEADERS = {"Content-Type": "application/json"}

#: The prefix every probe prompt carries, so the payload can be measured
#: without it.
PROMPT_PREFIX = "Summarize: "


class ContextWindowCheck(BaseCheck):
    """Probe context window limits."""

    name = "ai_context_window_check"
    description = "Estimate context window size and token limits"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["context_info"]

    sequential = True

    reason = "Context limits affect prompt injection payload sizes and conversation hijacking"
    references = ["OWASP LLM Top 10"]
    techniques = ["context probing", "token estimation"]

    TEST_SIZES = [
        (100, "A" * 400),
        (500, "word " * 500),
        (2000, "test " * 2000),
        (4000, "data " * 4000),
    ]

    #: Payload length -> the token estimate that length stands for. Derived from
    #: `TEST_SIZES` so `grade()` can identify a recorded prompt's row without
    #: being told the order they were sent in.
    _TOKENS_BY_PAYLOAD_LEN = {len(payload): tokens for tokens, payload in TEST_SIZES}

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
                candidate = self.create_candidate(
                    host=service.host,
                    discriminator="context-window",
                    target=service,
                    target_url=url,
                )
                await self._probe_context(url, api_format, candidate, scan_id)
                result.candidates.append(candidate)

                # `context_{port}` has to exist by the time the next check runs,
                # so the probe parses its own exchanges with the same function
                # `grade()` calls over the stored copies.
                result.outputs[f"context_{service.port}"] = self._reading(candidate.exchanges)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _probe_context(
        self, url: str, api_format: str, candidate: Candidate, scan_id: str
    ) -> None:
        """Send increasing payloads until one is refused, recording each."""
        cfg = HttpConfig(timeout_seconds=30.0, verify_ssl=False)
        async with AsyncHttpClient(cfg) as client:
            for _token_estimate, payload in self.TEST_SIZES:
                await self._rate_limit()

                request = format_chat_request(f"{PROMPT_PREFIX}{payload}", api_format)
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

                # Stop on the first refusal, reading the answer off the record.
                if exchange.error or exchange.response_status != 200:
                    break

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Report the largest payload the endpoint accepted.

        Only the positive claim is reported, exactly as before the split: an
        endpoint that refused the smallest payload produces no observation,
        because "we learned nothing about the window" is not a finding.
        """
        reading = self._reading(list(evidence))
        if reading["max_successful"] <= 0:
            return []

        confidence, why = self._confidence_for(reading)

        return [
            Verdict(
                severity="info",
                confidence=confidence,
                discriminator="context-window",
                title=f"Context window: ~{reading['max_successful']}+ tokens",
                description=(
                    f"Successfully processed ~{reading['max_successful']} tokens"
                    + (f", failed at ~{reading['failed_at']}" if reading["failed_at"] else "")
                ),
                evidence=fmt_context_evidence(
                    reading["max_successful"],
                    reading["failed_at"],
                    reading["error_type"],
                ),
                reasoning=why,
                signals=dict(reading),
                references=["OWASP LLM Top 10"],
                evidence_ids=evidence.ids(),
            )
        ]

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """The `context_info` shape, read off recorded exchanges.

        The original ladder, unchanged: a 200 raises `max_successful`, anything
        else sets `failed_at` and classifies the refusal. Each exchange's size
        comes from its own recorded prompt rather than from the send order.
        """
        reading: dict[str, Any] = {
            "max_successful": 0,
            "failed_at": None,
            "error_type": None,
        }

        for exchange in exchanges:
            tokens = self._tokens_for(exchange)
            if tokens is None:
                continue

            if exchange.error:
                reading["failed_at"] = tokens
                reading["error_type"] = "connection_error"
                break

            if exchange.response_status == 200:
                reading["max_successful"] = tokens
                continue

            reading["failed_at"] = tokens
            body = safe_json(exchange.response_body or "") or {}
            body_str = str(body).lower()
            if "context" in body_str or "token" in body_str:
                reading["error_type"] = "context_limit"
            else:
                reading["error_type"] = "other"
            break

        return reading

    def _tokens_for(self, exchange: Exchange) -> int | None:
        """Which `TEST_SIZES` row this exchange tested, from its own request."""
        prompt = prompt_from_request(exchange.request_body or "")
        if not prompt:
            return None
        payload = prompt[len(PROMPT_PREFIX) :] if prompt.startswith(PROMPT_PREFIX) else prompt
        return self._TOKENS_BY_PAYLOAD_LEN.get(len(payload))

    def _confidence_for(self, reading: dict) -> tuple[float, str]:
        """How sure the window estimate is, and why it is not 1.0.

        Never high, and the reason is in the claim itself: this is four
        samples on a logarithmic ladder, so the answer is a floor with a wide
        bracket rather than a measurement. `~500+ tokens` after a refusal at
        2000 locates the wall somewhere in a 1500-token span. And the token
        counts are estimates over character counts, not a tokeniser's output —
        `"word " * 500` is 500 words but not 500 tokens in any real model.

        What moves the number is *why* the next size failed. A refusal whose
        body mentions context or tokens is the endpoint telling us we found
        its limit. A 500 or a dropped connection at 4000 tokens is as likely
        to be a timeout, a proxy body cap, or a gateway giving up — the window
        may be far larger than the probe could show.
        """
        top = reading["max_successful"] == self.TEST_SIZES[-1][0]
        error_type = reading["error_type"]

        if top:
            return 0.6, (
                f"every payload up to ~{reading['max_successful']} tokens was accepted, so this "
                "is a floor with no upper bound measured at all — the probe ran out of sizes, "
                "not the endpoint out of context"
            )
        if error_type == "context_limit":
            return 0.75, (
                f"the refusal at ~{reading['failed_at']} names context or tokens, so the wall is "
                "the endpoint's own; the estimate is still a four-sample ladder, and the token "
                "counts are character-count approximations rather than a tokeniser's"
            )
        if error_type == "connection_error":
            return 0.4, (
                f"the probe at ~{reading['failed_at']} tokens failed to connect, which a timeout, "
                "a proxy body cap or a gateway giving up produces just as readily as a context "
                "limit — the real window may be much larger"
            )
        return 0.5, (
            f"the refusal at ~{reading['failed_at']} tokens said nothing about context or tokens, "
            "so the cause is unattributed; it could be a body-size limit anywhere in front of the "
            "model"
        )
