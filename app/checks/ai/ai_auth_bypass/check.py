"""
app/checks/ai/ai_auth_bypass/check.py - API Key/Auth Bypass on AI Endpoints

Test discovered chat endpoints with various authentication states to
identify auth bypass vulnerabilities.

**Probe/grade.** The probe sends the same prompt under eight
auth states and records each; `grade()` re-reads them, sorts the accepted states
from the rejected, and walks the original severity ladder. `_reading()` is the
one parser both halves call (§0.12). Which auth state a recorded exchange
carried is read back off its `Authorization` request header, not remembered from
the loop — the state *is* the request, so the record is authoritative.
"""

from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.grading import Candidate, Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.ai_helpers import format_chat_request
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}


class AuthBypassCheck(BaseCheck):
    """Test AI endpoint authentication for bypass vulnerabilities."""

    name = "ai_auth_bypass"
    description = "Test AI endpoints with various auth states to detect bypass vulnerabilities"
    intrusive = True

    conditions = [CheckCondition("chat_endpoints", "truthy")]
    produces = ["auth_status"]

    sequential = True

    reason = "Many internal AI services have no auth or accept any key"
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "OWASP API Security Top 10 - API2 Broken Authentication",
    ]
    techniques = ["auth bypass", "credential testing"]

    # Auth states to test: (label, headers_dict)
    AUTH_TESTS = [
        ("no_auth", {}),
        ("empty_bearer", {"Authorization": "Bearer "}),
        ("default_sk_test", {"Authorization": "Bearer sk-test"}),
        ("default_demo", {"Authorization": "Bearer demo"}),
        ("default_empty_key", {"Authorization": "Bearer EMPTY"}),
        ("default_test_key", {"Authorization": "Bearer test-key"}),
        ("default_no_key", {"Authorization": "Bearer sk-no-key-required"}),
        ("basic_test", {"Authorization": "Basic dGVzdDp0ZXN0"}),
    ]

    #: The `Authorization` value each label sends, for reading a recorded
    #: exchange's state back off its request header. `no_auth` has none.
    _LABEL_BY_AUTH = {headers.get("Authorization", ""): label for label, headers in AUTH_TESTS}

    TEST_PROMPT = "Say hello."

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
                # No discriminator — which of the five judgements applies is the
                # grader's to decide, and an ungraded candidate should not
                # pre-claim `critical`.
                candidate = self.create_candidate(host=service.host, target=service, target_url=url)
                await self._test_auth(url, api_format, candidate, scan_id)
                result.candidates.append(candidate)

                result.outputs[f"auth_status_{service.port}"] = self._reading(candidate.exchanges)
            except Exception as e:
                result.errors.append(f"{url}: {e}")

        return result

    async def _test_auth(
        self, url: str, api_format: str, candidate: Candidate, scan_id: str
    ) -> None:
        """Send the prompt under each auth state, recording every attempt."""
        cfg = HttpConfig(timeout_seconds=15.0, verify_ssl=False)
        async with AsyncHttpClient(cfg) as client:
            for _label, auth_headers in self.AUTH_TESTS:
                await self._rate_limit()

                headers = {**JSON_HEADERS, **auth_headers}
                body = format_chat_request(self.TEST_PROMPT, api_format)
                resp = await client.post(url, json=body, headers=headers)

                candidate.attach(
                    exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=scan_id,
                        host=candidate.host,
                        method="POST",
                        request_headers=headers,
                        request_json=body,
                    )
                )

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Walk the original auth-bypass ladder over the recorded attempts."""
        reading = self._reading(list(evidence))
        accepted = reading["accepted"]
        rejected = reading["rejected"]
        ids = evidence.ids()

        # A 200 to a chat request means the credential was accepted, unless the
        # endpoint answers 200 to *everything* — in which case a "rejected"
        # state would have been accepted too. The whole ladder rests on the
        # endpoint discriminating, so that is the shared confidence question.
        discriminates = bool(rejected)

        if "no_auth" in accepted:
            confidence, why = self._confidence(
                discriminates,
                base=0.95,
                claim="the endpoint answered a chat request carrying no Authorization header",
            )
            return [
                self._verdict(
                    "critical",
                    confidence,
                    why,
                    "no-auth-required",
                    "AI endpoint requires no authentication",
                    "Chat endpoint responds to requests without any auth headers",
                    f"No auth required. Accepted: {', '.join(accepted)}",
                    reading,
                    ids,
                    refs=self.references,
                )
            ]

        if "empty_bearer" in accepted:
            confidence, why = self._confidence(
                discriminates,
                base=0.9,
                claim="an empty Bearer token was accepted where a real one is expected",
            )
            return [
                self._verdict(
                    "high",
                    confidence,
                    why,
                    "empty-bearer-bypass",
                    "Auth bypass: empty Bearer token accepted",
                    "Endpoint responds to requests with an empty Bearer token",
                    f"Empty bearer accepted. All accepted: {', '.join(accepted)}",
                    reading,
                    ids,
                    refs=self.references,
                )
            ]

        default_accepted = [a for a in accepted if a.startswith("default_")]
        if default_accepted:
            confidence, why = self._confidence(
                discriminates,
                base=0.9,
                claim=f"well-known default key(s) accepted: {', '.join(default_accepted)}",
            )
            return [
                self._verdict(
                    "critical",
                    confidence,
                    why,
                    "default-key-accepted",
                    f"Default API key accepted: {', '.join(default_accepted)}",
                    "Endpoint accepts well-known default or test API keys",
                    f"Default keys accepted: {', '.join(default_accepted)}",
                    reading,
                    ids,
                    refs=self.references,
                )
            ]

        if "basic_test" in accepted:
            confidence, why = self._confidence(
                discriminates,
                base=0.9,
                claim="Basic test:test credentials were accepted",
            )
            return [
                self._verdict(
                    "high",
                    confidence,
                    why,
                    "basic-test-bypass",
                    "Auth bypass: Basic test:test credentials accepted",
                    "Endpoint accepts Basic auth with test:test credentials",
                    "Basic dGVzdDp0ZXN0 (test:test) accepted",
                    reading,
                    ids,
                    refs=self.references,
                )
            ]

        # Nothing bypassed. Reported as before, at `info`.
        return [
            self._verdict(
                "info",
                0.9,
                f"all {len(self.AUTH_TESTS)} states carrying a bogus or absent credential were "
                "rejected with 401/403",
                "auth-enforced",
                "Authentication enforced",
                f"All {len(self.AUTH_TESTS)} bypass attempts rejected",
                f"Rejected: {len(rejected)}/{len(self.AUTH_TESTS)} attempts",
                reading,
                ids,
            )
        ]

    # ── Shared reading + verdict assembly ────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """Sort recorded attempts into accepted (200) and rejected (401/403).

        The auth state of each is the `Authorization` header it was sent with,
        read back off the recorded request rather than the send order.
        """
        accepted: list[str] = []
        rejected: list[str] = []

        for exchange in exchanges:
            if exchange.error:
                continue
            label = self._label_for(exchange)
            if label is None:
                continue

            if exchange.response_status == 200:
                accepted.append(label)
            elif exchange.response_status in (401, 403):
                rejected.append(label)

        return {"accepted": accepted, "rejected": rejected}

    def _label_for(self, exchange: Exchange) -> str | None:
        """Which auth-test label this exchange carried."""
        auth = (exchange.request_headers or {}).get("Authorization", "")
        return self._LABEL_BY_AUTH.get(auth)

    def _confidence(self, discriminates: bool, *, base: float, claim: str) -> tuple[float, str]:
        """Lower any acceptance verdict when the endpoint accepted everything.

        Every rung of the ladder is a 200 to a request that should have failed,
        and the recurring web-suite false positive reaches here: an endpoint
        that answers 200 to every path answers 200 to every credential too, so
        a bypass and a catch-all look identical from a status code alone. When
        at least one bogus state drew a 401/403, the endpoint is discriminating
        and the acceptance means something.
        """
        if discriminates:
            return base, f"{claim}; other bogus states drew 401/403, so the endpoint discriminates"
        return min(base, 0.5), (
            f"{claim}; but every state was accepted and none rejected, so a catch-all endpoint "
            "answering 200 to anything would look the same — the acceptance may not be an auth "
            "decision at all"
        )

    def _verdict(
        self,
        severity: str,
        confidence: float,
        why: str,
        discriminator: str,
        title: str,
        description: str,
        evidence: str,
        reading: dict,
        ids: list[str],
        refs: list[str] | None = None,
    ) -> Verdict:
        return Verdict(
            severity=severity,
            confidence=confidence,
            discriminator=discriminator,
            title=title,
            description=description,
            evidence=evidence,
            reasoning=why,
            signals=dict(reading),
            references=list(refs or []),
            raw_data=dict(reading),
            evidence_ids=ids,
        )
