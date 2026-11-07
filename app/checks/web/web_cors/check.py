"""
app/checks/web/cors.py - CORS Misconfiguration Testing

Test for overly permissive CORS configurations.

**Probe/grade.** `check_service()` sends one preflight per
test origin, records each, and stops at the first origin the server accepted;
`grade()` re-reads the recorded preflights and decides *how* it was accepted.

The probe still stops early, and that is deliberate: the original broke out of
the loop on the first hit, so probing on would be a request this check never
made. It decides whether to stop by reading the exchange it just recorded rather
than the response object — §6.2's two parses, with `_classify()` as the one
parser both halves call.

What the split adds is an honest confidence, and here it earns its keep twice:

- A wildcard ACAO *with* credentials is graded `high`, but no browser will
  honour `*` alongside `Allow-Credentials: true`. The severity is preserved and
  the confidence says the escalation rests on a combination browsers refuse.
- `Access-Control-Allow-Origin: null` fires whichever origin was sent, and a
  literal `null` is also how several frameworks spell *denied*. Sending `null`
  and getting it back is a reflection; getting it back for
  `https://evil.attacker.com` probably is not, and the two no longer assert
  themselves identically.
"""

from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_cors_evidence
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict

#: The preflight request headers, sent verbatim with every test origin.
PREFLIGHT_HEADERS = {
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "Content-Type",
}


class CorsCheck(ServiceIteratingCheck):
    """Test for CORS misconfigurations."""

    name = "web_cors"  # renamed from cors_check
    description = "Test for overly permissive CORS configurations"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["cors_observations"]
    service_types = ["http", "html", "api", "ai"]

    reason = "CORS misconfigurations can allow malicious sites to steal data via a user's browser"
    references = ["OWASP WSTG-CLNT-07", "CWE-942", "PortSwigger CORS"]
    techniques = ["configuration testing", "CORS exploitation"]

    TEST_ORIGINS = [
        "https://evil.attacker.com",
        "null",  # null origin sandbox bypass
    ]

    # ══ Probe ════════════════════════════════════════════════════════
    # Send, record, stop at the first acceptance. Judge nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        # One candidate per service: the original emitted at most one
        # observation here, so the candidate stays undiscriminated and `grade()`
        # names the discriminator it earns.
        candidate = self.create_candidate(host=service.host, target=service)

        try:
            async with AsyncHttpClient(cfg) as client:
                for origin in self.TEST_ORIGINS:
                    resp = await client.options(
                        service.url,
                        headers={"Origin": origin, **PREFLIGHT_HEADERS},
                    )

                    if resp.error:
                        result.errors.append(f"CORS OPTIONS {service.url}: {resp.error}")
                        continue

                    exchange = exchange_from_response(
                        resp,
                        check_name=self.name,
                        scan_id=context.get("scan_id") or "",
                        host=service.host,
                        method="OPTIONS",
                        request_headers={"Origin": origin, **PREFLIGHT_HEADERS},
                    )
                    candidate.attach(exchange)

                    # The original stopped at the first acceptance; read that off
                    # the exchange just recorded, so the grader reads the same
                    # bytes rather than a second copy of the reading.
                    if _classify(*_reading(exchange)) is not None:
                        break

            if candidate.exchanges:
                result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"CORS check on {service.url}: {e}")

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded preflights. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on the first preflight the server accepted.

        At most one verdict, matching the probe's `break`: the origins are tried
        in escalating order and the first acceptance is the answer.
        """
        for exchange in evidence.completed():
            origin, acao, acac = _reading(exchange)
            kind = _classify(origin, acao, acac)
            if kind is None:
                continue

            with_credentials = acac == "true"
            credentials_note = f" | credentials: {acac or 'not set'}"

            if kind == "wildcard-origin":
                return [
                    Verdict(
                        severity="high" if with_credentials else "medium",
                        # The wildcard itself is categorical. The `high` rests on
                        # `Allow-Credentials: true` being honoured, and browsers
                        # refuse to honour it alongside `*` — so the escalated
                        # verdict is the less certain of the two.
                        confidence=0.8 if with_credentials else 0.95,
                        discriminator="wildcard-origin",
                        title="CORS wildcard origin",
                        description=(
                            "Server allows any origin — may allow cross-origin data theft"
                        ),
                        evidence=fmt_cors_evidence(origin, acao) + credentials_note,
                        reasoning=(
                            "ACAO is '*' with credentials allowed, a pairing no browser "
                            "honours — the wildcard is certain, the escalation is not"
                            if with_credentials
                            else "ACAO is '*' verbatim in the recorded preflight"
                        ),
                        signals={"allow_origin": acao, "allow_credentials": with_credentials},
                        references=["CWE-942"],
                        evidence_ids=[exchange.id],
                    )
                ]

            if kind == "reflected-origin":
                return [
                    Verdict(
                        severity="high" if with_credentials else "medium",
                        # The server echoed an origin we invented, so it cannot
                        # be an allowlist entry. Not 1.0 because a preflight is
                        # not the actual request: some frameworks reflect in
                        # OPTIONS middleware that never runs on the POST.
                        confidence=0.95,
                        discriminator="reflected-origin",
                        title="CORS reflects arbitrary origin",
                        description=f"Server reflects attacker-controlled origin: {origin}",
                        evidence=fmt_cors_evidence(origin, acao) + credentials_note,
                        reasoning=(
                            f"ACAO echoed the invented origin {origin}, so no allowlist "
                            "can explain it; only the preflight was observed"
                        ),
                        signals={"allow_origin": acao, "allow_credentials": with_credentials},
                        references=["CWE-942"],
                        evidence_ids=[exchange.id],
                    )
                ]

            # kind == "null-origin"
            echoed = origin == "null"
            return [
                Verdict(
                    severity="medium",
                    # Sending `null` and getting it back is a reflection. Getting
                    # it back for some other origin is ambiguous: a literal
                    # `null` ACAO is also how several frameworks spell "denied".
                    confidence=0.9 if echoed else 0.65,
                    discriminator="null-origin",
                    title="CORS allows null origin",
                    description=("Server accepts 'null' origin — sandbox iframe bypass possible"),
                    evidence=fmt_cors_evidence("null", "null") + credentials_note,
                    reasoning=(
                        "Origin 'null' was sent and echoed back"
                        if echoed
                        else f"ACAO is 'null' but the origin sent was {origin}; a literal "
                        "'null' is also how some frameworks deny a preflight"
                    ),
                    signals={
                        "allow_origin": acao,
                        "origin_sent": origin,
                        "allow_credentials": with_credentials,
                    },
                    references=["CWE-942"],
                    evidence_ids=[exchange.id],
                )
            ]

        return []


def _reading(exchange: Exchange) -> tuple[str, str, str]:
    """The origin sent and the two CORS headers that came back.

    The parsed answer lives on the exchange, not in a return value from the
    request — which is what makes the probe's reading and the grader's the same
    reading (§0.12).
    """
    request_headers = extract_headers_dict(exchange.request_headers or {})
    response_headers = extract_headers_dict(exchange.response_headers or {})
    return (
        request_headers.get("origin", ""),
        response_headers.get("access-control-allow-origin", ""),
        response_headers.get("access-control-allow-credentials", "").lower(),
    )


def _classify(origin: str, acao: str, acac: str) -> str | None:
    """Which acceptance this preflight shows, or `None` for none.

    The original chain of `if`/`elif`, lifted verbatim so that the probe's
    decision to stop and the grader's decision to speak cannot drift apart.
    """
    if acao == "*":
        return "wildcard-origin"
    if acao == origin and origin != "null":
        return "reflected-origin"
    if acao == "null":
        return "null-origin"
    return None
