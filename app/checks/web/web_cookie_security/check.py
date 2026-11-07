"""
app/checks/web/cookie_security.py - Cookie Security Analysis

Parses Set-Cookie headers and checks for missing security attributes:
- Secure flag
- HttpOnly flag
- SameSite attribute
- Domain scope
- Long-lived session cookies

**Probe/grade.** `check_service()` sends one request and
hands the response over; `grade()` re-reads the recorded `Set-Cookie` headers
and places the severity. A single-shot check, so the whole classifier — parsing
included — moved to the grade side unchanged, which is what §6.2 predicts.

The confidence separates two things this check ran together. **Whether an
attribute is present is categorical**: the header either says `Secure` or it
does not, and there is nothing to interpret. **Whether the cookie is a session
cookie is a guess from its name** — `SESSION_COOKIE_PATTERNS` matches
substrings like `sid`, `auth` and `token` — and that guess is the only thing
standing between `low` and `medium`. So an unescalated verdict carries 0.99 and
an escalated one carries 0.85, with the matched name pattern in `signals`.
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

# Cookie names that suggest session/auth tokens
SESSION_COOKIE_PATTERNS = re.compile(
    r"(session|sess|sid|jsessionid|phpsessid|aspsessionid|connect\.sid|"
    r"_session|auth|token|jwt|access_token|refresh_token|csrf|xsrf)",
    re.I,
)

# Max-Age threshold: 1 year in seconds
MAX_AGE_THRESHOLD = 365 * 24 * 60 * 60

#: Confidence for a judgement that is only a reading of the header.
CERTAIN = 0.99
#: Confidence for one whose severity was escalated on the cookie's *name*.
NAME_INFERRED = 0.85


class CookieSecurityCheck(ServiceIteratingCheck):
    """Analyze Set-Cookie headers for missing security attributes."""

    name = "web_cookie_security"
    description = "Check cookies for missing Secure, HttpOnly, SameSite attributes"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["cookie_observations"]
    service_types = ["http", "html", "api", "ai"]

    reason = "Insecure cookies enable session theft via XSS, network sniffing, and CSRF"
    references = ["OWASP WSTG-SESS-02", "CWE-614", "CWE-1004"]
    techniques = ["cookie attribute analysis", "session management testing"]

    # ══ Probe ════════════════════════════════════════════════════════
    # Send, record, assert nothing.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                resp = await client.get(service.url)

            if resp.error:
                result.errors.append(f"{service.url}: {resp.error}")
                return result

            # One candidate per service: every cookie attribute is its own
            # judgement over the same response, so the candidate stays
            # undiscriminated and `grade()` names each one.
            candidate = self.create_candidate(host=service.host, target=service)
            candidate.attach(
                exchange_from_response(
                    resp,
                    check_name=self.name,
                    scan_id=context.get("scan_id") or "",
                    host=service.host,
                )
            )
            result.candidates.append(candidate)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    # ══ Grade ════════════════════════════════════════════════════════
    # Re-read the recorded Set-Cookie headers. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one response's cookies."""
        exchange = next(iter(evidence.completed()), None)
        if exchange is None:
            return []

        cookies = self._extract_set_cookies(exchange.response_headers or {})
        evidence_ids = [exchange.id]

        verdicts: list[Verdict] = []
        for cookie in cookies:
            verdicts.extend(self._grade_cookie(cookie, evidence_ids))
        return verdicts

    @staticmethod
    def _extract_set_cookies(headers: dict[str, str]) -> list[dict]:
        """Parse Set-Cookie headers into structured cookie dicts."""
        cookies = []
        for key, value in headers.items():
            if key.lower() != "set-cookie":
                continue
            # Each Set-Cookie header is one cookie
            parsed = _parse_set_cookie(value)
            if parsed:
                cookies.append(parsed)
        return cookies

    def _grade_cookie(self, cookie: dict, evidence_ids: list[str]) -> list[Verdict]:
        """Grade a single recorded cookie. One verdict per issue."""
        name = cookie["name"]
        attrs = cookie["attributes"]
        session_match = SESSION_COOKIE_PATTERNS.search(name)
        is_session = bool(session_match)
        raw = f"Set-Cookie: {cookie['raw'][:200]}"

        def signals(**extra: Any) -> dict[str, Any]:
            return {
                "cookie": name,
                "session_cookie": is_session,
                "name_pattern": session_match.group(0) if session_match else None,
                **extra,
            }

        def why(claim: str) -> str:
            """The reading, plus what the escalation rests on where there is one."""
            if is_session:
                return (
                    f"{claim}; graded as a session cookie because its name contains "
                    f"'{session_match.group(0)}', which is a guess about the cookie's role"
                )
            return claim

        verdicts: list[Verdict] = []

        # ── Missing Secure flag ──
        if "secure" not in attrs:
            verdicts.append(
                Verdict(
                    severity="medium" if is_session else "low",
                    confidence=NAME_INFERRED if is_session else CERTAIN,
                    discriminator=f"no-secure-{name}",
                    title=f"Cookie missing Secure flag: {name}",
                    description=(f"Cookie '{name}' can be sent over unencrypted HTTP connections"),
                    evidence=raw,
                    reasoning=why("the Set-Cookie header declares no Secure attribute"),
                    signals=signals(),
                    references=["CWE-614"],
                    evidence_ids=evidence_ids,
                )
            )

        # ── Missing HttpOnly flag ──
        if "httponly" not in attrs:
            verdicts.append(
                Verdict(
                    severity="medium" if is_session else "low",
                    confidence=NAME_INFERRED if is_session else CERTAIN,
                    discriminator=f"no-httponly-{name}",
                    title=f"Cookie missing HttpOnly: {name}",
                    description=(
                        f"Cookie '{name}' is accessible to JavaScript — vulnerable to XSS theft"
                    ),
                    evidence=raw,
                    reasoning=why("the Set-Cookie header declares no HttpOnly attribute"),
                    signals=signals(),
                    references=["CWE-1004"],
                    evidence_ids=evidence_ids,
                )
            )

        # ── Missing or weak SameSite ──
        samesite = attrs.get("samesite", "").lower()
        if not samesite:
            verdicts.append(
                Verdict(
                    severity="low",
                    # The absence is certain; the consequence is not, because
                    # current browsers default to `Lax` rather than to nothing.
                    confidence=0.95,
                    discriminator=f"no-samesite-{name}",
                    title=f"Cookie missing SameSite: {name}",
                    description=(
                        f"Cookie '{name}' has no SameSite attribute — browser default may vary"
                    ),
                    evidence=raw,
                    reasoning=(
                        "no SameSite attribute in the header; what a browser then applies "
                        "is its own default, which has changed over time"
                    ),
                    signals=signals(),
                    references=["CWE-352"],
                    evidence_ids=evidence_ids,
                )
            )
        elif samesite == "none":
            verdicts.append(
                Verdict(
                    severity="medium" if is_session else "low",
                    confidence=NAME_INFERRED if is_session else CERTAIN,
                    discriminator=f"samesite-none-{name}",
                    title=f"Cookie SameSite=None: {name}",
                    description=(f"Cookie '{name}' is sent on all cross-site requests — CSRF risk"),
                    evidence=raw,
                    reasoning=why("the header declares SameSite=None verbatim"),
                    signals=signals(samesite=samesite),
                    references=["CWE-352"],
                    evidence_ids=evidence_ids,
                )
            )

        # ── Broad domain scope ──
        domain = attrs.get("domain", "")
        if domain and isinstance(domain, str) and domain.startswith("."):
            verdicts.append(
                Verdict(
                    severity="low",
                    # The declared scope is read verbatim. Not 0.99 because the
                    # claim is about the declaration: browsers treat a
                    # dot-prefixed and a bare `Domain=` identically, so the
                    # leading dot marks the legacy spelling, not the risk.
                    confidence=0.95,
                    discriminator=f"broad-domain-{name}",
                    title=f"Cookie scoped to broad domain: {domain}",
                    description=(f"Cookie '{name}' is shared across all subdomains of {domain}"),
                    evidence=raw,
                    reasoning=(
                        f"Domain={domain} is declared with a leading dot, the legacy "
                        "spelling of a subdomain-wide scope"
                    ),
                    signals=signals(domain=domain),
                    evidence_ids=evidence_ids,
                )
            )

        # ── Excessively long-lived session cookie ──
        max_age = attrs.get("max-age")
        if max_age and is_session:
            try:
                age_val = int(max_age)
            except (ValueError, TypeError):
                age_val = None
            if age_val is not None and age_val > MAX_AGE_THRESHOLD:
                verdicts.append(
                    Verdict(
                        severity="low",
                        # Max-Age is read verbatim and compared to a constant;
                        # the soft half is again "this is a session cookie".
                        confidence=NAME_INFERRED,
                        discriminator=f"long-lived-{name}",
                        title=f"Long-lived session cookie: {name}",
                        description=(
                            f"Session cookie '{name}' has Max-Age={age_val} "
                            f"(>{MAX_AGE_THRESHOLD}s / 1 year)"
                        ),
                        evidence=raw,
                        reasoning=why(f"Max-Age={age_val} exceeds {MAX_AGE_THRESHOLD}s"),
                        signals=signals(max_age=age_val),
                        evidence_ids=evidence_ids,
                    )
                )

        return verdicts


def _parse_set_cookie(header_value: str) -> dict | None:
    """Parse a Set-Cookie header value into name, value, and attributes."""
    if not header_value or "=" not in header_value.split(";")[0]:
        return None

    parts = header_value.split(";")
    # First part is name=value
    name_val = parts[0].strip()
    eq_idx = name_val.index("=")
    name = name_val[:eq_idx].strip()
    if not name:
        return None

    # Parse attributes
    attributes = {}
    for part in parts[1:]:
        part = part.strip()
        if "=" in part:
            attr_name, attr_val = part.split("=", 1)
            attributes[attr_name.strip().lower()] = attr_val.strip()
        elif part:
            attributes[part.lower()] = True

    return {
        "name": name,
        "attributes": attributes,
        "raw": header_value,
    }
