"""
app/checks/web/web_header_analysis/check.py - HTTP Header Analysis

Deep analysis of HTTP response headers for:
- Missing security headers
- Security header VALUE grading (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- CORS misconfigurations
- Server version disclosure
- Technology fingerprinting

**Probe/grade.** This check is split along the capture
line: `check_service()` sends one request, records it, and emits a `Candidate`
carrying a provisional severity and no judgment at all; `grade()` re-reads the
recorded response and returns one `Verdict` per judgement, each with its own
confidence. The whole classifier — parsing included — moved to the grade side
unchanged, which is what §6.2 predicts for a single-shot check.

Two properties this shape buys immediately, before any LLM grading exists:

- The judgements are re-derivable. Given the stored exchange, `grade()` returns
  the same verdicts without a network, next week or next year.
- Every judgement now states how sure it is. "Server header contains a digit"
  was always a weaker signal than "the header is absent"; until now both were
  asserted identically.
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.evidence_fmt import fmt_cors_evidence, fmt_header_evidence
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import (
    extract_cors_headers,
    extract_headers_dict,
    extract_security_headers,
    extract_server_header,
)


class HeaderAnalysisCheck(ServiceIteratingCheck):
    """Analyze HTTP response headers for security issues and information disclosure."""

    name = "web_header_analysis"
    description = "Analyze HTTP headers for technology disclosure and security misconfigurations"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["header_observations"]
    service_types = ["http", "html", "api", "ai"]

    reason = "HTTP headers often reveal server software, frameworks, and security misconfigurations"
    references = ["OWASP WSTG-INFO-02", "CWE-200", "CIS Benchmarks", "OWASP Secure Headers Project"]
    techniques = ["banner grabbing", "fingerprinting", "security header analysis"]

    # Severity is declared in `contract.yaml` as of 57.4: `model: fixed`, one
    # entry per discriminator, `default: low`. There is deliberately no
    # `provisional_severity` class attribute any more — the contract is the
    # single source of truth, and `from_config` puts it on the instance. This
    # check cannot produce a critical, so a deferred grade cannot mislead
    # `on_critical` (§6.1).

    SECURITY_HEADERS = {
        "strict-transport-security": "HSTS not set - vulnerable to downgrade attacks",
        "x-content-type-options": "Missing - vulnerable to MIME sniffing",
        "x-frame-options": "Missing - potentially vulnerable to clickjacking",
        "content-security-policy": "No CSP - vulnerable to XSS",
        "x-xss-protection": "Legacy XSS protection not set",
        "referrer-policy": "No referrer policy set",
    }

    # ── CSP directives considered weak ──
    CSP_WEAK_PATTERNS = ["'unsafe-inline'", "'unsafe-eval'", "data:", "blob:"]
    CSP_WILDCARD_RE = re.compile(r"(?:^|\s)\*(?:\s|;|$)")
    CSP_BROAD_WILDCARD_RE = re.compile(r"\*\.\S+")  # *.example.com

    # ── HSTS thresholds ──
    HSTS_MIN_MAX_AGE = 31536000  # 1 year in seconds

    # ── Referrer-Policy grades (strict → weak) ──
    REFERRER_GRADES = {
        "no-referrer": "strict",
        "same-origin": "strict",
        "strict-origin": "strict",
        "strict-origin-when-cross-origin": "moderate",
        "origin": "moderate",
        "origin-when-cross-origin": "moderate",
        "no-referrer-when-downgrade": "weak",
        "unsafe-url": "weak",
    }

    SENSITIVE_FEATURES = {"camera", "microphone", "geolocation", "payment", "usb", "midi"}

    # ══ Probe ════════════════════════════════════════════════════════
    # Send, record, assert nothing. Everything below the capture line.

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                resp = await client.get(service.url)

            if resp.error:
                result.errors.append(f"{service.url}: {resp.error}")
                return result

            # The exchange is handed over in memory as well as recorded, because
            # capture is off by default (§0.4). When it is on, `evidence_for`
            # pairs this with the stored copy by `content_hash` and the grader
            # reads the corpus row instead — same bytes, plus an id to bind to.
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
    # Re-read the recorded response. Never the network.

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one recorded response's headers.

        One exchange, several independent judgements — CSP, HSTS, CORS and the
        Server header each stand or fall on their own, so each is its own
        verdict with its own discriminator and confidence.
        """
        exchange = next(iter(evidence.completed()), None)
        if exchange is None:
            return []

        headers = exchange.response_headers or {}
        evidence_ids = [exchange.id]

        headers_lower = extract_headers_dict(headers)
        security = extract_security_headers(headers)
        cors = extract_cors_headers(headers)

        verdicts: list[Verdict] = []

        # ── Missing security headers ──────────────────────────
        missing = [(h, msg) for h, msg in self.SECURITY_HEADERS.items() if security.get(h) is None]
        if missing:
            verdicts.append(
                Verdict(
                    severity="low",
                    # Absence of a header is as categorical as evidence gets.
                    confidence=0.99,
                    discriminator="missing-security-headers",
                    title=f"Missing security headers ({len(missing)})",
                    description="\n".join(f"- {h}: {msg}" for h, msg in missing),
                    evidence="Headers not present: " + ", ".join(h for h, _ in missing),
                    reasoning=f"{len(missing)} of {len(self.SECURITY_HEADERS)} security headers absent",
                    signals={"missing": [h for h, _ in missing]},
                    references=["OWASP Secure Headers Project"],
                    evidence_ids=evidence_ids,
                )
            )

        # ── CSP value grading ─────────────────────────────────
        csp = security.get("content-security-policy")
        if csp:
            verdicts.extend(self._grade_csp(csp, evidence_ids))

        # ── HSTS value grading ────────────────────────────────
        hsts = security.get("strict-transport-security")
        if hsts:
            verdicts.extend(self._grade_hsts(hsts, evidence_ids))

        # ── X-Frame-Options grading ───────────────────────────
        xfo = security.get("x-frame-options")
        if xfo:
            verdicts.extend(self._grade_xfo(xfo, evidence_ids))

        # ── Referrer-Policy grading ───────────────────────────
        rp = security.get("referrer-policy")
        if rp:
            verdicts.extend(self._grade_referrer_policy(rp, evidence_ids))

        # ── Permissions-Policy grading ────────────────────────
        pp = security.get("permissions-policy") or headers_lower.get("permissions-policy")
        if pp:
            verdicts.extend(self._grade_permissions_policy(pp, evidence_ids))

        # ── CORS wildcard ─────────────────────────────────────
        acao = cors.get("access-control-allow-origin") or ""
        acac = (cors.get("access-control-allow-credentials") or "").lower()
        if acao == "*":
            with_credentials = acac == "true"
            verdicts.append(
                Verdict(
                    severity="high" if with_credentials else "medium",
                    confidence=0.95,
                    discriminator="cors-wildcard",
                    title="CORS allows any origin",
                    description="Wildcard CORS policy may allow cross-origin attacks",
                    evidence=fmt_cors_evidence("*", acao) + f" (credentials: {acac})",
                    reasoning=(
                        "Wildcard origin with credentials allowed"
                        if with_credentials
                        else "Wildcard origin without credentials"
                    ),
                    signals={"allow_origin": acao, "allow_credentials": with_credentials},
                    references=["CWE-942"],
                    evidence_ids=evidence_ids,
                )
            )

        # ── Server version disclosure ─────────────────────────
        server = extract_server_header(headers) or ""
        if server and any(c.isdigit() for c in server):
            verdicts.append(
                Verdict(
                    severity="low",
                    # A digit in the Server header is usually a version and
                    # sometimes not — "nginx" behind a CDN that appends a build
                    # number discloses nothing useful. Stated, not asserted.
                    confidence=0.8,
                    discriminator="server-version-disclosure",
                    title=f"Server version disclosed: {server}",
                    description="Server header reveals version information",
                    evidence=fmt_header_evidence("Server", server),
                    reasoning="Server header contains digits, read as a version",
                    signals={"server": server},
                    evidence_ids=evidence_ids,
                )
            )

        return verdicts

    # ── CSP grading ──────────────────────────────────────────────────

    def _grade_csp(self, csp: str, evidence_ids: list[str]) -> list[Verdict]:
        """Grade CSP header value for weak directives."""
        csp_lower = csp.lower()
        issues = []

        # Check for unsafe directives
        for weak in self.CSP_WEAK_PATTERNS:
            if weak in csp_lower:
                issues.append(weak)

        # Check for wildcard source
        if self.CSP_WILDCARD_RE.search(csp_lower):
            issues.append("wildcard (*) source")

        # Check for broad wildcard domains
        broad = self.CSP_BROAD_WILDCARD_RE.findall(csp_lower)
        if broad:
            issues.append(f"broad wildcard: {', '.join(broad[:3])}")

        # Check missing default-src
        if "default-src" not in csp_lower:
            issues.append("missing default-src")

        if not issues:
            return []

        return [
            Verdict(
                severity="medium",
                confidence=0.9,
                discriminator="csp-weak",
                title=f"Weak CSP policy ({len(issues)} issue{'s' if len(issues) != 1 else ''})",
                description="Content-Security-Policy contains weak directives:\n"
                + "\n".join(f"- {i}" for i in issues),
                evidence=fmt_header_evidence("Content-Security-Policy", csp),
                reasoning=f"{len(issues)} weak directive(s) in the declared policy",
                signals={"issues": issues},
                references=["CWE-693", "OWASP CSP Cheat Sheet"],
                evidence_ids=evidence_ids,
            )
        ]

    # ── HSTS grading ─────────────────────────────────────────────────

    def _grade_hsts(self, hsts: str, evidence_ids: list[str]) -> list[Verdict]:
        """Grade HSTS header value."""
        hsts_lower = hsts.lower()
        issues = []

        # Parse max-age
        ma_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
        max_age = int(ma_match.group(1)) if ma_match else None
        if max_age is not None:
            if max_age < self.HSTS_MIN_MAX_AGE:
                issues.append(
                    f"max-age too short: {max_age} (should be >= {self.HSTS_MIN_MAX_AGE})"
                )
        else:
            issues.append("max-age not set")

        if "includesubdomains" not in hsts_lower:
            issues.append("missing includeSubDomains directive")

        if not issues:
            return []

        return [
            Verdict(
                severity="low",
                confidence=0.95,
                discriminator="hsts-weak",
                title=(
                    f"Weak HSTS configuration ({len(issues)} issue{'s' if len(issues) != 1 else ''})"
                ),
                description="Strict-Transport-Security header is present but weak:\n"
                + "\n".join(f"- {i}" for i in issues),
                evidence=fmt_header_evidence("Strict-Transport-Security", hsts),
                reasoning="Directive values read directly from the recorded header",
                signals={"issues": issues, "max_age": max_age},
                references=["CWE-319"],
                evidence_ids=evidence_ids,
            )
        ]

    # ── X-Frame-Options grading ──────────────────────────────────────

    def _grade_xfo(self, xfo: str, evidence_ids: list[str]) -> list[Verdict]:
        """Grade X-Frame-Options header value."""
        xfo_upper = xfo.strip().upper()
        if not xfo_upper.startswith("ALLOW-FROM"):
            return []

        return [
            Verdict(
                severity="medium",
                confidence=0.95,
                discriminator="xfo-allow-from",
                title="X-Frame-Options uses deprecated ALLOW-FROM",
                description="ALLOW-FROM is deprecated and ignored by modern browsers — "
                "use CSP frame-ancestors instead",
                evidence=fmt_header_evidence("X-Frame-Options", xfo),
                reasoning="Directive is ALLOW-FROM, which no current browser honours",
                signals={"directive": xfo_upper.split()[0]},
                references=["CWE-1021"],
                evidence_ids=evidence_ids,
            )
        ]

    # ── Referrer-Policy grading ──────────────────────────────────────

    def _grade_referrer_policy(self, rp: str, evidence_ids: list[str]) -> list[Verdict]:
        """Grade Referrer-Policy header value."""
        # Multiple policies can be comma-separated; last valid one wins
        policies = [p.strip().lower() for p in rp.split(",")]
        effective = policies[-1] if policies else ""
        grade = self.REFERRER_GRADES.get(effective, "unknown")

        if grade != "weak":
            return []

        return [
            Verdict(
                severity="low",
                confidence=0.9,
                discriminator="referrer-policy-weak",
                title=f"Weak Referrer-Policy: {effective}",
                description=f"Referrer-Policy '{effective}' may leak full URLs to external sites",
                evidence=fmt_header_evidence("Referrer-Policy", rp),
                reasoning=f"Effective policy '{effective}' is graded weak",
                signals={"effective": effective, "grade": grade},
                references=["CWE-200"],
                evidence_ids=evidence_ids,
            )
        ]

    # ── Permissions-Policy grading ───────────────────────────────────

    def _grade_permissions_policy(self, pp: str, evidence_ids: list[str]) -> list[Verdict]:
        """Grade Permissions-Policy header for overly permissive features."""
        pp_lower = pp.lower()
        permissive = []

        for feature in self.SENSITIVE_FEATURES:
            # feature=* means allow all origins
            pattern = re.compile(rf"{feature}\s*=\s*\*")
            if pattern.search(pp_lower):
                permissive.append(feature)

        if not permissive:
            return []

        return [
            Verdict(
                severity="low",
                confidence=0.85,
                discriminator="permissions-policy-permissive",
                title=(
                    f"Permissive Permissions-Policy "
                    f"({len(permissive)} feature{'s' if len(permissive) != 1 else ''})"
                ),
                description="Permissions-Policy allows all origins for sensitive features:\n"
                + "\n".join(f"- {f}" for f in sorted(permissive)),
                evidence=fmt_header_evidence("Permissions-Policy", pp),
                reasoning=f"{len(permissive)} sensitive feature(s) delegated to all origins",
                signals={"features": sorted(permissive)},
                references=["OWASP Secure Headers Project"],
                evidence_ids=evidence_ids,
            )
        ]
