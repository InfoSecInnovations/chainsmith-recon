"""
app/checks/web/headers.py - HTTP Header Analysis

Deep analysis of HTTP response headers for:
- Missing security headers
- Security header VALUE grading (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- CORS misconfigurations
- Server version disclosure
- Technology fingerprinting
"""

import re
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.parsing import extract_headers_dict, extract_security_headers, extract_cors_headers, extract_server_header
from app.lib.findings import build_finding
from app.lib.evidence import fmt_header_evidence, fmt_cors_evidence


class HeaderAnalysisCheck(ServiceIteratingCheck):
    """Analyze HTTP response headers for security issues and information disclosure."""

    name = "header_analysis"
    description = "Analyze HTTP headers for technology disclosure and security misconfigurations"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["header_findings"]
    service_types = ["http", "html", "api", "ai"]

    timeout_seconds = 60.0
    delay_between_targets = 0.2

    reason = "HTTP headers often reveal server software, frameworks, and security misconfigurations"
    references = ["OWASP WSTG-INFO-02", "CWE-200", "CIS Benchmarks", "OWASP Secure Headers Project"]
    techniques = ["banner grabbing", "fingerprinting", "security header analysis"]

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

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                resp = await client.get(service.url)

            if resp.error:
                result.errors.append(f"{service.url}: {resp.error}")
                return result

            headers_lower = extract_headers_dict(resp.headers)
            security = extract_security_headers(resp.headers)
            cors = extract_cors_headers(resp.headers)

            # ── Missing security headers ──────────────────────────
            missing = [(h, msg) for h, msg in self.SECURITY_HEADERS.items() if security.get(h) is None]
            if missing:
                result.findings.append(build_finding(
                    check_name=self.name,
                    title=f"Missing security headers ({len(missing)})",
                    description="\n".join(f"- {h}: {msg}" for h, msg in missing),
                    severity="low",
                    evidence="Headers not present: " + ", ".join(h for h, _ in missing),
                    host=service.host,
                    discriminator="missing-security-headers",
                    target=service,
                    references=["OWASP Secure Headers Project"],
                ))

            # ── CSP value grading ─────────────────────────────────
            csp = security.get("content-security-policy")
            if csp:
                self._grade_csp(csp, service, result)

            # ── HSTS value grading ────────────────────────────────
            hsts = security.get("strict-transport-security")
            if hsts:
                self._grade_hsts(hsts, service, result)

            # ── X-Frame-Options grading ───────────────────────────
            xfo = security.get("x-frame-options")
            if xfo:
                self._grade_xfo(xfo, service, result)

            # ── Referrer-Policy grading ───────────────────────────
            rp = security.get("referrer-policy")
            if rp:
                self._grade_referrer_policy(rp, service, result)

            # ── Permissions-Policy grading ────────────────────────
            pp = security.get("permissions-policy") or headers_lower.get("permissions-policy")
            if pp:
                self._grade_permissions_policy(pp, service, result)

            # ── CORS wildcard ─────────────────────────────────────
            acao = cors.get("access-control-allow-origin") or ""
            acac = (cors.get("access-control-allow-credentials") or "").lower()
            if acao == "*":
                severity = "high" if acac == "true" else "medium"
                result.findings.append(build_finding(
                    check_name=self.name,
                    title="CORS allows any origin",
                    description="Wildcard CORS policy may allow cross-origin attacks",
                    severity=severity,
                    evidence=fmt_cors_evidence("*", acao) + f" (credentials: {acac})",
                    host=service.host,
                    discriminator="cors-wildcard",
                    target=service,
                    references=["CWE-942"],
                ))

            # ── Server version disclosure ─────────────────────────
            server = extract_server_header(resp.headers) or ""
            if server and any(c.isdigit() for c in server):
                result.findings.append(build_finding(
                    check_name=self.name,
                    title=f"Server version disclosed: {server}",
                    description="Server header reveals version information",
                    severity="low",
                    evidence=fmt_header_evidence("Server", server),
                    host=service.host,
                    discriminator="server-version-disclosure",
                    target=service,
                ))

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    # ── CSP grading ──────────────────────────────────────────────────

    def _grade_csp(self, csp: str, service: Service, result: CheckResult) -> None:
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

        if issues:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Weak CSP policy ({len(issues)} issue{'s' if len(issues) != 1 else ''})",
                description="Content-Security-Policy contains weak directives:\n"
                            + "\n".join(f"- {i}" for i in issues),
                severity="medium",
                evidence=fmt_header_evidence("Content-Security-Policy", csp),
                host=service.host,
                discriminator="csp-weak",
                target=service,
                references=["CWE-693", "OWASP CSP Cheat Sheet"],
            ))

    # ── HSTS grading ─────────────────────────────────────────────────

    def _grade_hsts(self, hsts: str, service: Service, result: CheckResult) -> None:
        """Grade HSTS header value."""
        hsts_lower = hsts.lower()
        issues = []

        # Parse max-age
        ma_match = re.search(r"max-age\s*=\s*(\d+)", hsts_lower)
        if ma_match:
            max_age = int(ma_match.group(1))
            if max_age < self.HSTS_MIN_MAX_AGE:
                issues.append(f"max-age too short: {max_age} (should be >= {self.HSTS_MIN_MAX_AGE})")
        else:
            issues.append("max-age not set")

        if "includesubdomains" not in hsts_lower:
            issues.append("missing includeSubDomains directive")

        if issues:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Weak HSTS configuration ({len(issues)} issue{'s' if len(issues) != 1 else ''})",
                description="Strict-Transport-Security header is present but weak:\n"
                            + "\n".join(f"- {i}" for i in issues),
                severity="low",
                evidence=fmt_header_evidence("Strict-Transport-Security", hsts),
                host=service.host,
                discriminator="hsts-weak",
                target=service,
                references=["CWE-319"],
            ))

    # ── X-Frame-Options grading ──────────────────────────────────────

    def _grade_xfo(self, xfo: str, service: Service, result: CheckResult) -> None:
        """Grade X-Frame-Options header value."""
        xfo_upper = xfo.strip().upper()
        if xfo_upper.startswith("ALLOW-FROM"):
            result.findings.append(build_finding(
                check_name=self.name,
                title="X-Frame-Options uses deprecated ALLOW-FROM",
                description="ALLOW-FROM is deprecated and ignored by modern browsers — "
                            "use CSP frame-ancestors instead",
                severity="medium",
                evidence=fmt_header_evidence("X-Frame-Options", xfo),
                host=service.host,
                discriminator="xfo-allow-from",
                target=service,
                references=["CWE-1021"],
            ))

    # ── Referrer-Policy grading ──────────────────────────────────────

    def _grade_referrer_policy(self, rp: str, service: Service, result: CheckResult) -> None:
        """Grade Referrer-Policy header value."""
        # Multiple policies can be comma-separated; last valid one wins
        policies = [p.strip().lower() for p in rp.split(",")]
        effective = policies[-1] if policies else ""
        grade = self.REFERRER_GRADES.get(effective, "unknown")

        if grade == "weak":
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Weak Referrer-Policy: {effective}",
                description=f"Referrer-Policy '{effective}' may leak full URLs to external sites",
                severity="low",
                evidence=fmt_header_evidence("Referrer-Policy", rp),
                host=service.host,
                discriminator="referrer-policy-weak",
                target=service,
                references=["CWE-200"],
            ))

    # ── Permissions-Policy grading ───────────────────────────────────

    SENSITIVE_FEATURES = {"camera", "microphone", "geolocation", "payment", "usb", "midi"}

    def _grade_permissions_policy(self, pp: str, service: Service, result: CheckResult) -> None:
        """Grade Permissions-Policy header for overly permissive features."""
        pp_lower = pp.lower()
        permissive = []

        for feature in self.SENSITIVE_FEATURES:
            # feature=* means allow all origins
            pattern = re.compile(rf"{feature}\s*=\s*\*")
            if pattern.search(pp_lower):
                permissive.append(feature)

        if permissive:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Permissive Permissions-Policy ({len(permissive)} feature{'s' if len(permissive) != 1 else ''})",
                description="Permissions-Policy allows all origins for sensitive features:\n"
                            + "\n".join(f"- {f}" for f in sorted(permissive)),
                severity="low",
                evidence=fmt_header_evidence("Permissions-Policy", pp),
                host=service.host,
                discriminator="permissions-policy-permissive",
                target=service,
                references=["OWASP Secure Headers Project"],
            ))
