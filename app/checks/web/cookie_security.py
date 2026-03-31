"""
app/checks/web/cookie_security.py - Cookie Security Analysis

Parses Set-Cookie headers and checks for missing security attributes:
- Secure flag
- HttpOnly flag
- SameSite attribute
- Domain scope
- Long-lived session cookies
"""

import re
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding
from app.lib.evidence import fmt_header_evidence


# Cookie names that suggest session/auth tokens
SESSION_COOKIE_PATTERNS = re.compile(
    r"(session|sess|sid|jsessionid|phpsessid|aspsessionid|connect\.sid|"
    r"_session|auth|token|jwt|access_token|refresh_token|csrf|xsrf)",
    re.I,
)

# Max-Age threshold: 1 year in seconds
MAX_AGE_THRESHOLD = 365 * 24 * 60 * 60


class CookieSecurityCheck(ServiceIteratingCheck):
    """Analyze Set-Cookie headers for missing security attributes."""

    name = "cookie_security"
    description = "Check cookies for missing Secure, HttpOnly, SameSite attributes"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["cookie_findings"]
    service_types = ["http", "html", "api", "ai"]

    timeout_seconds = 60.0
    delay_between_targets = 0.2

    reason = "Insecure cookies enable session theft via XSS, network sniffing, and CSRF"
    references = ["OWASP WSTG-SESS-02", "CWE-614", "CWE-1004"]
    techniques = ["cookie attribute analysis", "session management testing"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                resp = await client.get(service.url)

            if resp.error:
                result.errors.append(f"{service.url}: {resp.error}")
                return result

            # Collect all Set-Cookie headers
            cookies = self._extract_set_cookies(resp.headers)
            if not cookies:
                return result

            for cookie in cookies:
                self._analyze_cookie(cookie, service, result)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

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

    def _analyze_cookie(self, cookie: dict, service: Service, result: CheckResult) -> None:
        """Check a single cookie for security issues."""
        name = cookie["name"]
        attrs = cookie["attributes"]
        is_session = bool(SESSION_COOKIE_PATTERNS.search(name))

        # ── Missing Secure flag ──
        if "secure" not in attrs:
            severity = "medium" if is_session else "low"
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Cookie missing Secure flag: {name}",
                description=f"Cookie '{name}' can be sent over unencrypted HTTP connections",
                severity=severity,
                evidence=f"Set-Cookie: {cookie['raw'][:200]}",
                host=service.host,
                discriminator=f"no-secure-{name}",
                target=service,
                references=["CWE-614"],
            ))

        # ── Missing HttpOnly flag ──
        if "httponly" not in attrs:
            severity = "medium" if is_session else "low"
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Cookie missing HttpOnly: {name}",
                description=f"Cookie '{name}' is accessible to JavaScript — vulnerable to XSS theft",
                severity=severity,
                evidence=f"Set-Cookie: {cookie['raw'][:200]}",
                host=service.host,
                discriminator=f"no-httponly-{name}",
                target=service,
                references=["CWE-1004"],
            ))

        # ── Missing or weak SameSite ──
        samesite = attrs.get("samesite", "").lower()
        if not samesite:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Cookie missing SameSite: {name}",
                description=f"Cookie '{name}' has no SameSite attribute — browser default may vary",
                severity="low",
                evidence=f"Set-Cookie: {cookie['raw'][:200]}",
                host=service.host,
                discriminator=f"no-samesite-{name}",
                target=service,
                references=["CWE-352"],
            ))
        elif samesite == "none":
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Cookie SameSite=None: {name}",
                description=f"Cookie '{name}' is sent on all cross-site requests — CSRF risk",
                severity="medium" if is_session else "low",
                evidence=f"Set-Cookie: {cookie['raw'][:200]}",
                host=service.host,
                discriminator=f"samesite-none-{name}",
                target=service,
                references=["CWE-352"],
            ))

        # ── Broad domain scope ──
        domain = attrs.get("domain", "")
        if domain and domain.startswith("."):
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Cookie scoped to broad domain: {domain}",
                description=f"Cookie '{name}' is shared across all subdomains of {domain}",
                severity="low",
                evidence=f"Set-Cookie: {cookie['raw'][:200]}",
                host=service.host,
                discriminator=f"broad-domain-{name}",
                target=service,
            ))

        # ── Excessively long-lived session cookie ──
        max_age = attrs.get("max-age")
        if max_age and is_session:
            try:
                age_val = int(max_age)
                if age_val > MAX_AGE_THRESHOLD:
                    result.findings.append(build_finding(
                        check_name=self.name,
                        title=f"Long-lived session cookie: {name}",
                        description=f"Session cookie '{name}' has Max-Age={age_val} "
                                    f"(>{MAX_AGE_THRESHOLD}s / 1 year)",
                        severity="low",
                        evidence=f"Set-Cookie: {cookie['raw'][:200]}",
                        host=service.host,
                        discriminator=f"long-lived-{name}",
                        target=service,
                    ))
            except ValueError:
                pass


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
