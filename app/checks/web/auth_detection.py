"""
app/checks/web/auth_detection.py - Authentication Detection

Probes for authentication mechanisms:
- HTTP Basic/Digest/Bearer (401 + WWW-Authenticate)
- OAuth/OIDC discovery endpoints
- Login form detection
- API key headers

Outputs auth_mechanisms for downstream checks.
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.evidence import fmt_status_evidence
from app.lib.findings import build_finding
from app.lib.http import AsyncHttpClient, HttpConfig

# Paths to probe for auth mechanisms
AUTH_PROBE_PATHS = [
    "/.well-known/openid-configuration",
    "/oauth/authorize",
    "/oauth/token",
    "/auth",
    "/login",
    "/signin",
    "/api/auth",
    "/api/login",
]

# Password input pattern in HTML
LOGIN_FORM_RE = re.compile(
    r"""<input[^>]*type\s*=\s*["']password["'][^>]*>""",
    re.I,
)


class AuthDetectionCheck(ServiceIteratingCheck):
    """Detect authentication mechanisms on HTTP services."""

    name = "auth_detection"
    description = "Detect authentication mechanisms (Basic, Bearer, OAuth, login forms)"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["auth_mechanisms"]
    service_types = ["http", "html", "api", "ai"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = "Understanding authentication informs downstream AI/agent check interpretation"
    references = ["OWASP WSTG-ATHN-01", "CWE-287"]
    techniques = ["authentication detection", "endpoint enumeration"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mechanisms: dict[str, list[str]] = {}

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                # ── Check root for WWW-Authenticate ──
                root_resp = await client.get(service.url)
                if not root_resp.error:
                    self._check_www_authenticate(root_resp, service, result, mechanisms)

                # ── Probe auth-related paths ──
                for path in AUTH_PROBE_PATHS:
                    await self._rate_limit()
                    resp = await client.get(service.with_path(path))
                    if resp.error:
                        continue

                    # 401/403 with WWW-Authenticate
                    if resp.status_code in (401, 403):
                        self._check_www_authenticate(resp, service, result, mechanisms, path=path)

                    # OIDC discovery document
                    if path == "/.well-known/openid-configuration" and resp.status_code == 200:
                        body = (resp.body or "").lower()
                        if "issuer" in body and "authorization_endpoint" in body:
                            mechanisms.setdefault("oidc", []).append(path)
                            result.findings.append(
                                build_finding(
                                    check_name=self.name,
                                    title=f"OAuth/OIDC provider detected: {service.host}",
                                    description="OpenID Connect discovery document found",
                                    severity="info",
                                    evidence=fmt_status_evidence(
                                        service.with_path(path),
                                        200,
                                        (resp.body or "")[:200],
                                    ),
                                    host=service.host,
                                    discriminator="oidc-discovery",
                                    target=service,
                                )
                            )

                    # OAuth endpoints
                    if path in ("/oauth/authorize", "/oauth/token") and resp.status_code in (
                        200,
                        302,
                        400,
                    ):
                        mechanisms.setdefault("oauth", []).append(path)

                    # Login form detection
                    if resp.status_code == 200 and resp.body and LOGIN_FORM_RE.search(resp.body):
                        mechanisms.setdefault("login_form", []).append(path)
                        result.findings.append(
                            build_finding(
                                check_name=self.name,
                                title=f"Login page detected: {service.host}{path}",
                                description="HTML page with password input form found",
                                severity="info",
                                evidence=fmt_status_evidence(service.with_path(path), 200),
                                host=service.host,
                                discriminator=f"login-form-{path.replace('/', '-')}",
                                target=service,
                            )
                        )

                # ── Check if API endpoints lack auth ──
                api_paths = self._get_api_paths(service, context)
                for api_path in api_paths[:5]:  # Check up to 5
                    await self._rate_limit()
                    resp = await client.get(service.with_path(api_path))
                    if resp.error:
                        continue
                    if resp.status_code == 200:
                        ct = ""
                        for k, v in resp.headers.items():
                            if k.lower() == "content-type":
                                ct = v.lower()
                                break
                        if "json" in ct or "api" in api_path:
                            result.findings.append(
                                build_finding(
                                    check_name=self.name,
                                    title=f"API endpoint requires no authentication: {service.host}{api_path}",
                                    description="API endpoint returned 200 with no authentication required",
                                    severity="medium",
                                    evidence=fmt_status_evidence(service.with_path(api_path), 200),
                                    host=service.host,
                                    discriminator=f"no-auth-{api_path.replace('/', '-')}",
                                    target=service,
                                )
                            )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        result.outputs["auth_mechanisms"] = mechanisms
        return result

    def _check_www_authenticate(
        self,
        resp,
        service: Service,
        result: CheckResult,
        mechanisms: dict,
        path: str = "/",
    ) -> None:
        """Check for WWW-Authenticate header and record mechanism."""
        www_auth = ""
        for k, v in resp.headers.items():
            if k.lower() == "www-authenticate":
                www_auth = v
                break

        if not www_auth:
            return

        auth_type = www_auth.split()[0].lower() if www_auth.split() else "unknown"
        mechanisms.setdefault(auth_type, []).append(path)

        severity = "info"
        # Bearer without HTTPS is a risk
        if auth_type == "bearer" and service.scheme == "http":
            severity = "low"

        result.findings.append(
            build_finding(
                check_name=self.name,
                title=f"{auth_type.title()} auth required: {service.host}{path}",
                description=f"WWW-Authenticate header specifies {auth_type} authentication",
                severity=severity,
                evidence=f"HTTP {resp.status_code} | WWW-Authenticate: {www_auth[:200]}",
                host=service.host,
                discriminator=f"www-auth-{auth_type}-{path.replace('/', '-')}",
                target=service,
            )
        )

    @staticmethod
    def _get_api_paths(service: Service, context: dict) -> list[str]:
        """Get API-like paths from path_probe context."""
        paths_key = f"paths_{service.port}"
        paths_data = context.get("discovered_paths", {})
        if isinstance(paths_data, dict) and paths_key in paths_data:
            accessible = paths_data[paths_key].get("accessible", [])
        elif paths_key in context:
            accessible = context[paths_key].get("accessible", [])
        else:
            accessible = []
        # Filter to paths that look like API endpoints
        return [
            p
            for p in accessible
            if any(seg in p.lower() for seg in ["/api/", "/v1/", "/v2/", "/graphql"])
        ]
