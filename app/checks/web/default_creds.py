"""
app/checks/web/default_creds.py - Default Credentials on Admin Panels

When path_probe finds admin panels returning 200 with login forms,
tests a small set of default credential pairs.

GATED: Requires checks.intrusive_web = true (opt-in).
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.evidence import fmt_status_evidence
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation


class DefaultCredsCheck(ServiceIteratingCheck):
    """Test discovered admin panels for default credentials."""

    name = "default_creds"
    description = "Test admin panels for default credentials and unauthenticated access"
    intrusive = True

    conditions = [CheckCondition("services", "truthy")]
    produces = ["default_creds_observations"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 60.0
    delay_between_targets = 0.5

    reason = "Admin panels with default credentials supersede all AI-specific observations on the same host"
    references = ["OWASP WSTG-ATHN-02", "CWE-798", "CWE-1392"]
    techniques = ["default credential testing", "authentication bypass"]

    # Admin paths to test (only those found by path_probe with login forms)
    ADMIN_PATTERNS = [
        "/admin",
        "/admin/",
        "/administrator",
        "/console",
        "/dashboard",
        "/manager",
        "/wp-admin",
        "/panel",
    ]

    # Default credential pairs to test (kept minimal to avoid lockout)
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
    ]

    # Patterns indicating a login form
    LOGIN_FORM_PATTERNS = [
        re.compile(r'<input[^>]+type\s*=\s*["\']password["\']', re.I),
        re.compile(r"<form[^>]+login", re.I),
        re.compile(r"<form[^>]+auth", re.I),
    ]

    # Patterns indicating successful login
    LOGIN_SUCCESS_PATTERNS = [
        re.compile(r"dashboard", re.I),
        re.compile(r"welcome", re.I),
        re.compile(r"logged\s*in", re.I),
        re.compile(r"logout", re.I),
    ]

    # Patterns indicating failed login
    LOGIN_FAILURE_PATTERNS = [
        re.compile(r"invalid\s*(credentials|password|login)", re.I),
        re.compile(r"incorrect\s*(password|login)", re.I),
        re.compile(r"authentication\s*failed", re.I),
        re.compile(r"login\s*failed", re.I),
        re.compile(r"wrong\s*password", re.I),
    ]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Gate: intrusive_web must be enabled
        if not self._is_intrusive_allowed():
            result.outputs["default_creds_skipped"] = True
            return result

        accessible = self._get_accessible_paths(service, context)
        admin_paths = [
            p
            for p in accessible
            if any(
                a in p.lower() for a in ["/admin", "/console", "/dashboard", "/manager", "/panel"]
            )
        ]

        if not admin_paths:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                for path in admin_paths:
                    await self._rate_limit()
                    url = service.with_path(path)
                    resp = await client.get(url)

                    if resp.error or resp.status_code != 200 or not resp.body:
                        continue

                    # Check if page has a login form
                    has_login = any(p.search(resp.body) for p in self.LOGIN_FORM_PATTERNS)

                    if not has_login:
                        # No login form — admin panel may require no auth
                        if self._looks_like_admin_content(resp.body):
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=f"Admin panel requires no authentication: {service.host}{path}",
                                    description=f"Admin panel at {path} is accessible without any login",
                                    severity="critical",
                                    evidence=fmt_status_evidence(url, 200, resp.body[:200]),
                                    host=service.host,
                                    discriminator=f"no-auth-{path.replace('/', '-').strip('-')}",
                                    target=service,
                                    target_url=url,
                                )
                            )
                        continue

                    # Has login form — try default credentials
                    cred_found = await self._try_credentials(client, service, path, resp.body)

                    if cred_found:
                        username, password = cred_found
                        cred_display = (
                            f"{username}/{password}" if password else f"{username}/(empty)"
                        )
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Default credentials accepted: {cred_display} at {service.host}{path}",
                                description=f"Login with default credentials succeeded at {path}",
                                severity="critical",
                                evidence=f"POST {url} with {cred_display} -> login appears successful",
                                host=service.host,
                                discriminator=f"default-creds-{path.replace('/', '-').strip('-')}",
                                target=service,
                                target_url=url,
                                raw_data={"path": path, "username": username},
                            )
                        )
                    else:
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Login form detected: {service.host}{path}",
                                description=f"Admin login form found at {path} — default credentials rejected",
                                severity="high",
                                evidence=f"Login form at {url}, {len(self.DEFAULT_CREDS)} credential pairs tested and rejected",
                                host=service.host,
                                discriminator=f"login-form-{path.replace('/', '-').strip('-')}",
                                target=service,
                                target_url=url,
                            )
                        )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    async def _try_credentials(
        self,
        client: AsyncHttpClient,
        service: Service,
        path: str,
        form_html: str,
    ) -> tuple[str, str] | None:
        """Try default credential pairs. Returns (username, password) on success, None on failure."""
        url = service.with_path(path)

        for username, password in self.DEFAULT_CREDS:
            await self._rate_limit()

            # POST form data (common login form fields)
            resp = await client.post(
                url,
                data=f"username={username}&password={password}",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            if resp.error:
                continue

            body = resp.body or ""

            # Check for success indicators
            if any(p.search(body) for p in self.LOGIN_SUCCESS_PATTERNS):
                # Verify it's not a false positive by checking for failure patterns too
                if not any(p.search(body) for p in self.LOGIN_FAILURE_PATTERNS):
                    return (username, password)

            # 302 redirect after login often means success
            if resp.status_code in (301, 302, 303) and not any(
                p.search(body) for p in self.LOGIN_FAILURE_PATTERNS
            ):
                return (username, password)

        return None

    @staticmethod
    def _looks_like_admin_content(body: str) -> bool:
        """Check if page content looks like an admin panel (not just a redirect or error)."""
        admin_indicators = [
            "dashboard",
            "admin panel",
            "configuration",
            "settings",
            "manage",
            "users",
        ]
        body_lower = body.lower()
        return any(ind in body_lower for ind in admin_indicators)

    @staticmethod
    def _is_intrusive_allowed() -> bool:
        """Check if intrusive web checks are enabled in preferences."""
        try:
            from app.preferences import get_preferences

            return get_preferences().checks.intrusive_web
        except Exception:
            return False

    @staticmethod
    def _get_accessible_paths(service: Service, context: dict) -> list[str]:
        """Get accessible paths from path_probe context."""
        paths_key = f"paths_{service.port}"
        paths_data = context.get("discovered_paths", {})
        if isinstance(paths_data, dict) and paths_key in paths_data:
            return paths_data[paths_key].get("accessible", [])
        if paths_key in context:
            return context[paths_key].get("accessible", [])
        return []
