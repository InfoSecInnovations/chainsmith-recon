"""
app/checks/web/vcs_exposure.py - Exposed Version Control Detection

When path_probe finds .git/HEAD or .git/config returning 200,
this check probes deeper to assess exposure severity.
Also checks .svn/entries and .hg/store.
"""

import re
from typing import Any

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.evidence import fmt_status_evidence
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.observations import build_observation


class VCSExposureCheck(ServiceIteratingCheck):
    """Deep check for exposed version control metadata."""

    name = "vcs_exposure"
    description = "Assess depth of exposed .git/.svn/.hg repositories"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["vcs_observations"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = "Exposed .git allows full source code recovery including API keys, model configs, and credentials"
    references = ["OWASP WSTG-CONF-05", "CWE-538"]
    techniques = ["VCS metadata enumeration", "source code exposure assessment"]

    # Git paths to probe beyond .git/HEAD
    GIT_DEEP_PATHS = [
        "/.git/config",
        "/.git/COMMIT_EDITMSG",
        "/.git/refs/heads/main",
        "/.git/refs/heads/master",
        "/.git/logs/HEAD",
        "/.gitignore",
    ]

    # Patterns that indicate credentials in .git/config
    CREDENTIAL_PATTERNS = [
        re.compile(r"https?://[^:]+:[^@]+@", re.I),  # URL with embedded creds
        re.compile(r"token\s*=\s*\S+", re.I),
        re.compile(r"password\s*=\s*\S+", re.I),
    ]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Check if path_probe found accessible VCS paths
        accessible = self._get_accessible_paths(service, context)

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                # ── Git exposure ──
                if any(p for p in accessible if ".git" in p):
                    await self._check_git(client, service, result)

                # ── SVN exposure ──
                if any(p for p in accessible if ".svn" in p):
                    await self._check_svn(client, service, result)
                else:
                    # Probe even if path_probe didn't find it
                    svn_resp = await client.get(service.with_path("/.svn/entries"))
                    if not svn_resp.error and svn_resp.status_code == 200:
                        await self._check_svn(client, service, result)

                # ── Mercurial exposure ──
                hg_resp = await client.get(service.with_path("/.hg/store"))
                if not hg_resp.error and hg_resp.status_code == 200:
                    result.observations.append(
                        build_observation(
                            check_name=self.name,
                            title=f"Mercurial metadata exposed: {service.host}",
                            description=".hg/store is accessible — source code may be recoverable",
                            severity="high",
                            evidence=fmt_status_evidence(
                                service.with_path("/.hg/store"),
                                200,
                                hg_resp.body[:200] if hg_resp.body else "",
                            ),
                            host=service.host,
                            discriminator="hg-exposed",
                            target=service,
                        )
                    )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    async def _check_git(
        self, client: AsyncHttpClient, service: Service, result: CheckResult
    ) -> None:
        """Probe git metadata depth."""
        accessible_git = []
        git_config_body = ""

        for path in self.GIT_DEEP_PATHS:
            await self._rate_limit()
            resp = await client.get(service.with_path(path))
            if not resp.error and resp.status_code == 200:
                accessible_git.append(path)
                if path == "/.git/config":
                    git_config_body = resp.body or ""

        if not accessible_git:
            return

        # Check for credentials in .git/config
        has_creds = False
        if git_config_body:
            for pattern in self.CREDENTIAL_PATTERNS:
                if pattern.search(git_config_body):
                    has_creds = True
                    break

        if has_creds:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Git config contains credentials: {service.host}",
                    description="Remote URL with embedded token/password found in .git/config",
                    severity="critical",
                    evidence=f"Credential pattern found in .git/config (redacted). Accessible paths: {', '.join(accessible_git)}",
                    host=service.host,
                    discriminator="git-config-credentials",
                    target=service,
                    raw_data={"accessible_paths": accessible_git},
                )
            )
        else:
            recoverable = len(accessible_git) >= 3
            severity = "critical" if recoverable else "high"
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Git repository exposed: {service.host}",
                    description=f"{len(accessible_git)} git metadata files accessible — "
                    f"{'full source code likely recoverable' if recoverable else 'partial exposure'}",
                    severity=severity,
                    evidence=f"Accessible: {', '.join(accessible_git)}",
                    host=service.host,
                    discriminator="git-exposed",
                    target=service,
                    raw_data={"accessible_paths": accessible_git},
                )
            )

    async def _check_svn(
        self, client: AsyncHttpClient, service: Service, result: CheckResult
    ) -> None:
        """Probe SVN metadata."""
        resp = await client.get(service.with_path("/.svn/entries"))
        if not resp.error and resp.status_code == 200:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"SVN metadata exposed: {service.host}",
                    description=".svn/entries is accessible — source code may be recoverable",
                    severity="high",
                    evidence=fmt_status_evidence(
                        service.with_path("/.svn/entries"),
                        200,
                        resp.body[:200] if resp.body else "",
                    ),
                    host=service.host,
                    discriminator="svn-exposed",
                    target=service,
                )
            )

    @staticmethod
    def _get_accessible_paths(service: Service, context: dict) -> list[str]:
        """Get accessible paths from path_probe context."""
        paths_key = f"paths_{service.port}"
        paths_data = context.get("discovered_paths", {})
        if isinstance(paths_data, dict) and paths_key in paths_data:
            return paths_data[paths_key].get("accessible", [])
        # Also check top-level for backwards compat
        if paths_key in context:
            return context[paths_key].get("accessible", [])
        return []
