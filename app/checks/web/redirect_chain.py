"""
app/checks/web/redirect_chain.py - HTTP Redirect Chain Analysis

Follows redirect chains (up to 10 hops) and analyzes each step.
Checks for:
- Missing HTTP -> HTTPS upgrade
- Open redirects (arbitrary destination accepted)
- Excessive redirect chain length
- Cross-domain redirects
"""

import logging
from typing import Any
from urllib.parse import urljoin, urlparse

from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

logger = logging.getLogger(__name__)

MAX_HOPS = 10

# Paths commonly vulnerable to open redirect
REDIRECT_PARAM_PATHS = [
    "/redirect?url={target}",
    "/redirect?next={target}",
    "/login?next={target}",
    "/login?return_to={target}",
    "/logout?redirect={target}",
    "/auth/callback?redirect_uri={target}",
    "/go?to={target}",
    "/out?url={target}",
]

OPEN_REDIRECT_TARGET = "https://evil.example.com"


class RedirectChainCheck(ServiceIteratingCheck):
    """Analyze HTTP redirect chains for security issues."""

    name = "redirect_chain"
    description = "Follow redirect chains and check for HTTP->HTTPS, open redirects, excessive hops"
    intrusive = True

    conditions = [CheckCondition("services", "truthy")]
    produces = ["redirect_info"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = (
        "Missing HTTPS redirects expose traffic to interception; open redirects enable phishing"
    )
    references = ["OWASP WSTG-CLNT-04", "CWE-601"]
    techniques = ["redirect chain analysis", "open redirect testing"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        redirect_info: dict[str, Any] = {}

        # Use follow_redirects=False so we can inspect each hop
        cfg = HttpConfig(
            timeout_seconds=10.0,
            verify_ssl=False,
            follow_redirects=False,
        )

        try:
            async with AsyncHttpClient(cfg) as client:
                # 1. Check HTTP -> HTTPS redirect on root
                await self._check_https_redirect(client, service, result, redirect_info)

                # 2. Follow full redirect chain from root
                await self._rate_limit()
                chain = await self._follow_chain(client, service.url)
                if len(chain) > 1:
                    redirect_info["chain"] = [step["url"] for step in chain]
                    redirect_info["chain_length"] = len(chain)

                    if len(chain) > 3:
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Long redirect chain: {len(chain)} hops",
                                description=f"Redirect chain from {service.url} traverses {len(chain)} hops before reaching final destination",
                                severity="low",
                                evidence=f"Chain: {' -> '.join(step['url'] for step in chain[:6])}{'...' if len(chain) > 6 else ''}",
                                host=service.host,
                                discriminator="long-chain",
                                target=service,
                                raw_data={"chain": [s["url"] for s in chain]},
                            )
                        )

                    # Check for cross-domain redirects
                    domains = set()
                    for step in chain:
                        parsed = urlparse(step["url"])
                        if parsed.hostname:
                            domains.add(parsed.hostname)
                    external = domains - {service.host}
                    if external:
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title=f"Cross-domain redirect to: {', '.join(sorted(external))}",
                                description="Redirect chain passes through external domain(s)",
                                severity="info",
                                evidence=f"Domains in chain: {', '.join(sorted(domains))}",
                                host=service.host,
                                discriminator="cross-domain",
                                target=service,
                            )
                        )

                # 3. Test for open redirects
                await self._check_open_redirect(client, service, result, redirect_info)

        except Exception as e:
            result.errors.append(f"Redirect chain error: {e}")

        result.outputs["redirect_info"] = redirect_info
        return result

    async def _check_https_redirect(
        self,
        client: AsyncHttpClient,
        service: Service,
        result: CheckResult,
        info: dict,
    ) -> None:
        """Check if HTTP root redirects to HTTPS."""
        if service.scheme == "https":
            return  # Already HTTPS, nothing to check

        resp = await client.get(service.url)
        if resp.error:
            return

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if location.startswith("https://"):
                info["https_redirect"] = True
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"HTTP to HTTPS redirect present: {service.host}",
                        description="HTTP requests are redirected to HTTPS (good)",
                        severity="info",
                        evidence=f"HTTP {resp.status_code} -> {location}",
                        host=service.host,
                        discriminator="https-redirect-ok",
                        target=service,
                    )
                )
                return

        # HTTP service serves content without redirecting to HTTPS
        info["https_redirect"] = False
        result.observations.append(
            build_observation(
                check_name=self.name,
                title=f"No HTTP to HTTPS redirect: {service.host}",
                description="HTTP requests are not redirected to HTTPS, content is served over plain HTTP",
                severity="medium",
                evidence=f"GET {service.url} -> HTTP {resp.status_code} (no redirect to HTTPS)",
                host=service.host,
                discriminator="no-https-redirect",
                target=service,
                references=["CWE-319"],
            )
        )

    async def _follow_chain(self, client: AsyncHttpClient, url: str) -> list[dict]:
        """Follow redirect chain and return list of {url, status_code} hops."""
        chain = []
        visited = set()
        current_url = url

        for _ in range(MAX_HOPS):
            if current_url in visited:
                break  # Loop detected
            visited.add(current_url)

            resp = await client.get(current_url)
            chain.append({"url": current_url, "status_code": resp.status_code})

            if resp.error or resp.status_code not in (301, 302, 303, 307, 308):
                break

            location = resp.headers.get("location", "")
            if not location:
                break

            # Resolve relative redirect
            current_url = urljoin(current_url, location)
            await self._rate_limit()

        return chain

    async def _check_open_redirect(
        self,
        client: AsyncHttpClient,
        service: Service,
        result: CheckResult,
        info: dict,
    ) -> None:
        """Test common redirect parameters for open redirect."""
        open_redirects: list[str] = []

        for path_template in REDIRECT_PARAM_PATHS:
            path = path_template.format(target=OPEN_REDIRECT_TARGET)
            url = service.with_path(path)

            await self._rate_limit()
            resp = await client.get(url)

            if resp.error:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if OPEN_REDIRECT_TARGET in location:
                    open_redirects.append(path)
                    result.observations.append(
                        build_observation(
                            check_name=self.name,
                            title=f"Open redirect: {service.host}{path_template.split('?')[0]}",
                            description="Endpoint accepts arbitrary redirect destination via URL parameter",
                            severity="medium",
                            evidence=f"GET {url} -> HTTP {resp.status_code} Location: {location}",
                            host=service.host,
                            discriminator=f"open-redirect-{path_template.split('?')[0].replace('/', '-').strip('-')}",
                            target=service,
                            target_url=url,
                            references=["CWE-601", "OWASP WSTG-CLNT-04"],
                        )
                    )

        if open_redirects:
            info["open_redirects"] = open_redirects
