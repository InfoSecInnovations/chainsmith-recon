"""
app/checks/web/webdav.py - Insecure WebDAV Detection

Probes HTTP services for WebDAV methods (PROPFIND, MKCOL, PUT).
If any succeed, WebDAV is enabled and likely misconfigured.

GATED: Requires checks.intrusive_web = true (opt-in).
"""

import uuid
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding
from app.lib.evidence import fmt_status_evidence


class WebDAVCheck(ServiceIteratingCheck):
    """Detect insecure WebDAV access on HTTP services."""

    name = "webdav_check"
    description = "Probe for WebDAV methods that allow file upload or directory listing"
    intrusive = True

    conditions = [CheckCondition("services", "truthy")]
    produces = ["webdav_findings"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 60.0
    delay_between_targets = 0.3

    reason = "WebDAV write access = arbitrary file upload = likely RCE path, superseding AI-specific findings"
    references = ["OWASP WSTG-CONF-06", "CWE-284"]
    techniques = ["WebDAV method probing", "HTTP method enumeration"]

    # Methods to test, in order of severity
    WEBDAV_METHODS = ["PROPFIND", "MKCOL", "PUT"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Gate: intrusive_web must be enabled
        if not self._is_intrusive_allowed():
            result.outputs["webdav_skipped"] = True
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        try:
            async with AsyncHttpClient(cfg) as client:
                # Test PROPFIND on root
                propfind_resp = await client._request("PROPFIND", service.url, headers={"Depth": "0"})
                if not propfind_resp.error and propfind_resp.status_code in range(200, 300):
                    result.findings.append(build_finding(
                        check_name=self.name,
                        title=f"WebDAV PROPFIND enabled: {service.host}",
                        description="PROPFIND returned success — WebDAV directory listing possible",
                        severity="high",
                        evidence=fmt_status_evidence(service.url, propfind_resp.status_code, propfind_resp.body[:200] if propfind_resp.body else ""),
                        host=service.host,
                        discriminator="propfind-enabled",
                        target=service,
                    ))

                # Test PUT with a non-destructive test file
                test_filename = f"chainsmith-webdav-test-{uuid.uuid4().hex[:8]}.txt"
                test_url = service.with_path(f"/{test_filename}")
                put_resp = await client._request(
                    "PUT", test_url,
                    data="chainsmith webdav test",
                    headers={"Content-Type": "text/plain"},
                )
                if not put_resp.error and put_resp.status_code in (200, 201, 204):
                    result.findings.append(build_finding(
                        check_name=self.name,
                        title=f"WebDAV write access: PUT accepted at {service.host}",
                        description="PUT request succeeded — arbitrary file upload possible via WebDAV",
                        severity="critical",
                        evidence=fmt_status_evidence(test_url, put_resp.status_code),
                        host=service.host,
                        discriminator="put-write-access",
                        target=service,
                    ))
                    # Clean up: try to delete the test file
                    await client._request("DELETE", test_url)

                elif not put_resp.error and put_resp.status_code == 401:
                    result.findings.append(build_finding(
                        check_name=self.name,
                        title=f"WebDAV methods require auth: {service.host}",
                        description="WebDAV PUT returned 401 — methods detected but require authentication",
                        severity="medium",
                        evidence=fmt_status_evidence(test_url, put_resp.status_code),
                        host=service.host,
                        discriminator="put-requires-auth",
                        target=service,
                    ))

                # Test MKCOL
                mkcol_path = f"/chainsmith-webdav-test-{uuid.uuid4().hex[:8]}/"
                mkcol_url = service.with_path(mkcol_path)
                mkcol_resp = await client._request("MKCOL", mkcol_url)
                if not mkcol_resp.error and mkcol_resp.status_code in (200, 201, 204):
                    result.findings.append(build_finding(
                        check_name=self.name,
                        title=f"WebDAV MKCOL enabled: {service.host}",
                        description="MKCOL succeeded — directory creation via WebDAV possible",
                        severity="critical",
                        evidence=fmt_status_evidence(mkcol_url, mkcol_resp.status_code),
                        host=service.host,
                        discriminator="mkcol-enabled",
                        target=service,
                    ))
                    # Clean up
                    await client._request("DELETE", mkcol_url)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        return result

    @staticmethod
    def _is_intrusive_allowed() -> bool:
        """Check if intrusive web checks are enabled in preferences."""
        try:
            from app.preferences import get_preferences
            return get_preferences().checks.intrusive_web
        except Exception:
            return False
