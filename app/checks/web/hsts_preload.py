"""
app/checks/web/hsts_preload.py - HSTS Preload Verification

Checks whether a domain with an HSTS header is on the Chromium HSTS
preload list. Domains not preloaded are vulnerable to SSL stripping
on first visit, even with HSTS headers present.

Uses the hstspreload.org API for verification.
"""

import logging
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding

logger = logging.getLogger(__name__)


class HSTSPreloadCheck(ServiceIteratingCheck):
    """Verify HSTS preload status for domains with HSTS headers."""

    name = "hsts_preload"
    description = "Check if domain is on the HSTS preload list (Chromium)"

    conditions = [CheckCondition("services", "truthy")]
    produces = ["hsts_preload_info"]
    service_types = ["http", "html", "api"]

    timeout_seconds = 30.0
    delay_between_targets = 0.5

    reason = "Domains not on the HSTS preload list are vulnerable to SSL stripping on first visit"
    references = ["RFC 6797", "hstspreload.org"]
    techniques = ["HSTS preload verification", "transport security analysis"]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        preload_info: dict[str, Any] = {"checked": False}

        # Only relevant for HTTPS services or services with HSTS headers
        hsts_header = self._get_hsts_header(service, context)

        if not hsts_header and service.scheme != "https":
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"No HSTS header: {service.host}",
                description="No HSTS header present — HSTS preload check not applicable",
                severity="info",
                evidence="No Strict-Transport-Security header detected",
                host=service.host,
                discriminator="no-hsts",
                target=service,
            ))
            result.outputs["hsts_preload_info"] = preload_info
            return result

        # If no header found in context, fetch it ourselves
        if not hsts_header:
            cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
            try:
                async with AsyncHttpClient(cfg) as client:
                    await self._rate_limit()
                    resp = await client.get(service.url)
                    if not resp.error:
                        hsts_header = resp.headers.get("strict-transport-security", "")
            except Exception as e:
                result.errors.append(f"HSTS header fetch error: {e}")

        if not hsts_header:
            result.outputs["hsts_preload_info"] = preload_info
            return result

        # Parse HSTS header directives
        has_preload_directive = "preload" in hsts_header.lower()
        has_include_subdomains = "includesubdomains" in hsts_header.lower()

        # Extract max-age
        max_age = self._parse_max_age(hsts_header)

        # Check preload list via hstspreload.org API
        is_preloaded = False
        preload_status = "unknown"

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=True)
        try:
            async with AsyncHttpClient(cfg) as client:
                await self._rate_limit()
                api_url = f"https://hstspreload.org/api/v2/status?domain={service.host}"
                resp = await client.get(api_url)
                if not resp.error and resp.status_code == 200:
                    try:
                        data = resp.json()
                        preload_status = data.get("status", "unknown")
                        is_preloaded = preload_status == "preloaded"
                        preload_info["api_status"] = preload_status
                    except Exception:
                        preload_status = "api_error"
                else:
                    preload_status = "api_unreachable"
        except Exception as e:
            result.errors.append(f"HSTS preload API error: {e}")
            preload_status = "api_error"

        preload_info.update({
            "checked": True,
            "preloaded": is_preloaded,
            "has_preload_directive": has_preload_directive,
            "has_include_subdomains": has_include_subdomains,
            "max_age": max_age,
            "status": preload_status,
        })

        # Generate findings based on preload status
        if is_preloaded:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Domain is HSTS preloaded: {service.host}",
                description="Domain is on the Chromium HSTS preload list — browsers enforce HTTPS on first visit",
                severity="info",
                evidence=f"hstspreload.org status: {preload_status} | HSTS: {hsts_header[:200]}",
                host=service.host,
                discriminator="preloaded",
                target=service,
                references=["RFC 6797"],
            ))
        elif has_preload_directive and not is_preloaded:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"HSTS preload directive present but not yet preloaded: {service.host}",
                description="The HSTS header includes the preload directive, but the domain is not yet on the preload list. Submission may be pending or rejected.",
                severity="info",
                evidence=f"hstspreload.org status: {preload_status} | HSTS: {hsts_header[:200]}",
                host=service.host,
                discriminator="preload-pending",
                target=service,
                references=["RFC 6797", "hstspreload.org"],
            ))
        elif hsts_header and not is_preloaded:
            # HSTS present but not preloaded — first-visit vulnerability
            missing = []
            if not has_preload_directive:
                missing.append("preload directive")
            if not has_include_subdomains:
                missing.append("includeSubDomains")
            if max_age is not None and max_age < 31536000:
                missing.append(f"max-age too short ({max_age}, need >= 31536000)")

            detail = f"Missing: {', '.join(missing)}" if missing else "Preload list submission required"

            result.findings.append(build_finding(
                check_name=self.name,
                title=f"HSTS header present but domain not preloaded: {service.host}",
                description=f"HSTS is configured but the domain is not on the browser preload list — first visit is still vulnerable to SSL stripping. {detail}",
                severity="low",
                evidence=f"HSTS: {hsts_header[:200]} | Preload status: {preload_status}",
                host=service.host,
                discriminator="not-preloaded",
                target=service,
                references=["RFC 6797", "hstspreload.org"],
            ))

        result.outputs["hsts_preload_info"] = preload_info
        return result

    def _get_hsts_header(self, service: Service, context: dict[str, Any]) -> str:
        """Try to get HSTS header from header_analysis context output."""
        # Check header_analysis output from earlier check
        header_info = context.get("header_info", {})
        if isinstance(header_info, dict):
            headers = header_info.get("headers", {})
            if isinstance(headers, dict):
                return headers.get("strict-transport-security", "")
        return ""

    def _parse_max_age(self, hsts_header: str) -> int | None:
        """Extract max-age value from HSTS header."""
        for part in hsts_header.split(";"):
            part = part.strip().lower()
            if part.startswith("max-age"):
                try:
                    return int(part.split("=", 1)[1].strip())
                except (ValueError, IndexError):
                    pass
        return None
