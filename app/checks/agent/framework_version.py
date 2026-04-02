"""
app/checks/agent/framework_version.py - Framework Version Fingerprinting

Go beyond framework identification to version detection. Known vulnerable
versions can be identified from error formatting, capability sets, headers,
and behavioral differences.

Known vulnerable versions:
- LangChain < 0.0.325: PythonREPLTool arbitrary code execution
- LangChain < 0.0.350: LCEL deserialization issues
- LangServe early versions: Input validation bypasses
- AutoGen < 0.2: Default code execution without sandboxing

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
  https://nvd.nist.gov/vuln/detail/CVE-2023-36188
"""

import json
import re
from typing import Any

from app.checks.base import ServiceIteratingCheck, CheckResult, CheckCondition, Service
from app.lib.http import AsyncHttpClient, HttpConfig
from app.lib.findings import build_finding


# Known vulnerable version ranges per framework
VULNERABLE_VERSIONS = {
    "langchain": [
        {
            "max_version": "0.0.325",
            "cve": "CVE-2023-36188",
            "description": "PythonREPLTool arbitrary code execution",
            "severity": "high",
        },
        {
            "max_version": "0.0.350",
            "cve": None,
            "description": "LCEL deserialization vulnerabilities",
            "severity": "high",
        },
    ],
    "langserve": [
        {
            "max_version": "0.0.21",
            "cve": None,
            "description": "Input validation bypass in early versions",
            "severity": "medium",
        },
    ],
    "autogen": [
        {
            "max_version": "0.2.0",
            "cve": None,
            "description": "Default code execution without sandboxing",
            "severity": "high",
        },
    ],
}

# Version detection headers
VERSION_HEADERS = {
    "langserve": "x-langserve-version",
    "langgraph": "x-langgraph-version",
}

# Error patterns that reveal version info
VERSION_ERROR_PATTERNS = [
    re.compile(r"langchain[=\s]+([\d.]+)", re.IGNORECASE),
    re.compile(r"langserve[=\s]+([\d.]+)", re.IGNORECASE),
    re.compile(r"langgraph[=\s]+([\d.]+)", re.IGNORECASE),
    re.compile(r"autogen[=\s]+([\d.]+)", re.IGNORECASE),
    re.compile(r"crewai[=\s]+([\d.]+)", re.IGNORECASE),
    re.compile(r"version[\"':=\s]+([\d.]+)", re.IGNORECASE),
]


class AgentFrameworkVersionCheck(ServiceIteratingCheck):
    """
    Fingerprint agent framework versions for known vulnerabilities.

    Extracts version information from headers, error messages, and
    behavioral signatures, then cross-references against a database
    of known vulnerable versions.
    """

    name = "agent_framework_version"
    description = "Fingerprint agent framework versions and check for known vulnerabilities"

    conditions = [CheckCondition("agent_endpoints", "truthy")]
    produces = ["framework_versions"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 60.0
    delay_between_targets = 0.2

    reason = (
        "Outdated agent frameworks may contain known RCE, deserialization, "
        "or code execution vulnerabilities"
    )
    references = [
        "OWASP LLM Top 10 - LLM06 Sensitive Information Disclosure",
        "CVE-2023-36188 - LangChain PythonREPLTool RCE",
    ]
    techniques = [
        "version fingerprinting",
        "header analysis",
        "error message analysis",
    ]

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        agent_endpoints = context.get("agent_endpoints", [])
        frameworks = context.get("agent_frameworks", [])
        service_endpoints = [
            ep for ep in agent_endpoints
            if ep.get("service", {}).get("host") == service.host
        ]
        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        versions = {}  # framework -> version string

        try:
            async with AsyncHttpClient(cfg) as client:
                # 1. Check version headers on known endpoints
                for ep in service_endpoints:
                    url = ep.get("url", service.url)
                    resp = await client.get(url)
                    if resp.error:
                        continue
                    self._extract_version_headers(resp, versions)

                # 2. Trigger error responses to extract version info
                error_paths = ["/invoke", "/nonexistent_endpoint_probe"]
                for path in error_paths:
                    url = service.with_path(path)
                    # Send malformed input to trigger detailed errors
                    resp = await client.post(
                        url,
                        json={"__invalid__": True},
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.body:
                        self._extract_version_from_errors(resp.body, versions)

                # 3. Check /openapi.json or /docs for version metadata
                for meta_path in ["/openapi.json", "/docs", "/redoc"]:
                    url = service.with_path(meta_path)
                    resp = await client.get(url)
                    if resp.error or resp.status_code != 200:
                        continue
                    self._extract_version_from_metadata(resp.body or "", versions)

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        # Check detected versions against vulnerability database
        for framework, version in versions.items():
            vuln = self._check_vulnerabilities(framework, version)
            if vuln:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title=f"Vulnerable framework version: {framework} {version} ({vuln['cve'] or vuln['description']})",
                        description=(
                            f"Detected {framework} version {version} which is affected by: "
                            f"{vuln['description']}. "
                            f"{'CVE: ' + vuln['cve'] + '. ' if vuln['cve'] else ''}"
                            f"Vulnerable versions: <= {vuln['max_version']}."
                        ),
                        severity=vuln["severity"],
                        evidence=f"Framework: {framework}\nVersion: {version}\nVulnerable range: <= {vuln['max_version']}",
                        host=service.host,
                        discriminator=f"vuln-{framework}-{version}",
                        target=service,
                        target_url=service.url,
                        raw_data={"framework": framework, "version": version, "vulnerability": vuln},
                        references=self.references,
                    )
                )
            else:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title=f"Framework version detected: {framework} {version}",
                        description=f"Detected {framework} version {version}. No known vulnerabilities for this version.",
                        severity="info",
                        evidence=f"Framework: {framework}\nVersion: {version}",
                        host=service.host,
                        discriminator=f"version-{framework}",
                        target=service,
                        target_url=service.url,
                        raw_data={"framework": framework, "version": version},
                    )
                )

        if versions:
            result.outputs["framework_versions"] = versions

        return result

    def _extract_version_headers(self, resp, versions: dict) -> None:
        """Extract version from known framework headers."""
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        for framework, header in VERSION_HEADERS.items():
            val = headers_lower.get(header)
            if val:
                versions[framework] = val.strip()

    def _extract_version_from_errors(self, body: str, versions: dict) -> None:
        """Extract version numbers from error messages."""
        for pattern in VERSION_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                version = match.group(1)
                # Determine framework from pattern
                pattern_str = pattern.pattern.lower()
                for fw in ["langchain", "langserve", "langgraph", "autogen", "crewai"]:
                    if fw in pattern_str:
                        versions.setdefault(fw, version)
                        break

    def _extract_version_from_metadata(self, body: str, versions: dict) -> None:
        """Extract version from OpenAPI/docs metadata."""
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                info = data.get("info", {})
                if isinstance(info, dict):
                    version = info.get("version")
                    title = (info.get("title") or "").lower()
                    if version:
                        for fw in ["langserve", "langgraph", "langchain"]:
                            if fw in title:
                                versions.setdefault(fw, str(version))
                                break
        except (json.JSONDecodeError, TypeError):
            pass

    def _check_vulnerabilities(self, framework: str, version: str) -> dict | None:
        """Check if a framework version has known vulnerabilities."""
        fw_lower = framework.lower()
        vulns = VULNERABLE_VERSIONS.get(fw_lower, [])
        for vuln in vulns:
            if self._version_lte(version, vuln["max_version"]):
                return vuln
        return None

    @staticmethod
    def _version_lte(version: str, max_version: str) -> bool:
        """Compare version strings (simple numeric comparison)."""
        try:
            v_parts = [int(x) for x in version.split(".")[:4]]
            m_parts = [int(x) for x in max_version.split(".")[:4]]
            # Pad to equal length
            while len(v_parts) < len(m_parts):
                v_parts.append(0)
            while len(m_parts) < len(v_parts):
                m_parts.append(0)
            return v_parts <= m_parts
        except (ValueError, TypeError):
            return False
