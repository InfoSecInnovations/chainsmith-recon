"""
app/checks/agent/agent_framework_version/check.py - Framework Version Fingerprinting

Go beyond framework identification to version detection. Known vulnerable
versions can be identified from error formatting, capability sets, headers,
and behavioral differences.

Known vulnerable versions:
- LangChain < 0.0.325: PythonREPLTool arbitrary code execution
- LangChain < 0.0.350: LCEL deserialization issues
- LangServe early versions: Input validation bypasses
- AutoGen < 0.2: Default code execution without sandboxing

**Probe/grade.** The probe fetches the endpoints, triggers
error responses, and reads the OpenAPI/docs metadata, recording every exchange;
`grade()` re-reads them, rebuilds the `framework -> version` map, and cross-refs
the vulnerability database. `_reading()` is the one parser both halves call
(§0.12), and it now records *where* each version came from so `grade()` can
weight its confidence.

**Fixed**: severity is categorical — read from the vuln DB
(`vuln-*`) or `info` for a version with no known issue — so no grader above the
rule tier is called. No `observations:` map, for the `ai_model_info_check`
reason: the discriminator embeds the framework and version
(`vuln-<fw>-<version>` / `version-<fw>`), so a map cannot enumerate it;
`provisional_for()` falls to `default: info` and `grade()` places the real one.

Confidence is where the split pays: a version read from a server header is far
stronger than one scraped out of an error message by a `version[:=]([\\d.]+)`
regex that matches any number, and both are weaker than the naive dotted-int
`_version_lte` comparison that decides "vulnerable".

References:
  https://owasp.org/www-project-top-10-for-large-language-model-applications/
  https://nvd.nist.gov/vuln/detail/CVE-2023-36188
"""

import json
import re
from typing import Any

from app.capture.models import Exchange
from app.checks.base import CheckCondition, CheckResult, Service, ServiceIteratingCheck
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

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

META_PATHS = ("/openapi.json", "/docs", "/redoc")
ERROR_PATHS = ("/invoke", "/nonexistent_endpoint_probe")

# Confidence per source of a version string
_SOURCE_CONFIDENCE = {
    "header": 0.9,
    "metadata": 0.75,
    "error": 0.6,
}


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

    # ══ Probe ════════════════════════════════════════════════════════

    async def check_service(self, service: Service, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""

        agent_endpoints = context.get("agent_endpoints", [])
        service_endpoints = [
            ep for ep in agent_endpoints if ep.get("service", {}).get("host") == service.host
        ]
        if not service_endpoints:
            return result

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)
        candidate = self.create_candidate(host=service.host, target=service, target_url=service.url)

        try:
            async with AsyncHttpClient(cfg) as client:
                # 1. Version headers on known endpoints
                for ep in service_endpoints:
                    url = ep.get("url", service.url)
                    resp = await client.get(url)
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

                # 2. Trigger error responses to extract version info
                for path in ERROR_PATHS:
                    url = service.with_path(path)
                    body = {"__invalid__": True}
                    resp = await client.post(url, json=body, headers=JSON_HEADERS)
                    candidate.attach(
                        exchange_from_response(
                            resp,
                            check_name=self.name,
                            scan_id=scan_id,
                            host=service.host,
                            method="POST",
                            request_headers=JSON_HEADERS,
                            request_json=body,
                        )
                    )

                # 3. /openapi.json or /docs for version metadata
                for meta_path in META_PATHS:
                    url = service.with_path(meta_path)
                    resp = await client.get(url)
                    candidate.attach(
                        exchange_from_response(
                            resp, check_name=self.name, scan_id=scan_id, host=service.host
                        )
                    )

        except Exception as e:
            result.errors.append(f"{service.url}: {e}")

        if candidate.exchanges:
            result.candidates.append(candidate)
            versions = self._versions_plain(self._reading(candidate.exchanges))
            if versions:
                result.outputs["framework_versions"] = versions

        return result

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        reading = self._reading(list(evidence))
        ids = evidence.ids()
        verdicts: list[Verdict] = []

        for framework, found in reading.items():
            version = found["version"]
            source = found["source"]
            base_conf = _SOURCE_CONFIDENCE.get(source, 0.5)
            vuln = self._check_vulnerabilities(framework, version)

            if vuln:
                confidence = round(min(base_conf, 0.8), 2)
                verdicts.append(
                    Verdict(
                        severity=vuln["severity"],
                        confidence=confidence,
                        discriminator=f"vuln-{framework}-{version}",
                        title=(
                            f"Vulnerable framework version: {framework} {version} "
                            f"({vuln['cve'] or vuln['description']})"
                        ),
                        description=(
                            f"Detected {framework} version {version} which is affected by: "
                            f"{vuln['description']}. "
                            f"{'CVE: ' + vuln['cve'] + '. ' if vuln['cve'] else ''}"
                            f"Vulnerable versions: <= {vuln['max_version']}."
                        ),
                        evidence=(
                            f"Framework: {framework}\nVersion: {version}\n"
                            f"Detected via: {source}\nVulnerable range: <= {vuln['max_version']}"
                        ),
                        reasoning=self._reason_vuln(source),
                        signals={"framework": framework, "version": version, "source": source},
                        references=self.references,
                        raw_data={
                            "framework": framework,
                            "version": version,
                            "source": source,
                            "vulnerability": vuln,
                        },
                        tier=ctx.tier,
                        evidence_ids=ids,
                    )
                )
            else:
                verdicts.append(
                    Verdict(
                        severity="info",
                        confidence=round(base_conf, 2),
                        discriminator=f"version-{framework}",
                        title=f"Framework version detected: {framework} {version}",
                        description=(
                            f"Detected {framework} version {version}. "
                            "No known vulnerabilities for this version."
                        ),
                        evidence=f"Framework: {framework}\nVersion: {version}\nDetected via: {source}",
                        reasoning=self._reason_detect(source),
                        signals={"framework": framework, "version": version, "source": source},
                        raw_data={"framework": framework, "version": version, "source": source},
                        tier=ctx.tier,
                        evidence_ids=ids,
                    )
                )

        return verdicts

    def _reason_vuln(self, source: str) -> str:
        return (
            f"the version was read from a {source} signal, and 'vulnerable' rests on a naive "
            "dotted-integer `<=` comparison that ignores pre-release and packaging suffixes; a "
            "version string scraped from an error message by a catch-all `version:([\\d.]+)` "
            "regex can also belong to an unrelated component"
        )

    def _reason_detect(self, source: str) -> str:
        if source == "header":
            return "the framework declared this version in a response header — a self-report, but a direct one"
        if source == "metadata":
            return "read from the OpenAPI/docs `info.version`, tied to the framework only by a title match — it may be the app's own version rather than the framework's"
        return "scraped from response text by a regex that matches any dotted number, so the framework attribution and the value are both soft"

    # ── The parser both halves share ─────────────────────────────────

    def _reading(self, exchanges: list[Exchange]) -> dict:
        """Rebuild `framework -> {version, source}` off the recorded exchanges.

        Header signals win over error scrapes win over metadata, matching the
        original's overwrite/`setdefault` order.
        """
        versions: dict[str, dict] = {}

        # Pass 1: headers on endpoint GETs (strongest; overwrites)
        for exchange in exchanges:
            if exchange.request_method != "GET" or exchange.error:
                continue
            if self._is_meta(exchange.request_url):
                continue
            self._headers_into(exchange, versions)

        # Pass 2: error-message scrapes on the POSTs (setdefault)
        for exchange in exchanges:
            if exchange.request_method == "POST" and exchange.response_body:
                self._errors_into(exchange.response_body, versions)

        # Pass 3: OpenAPI/docs metadata on the meta GETs (setdefault)
        for exchange in exchanges:
            if exchange.request_method != "GET" or exchange.error:
                continue
            if not self._is_meta(exchange.request_url) or exchange.response_status != 200:
                continue
            self._metadata_into(exchange.response_body or "", versions)

        return versions

    def _versions_plain(self, reading: dict) -> dict:
        """The `produces` shape: framework -> version string."""
        return {fw: found["version"] for fw, found in reading.items()}

    @staticmethod
    def _is_meta(url: str | None) -> bool:
        return any((url or "").endswith(p) for p in META_PATHS)

    def _headers_into(self, exchange: Exchange, versions: dict) -> None:
        headers_lower = {k.lower(): v for k, v in (exchange.response_headers or {}).items()}
        for framework, header in VERSION_HEADERS.items():
            val = headers_lower.get(header)
            if val:
                versions[framework] = {"version": val.strip(), "source": "header"}

    def _errors_into(self, body: str, versions: dict) -> None:
        for pattern in VERSION_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                version = match.group(1)
                pattern_str = pattern.pattern.lower()
                for fw in ["langchain", "langserve", "langgraph", "autogen", "crewai"]:
                    if fw in pattern_str:
                        versions.setdefault(fw, {"version": version, "source": "error"})
                        break

    def _metadata_into(self, body: str, versions: dict) -> None:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(data, dict):
            return
        info = data.get("info", {})
        if not isinstance(info, dict):
            return
        version = info.get("version")
        title = (info.get("title") or "").lower()
        if version:
            for fw in ["langserve", "langgraph", "langchain"]:
                if fw in title:
                    versions.setdefault(fw, {"version": str(version), "source": "metadata"})
                    break

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
            while len(v_parts) < len(m_parts):
                v_parts.append(0)
            while len(m_parts) < len(v_parts):
                m_parts.append(0)
            return v_parts <= m_parts
        except (ValueError, TypeError):
            return False
