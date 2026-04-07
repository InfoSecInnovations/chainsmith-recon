"""
app/checks/mcp/template_injection.py - Resource Template Injection

Tests MCP resource templates for injection via template parameters.
Enumerates resource templates via resources/templates/list, then
probes parameters with injection payloads.

Safety: read-only, no destructive payloads.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/server/resources/
  CWE-89 SQL Injection
  CWE-22 Path Traversal
  CWE-78 OS Command Injection
"""

import json
import re
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.checks.mcp.invocation_safety import cap_response
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

# Injection payloads by type
INJECTION_PAYLOADS = {
    "sql": [
        ("' OR '1'='1", "SQL tautology"),
        ("1; SELECT 1--", "SQL statement termination"),
        ("UNION SELECT NULL--", "SQL UNION injection"),
    ],
    "path_traversal": [
        ("../../etc/passwd", "relative path traversal"),
        ("..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows traversal"),
        ("%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded traversal"),
    ],
    "command": [
        ("; echo chainsmith-probe", "command chaining"),
        ("| echo chainsmith-probe", "pipe injection"),
        ("`echo chainsmith-probe`", "backtick injection"),
    ],
    "template_nesting": [
        ("{other_param}", "recursive template"),
        ("${env:PATH}", "environment variable expansion"),
        ("{{7*7}}", "template expression"),
    ],
}

# URI template parameter pattern: {param_name}
TEMPLATE_PARAM_RE = re.compile(r"\{(\w+)\}")


class ResourceTemplateInjectionCheck(BaseCheck):
    """
    Test MCP resource template parameters for injection vulnerabilities.

    Enumerates resource templates, identifies parameters, and probes
    each with SQL, path traversal, command, and template injection payloads.
    """

    name = "mcp_template_injection"
    description = "Test MCP resource template parameters for injection"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_template_injection_results"]
    service_types = ["ai", "api", "http"]

    timeout_seconds = 90.0
    intrusive = True

    reason = "MCP resource templates with unsanitized parameters can lead to SQL injection, path traversal, or command injection"
    references = [
        "MCP Specification - Resources - https://spec.modelcontextprotocol.io/specification/server/resources/",
        "CWE-89 SQL Injection",
        "CWE-22 Path Traversal",
        "CWE-78 OS Command Injection",
    ]
    techniques = ["template injection", "parameter fuzzing", "input validation testing"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        injection_results = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")

            if not server_url:
                continue

            try:
                async with AsyncHttpClient(cfg) as client:
                    # Step 1: Enumerate resource templates
                    templates = await self._enumerate_templates(client, server_url)

                    if not templates:
                        continue

                    # Step 2: Test each template's parameters
                    for template in templates:
                        uri_template = template.get("uriTemplate", "")
                        params = TEMPLATE_PARAM_RE.findall(uri_template)

                        if not params:
                            continue

                        for param in params:
                            for inj_type, payloads in INJECTION_PAYLOADS.items():
                                for payload, desc in payloads:
                                    # Build URI with injection in this parameter
                                    test_uri = uri_template
                                    for p in params:
                                        if p == param:
                                            test_uri = test_uri.replace(f"{{{p}}}", payload)
                                        else:
                                            test_uri = test_uri.replace(f"{{{p}}}", "test")

                                    probe = await self._probe_template(client, server_url, test_uri)
                                    injection_results.append(
                                        {
                                            "template": uri_template,
                                            "param": param,
                                            "injection_type": inj_type,
                                            "payload": payload,
                                            "result": probe,
                                        }
                                    )

                                    if probe["vulnerable"]:
                                        severity = self._injection_severity(inj_type, probe)
                                        result.observations.append(
                                            build_observation(
                                                check_name=self.name,
                                                title=f"Resource template {inj_type} injection: parameter '{param}' is vulnerable",
                                                description=(
                                                    f"Template '{uri_template}' parameter '{param}' "
                                                    f"is vulnerable to {desc}. "
                                                    f"Payload '{payload}' was processed without sanitization."
                                                ),
                                                severity=severity,
                                                evidence=(
                                                    f"Template: {uri_template}\n"
                                                    f"Parameter: {param}\n"
                                                    f"Payload: {payload}\n"
                                                    f"Response: {cap_response(probe.get('body', ''))[:200]}"
                                                ),
                                                host=host,
                                                discriminator=f"tmpl-{inj_type}-{param}",
                                                raw_data={
                                                    "template": uri_template,
                                                    "param": param,
                                                    "payload": payload,
                                                },
                                            )
                                        )
                                        # Found injection in this param for this type, skip remaining payloads
                                        break

                    # If templates exist but no injection found
                    if templates and not any(
                        f.check_name == self.name and f.severity != "info" for f in result.observations
                    ):
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Resource template parameters properly validated",
                                description=f"Tested {len(templates)} resource templates, no injection vulnerabilities found.",
                                severity="info",
                                evidence=f"Templates tested: {len(templates)}\nPayloads per param: {sum(len(p) for p in INJECTION_PAYLOADS.values())}",
                                host=host,
                                discriminator="template-safe",
                            )
                        )

            except Exception as e:
                result.errors.append(f"Template injection on {server_url}: {e}")

        if injection_results:
            result.outputs["mcp_template_injection_results"] = injection_results

        return result

    async def _enumerate_templates(self, client, server_url: str) -> list[dict]:
        """Enumerate resource templates via resources/templates/list."""
        resp = await client.post(
            server_url,
            json={"jsonrpc": "2.0", "method": "resources/templates/list", "id": 1},
            headers={"Content-Type": "application/json"},
        )

        if resp.error or resp.status_code != 200 or not resp.body:
            return []

        try:
            data = json.loads(resp.body)
            result = data.get("result", data)
            if isinstance(result, dict) and "resourceTemplates" in result:
                return result["resourceTemplates"]
            if isinstance(result, list):
                return result
        except (json.JSONDecodeError, TypeError):
            pass
        return []

    async def _probe_template(self, client, server_url: str, uri: str) -> dict:
        """Probe a resource URI and check for injection indicators."""
        resp = await client.post(
            server_url,
            json={
                "jsonrpc": "2.0",
                "method": "resources/read",
                "params": {"uri": uri},
                "id": 1,
            },
            headers={"Content-Type": "application/json"},
        )

        probe = {
            "vulnerable": False,
            "body": "",
            "status": resp.status_code if not resp.error else None,
            "indicator": None,
        }

        if resp.error:
            return probe

        body = resp.body or ""
        probe["body"] = body
        probe["status"] = resp.status_code

        if resp.status_code != 200:
            # Check if error message reveals injection
            if any(
                kw in body.lower()
                for kw in [
                    "sql",
                    "syntax error",
                    "unterminated",
                    "unexpected",
                    "operand",
                    "column",
                    "table",
                ]
            ):
                probe["vulnerable"] = True
                probe["indicator"] = "sql_error"
            return probe

        # Check for successful injection indicators
        try:
            data = json.loads(body)
            if isinstance(data, dict) and "error" in data:
                error_msg = str(data["error"]).lower()
                if any(
                    kw in error_msg
                    for kw in [
                        "sql",
                        "syntax",
                        "column",
                        "table",
                        "relation",
                        "no such",
                        "permission",
                    ]
                ):
                    probe["vulnerable"] = True
                    probe["indicator"] = "sql_error_in_rpc"
                return probe

            result = data.get("result", data)
            if result and str(result) not in ("{}", "[]", "None", '""'):
                # Got actual content — check if it's the injected data
                result_str = str(result).lower()
                if any(
                    kw in result_str
                    for kw in [
                        "root:",
                        "/bin/bash",  # path traversal success
                        "chainsmith-probe",  # command injection success
                        "49",  # 7*7 template injection
                    ]
                ):
                    probe["vulnerable"] = True
                    probe["indicator"] = "content_injection"
        except (json.JSONDecodeError, TypeError):
            pass

        return probe

    def _injection_severity(self, inj_type: str, probe: dict) -> str:
        """Determine severity based on injection type and result."""
        if inj_type == "sql":
            if probe.get("indicator") == "content_injection":
                return "critical"
            return "high"  # SQL error = parameter passed unsanitized
        elif inj_type == "path_traversal":
            if probe.get("indicator") == "content_injection":
                return "critical"
            return "high"
        elif inj_type == "command":
            return "critical" if probe.get("indicator") == "content_injection" else "high"
        elif inj_type == "template_nesting":
            return "medium"
        return "medium"
