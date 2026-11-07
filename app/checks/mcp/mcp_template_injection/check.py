"""
app/checks/mcp/template_injection.py - Resource Template Injection

Tests MCP resource templates for injection via template parameters.
Enumerates resource templates via resources/templates/list, then
probes parameters with injection payloads.

Safety: read-only, no destructive payloads.

**Probe/grade.** The probe enumerates templates (recorded),
then for each parameter and payload sends one `resources/read` and records it.
`grade()` regenerates the injection library and the exact URIs the probe would
build, keys each recorded request's `params.uri` back to its
(template, param, injection type, payload) — the `rag_indirect_injection`
pattern, so a response is matched to its payload by the recorded request, never
positionally (§0.16) — and re-derives the vulnerability from the recorded
response. `_readings()` is the one parser both halves call (§0.12).

**Contextual**: whether a reflected error or echoed marker
is a real injection is a judgement, so severity is the grader's (the planned LLM tier). The
rule tier keeps the original severities and states its weakness in the
confidence — **a database error string can come from ordinary input validation**,
the template-expression result `49` (`{{7*7}}`) can appear by coincidence, and a
command marker is the very string the payload asked to be echoed, so a reflected
signal and an executed injection read alike here.

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

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.checks.mcp.invocation_safety import cap_response
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.datafiles import load_data
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Injection payloads by type. Shipped list: app/data/payloads/mcp_template_injection.yaml
# (operator-editable); this inline copy is the fallback. The YAML
# stores each payload as a [value, description] pair, unpacked like the original tuples.
_FALLBACK_INJECTION_PAYLOADS = {
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
INJECTION_PAYLOADS = load_data("payloads/mcp_template_injection.yaml", _FALLBACK_INJECTION_PAYLOADS)

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

    intrusive = True

    reason = "MCP resource templates with unsanitized parameters can lead to SQL injection, path traversal, or command injection"
    references = [
        "MCP Specification - Resources - https://spec.modelcontextprotocol.io/specification/server/resources/",
        "CWE-89 SQL Injection",
        "CWE-22 Path Traversal",
        "CWE-78 OS Command Injection",
    ]
    techniques = ["template injection", "parameter fuzzing", "input validation testing"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        mcp_servers = context.get("mcp_servers", [])
        injection_results = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")

            if not server_url:
                continue

            candidate = self.create_candidate(
                host=host, discriminator="template-injection", target_url=server_url
            )

            try:
                async with AsyncHttpClient(cfg) as client:
                    templates = await self._enumerate_templates(
                        client, server_url, scan_id, host, candidate
                    )
                    if not templates:
                        continue

                    for template in templates:
                        uri_template = template.get("uriTemplate", "")
                        params = TEMPLATE_PARAM_RE.findall(uri_template)
                        if not params:
                            continue

                        for param in params:
                            for _inj_type, payloads in INJECTION_PAYLOADS.items():
                                for payload, _desc in payloads:
                                    test_uri = self._build_uri(uri_template, params, param, payload)
                                    exchange = await self._probe_template(
                                        client, server_url, test_uri, scan_id, host, candidate
                                    )
                                    if self._probe_reading(exchange)["vulnerable"]:
                                        # First vulnerable payload for this param+type is
                                        # enough; the grader dedupes on the same key.
                                        break

            except Exception as e:
                result.errors.append(f"Template injection on {server_url}: {e}")

            result.candidates.append(candidate)
            injection_results.extend(self._readings(candidate.exchanges)[0])

        if injection_results:
            result.outputs["mcp_template_injection_results"] = injection_results

        return result

    @staticmethod
    def _build_uri(uri_template: str, params: list[str], target_param: str, payload: str) -> str:
        test_uri = uri_template
        for p in params:
            replacement = payload if p == target_param else "test"
            test_uri = test_uri.replace(f"{{{p}}}", replacement)
        return test_uri

    async def _enumerate_templates(
        self, client, server_url: str, scan_id: str, host: str, candidate
    ) -> list[dict]:
        """Enumerate resource templates via resources/templates/list."""
        body = {"jsonrpc": "2.0", "method": "resources/templates/list", "id": 1}
        resp = await client.post(server_url, json=body, headers=JSON_HEADERS)
        candidate.attach(
            exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=scan_id,
                host=host,
                method="POST",
                request_headers=JSON_HEADERS,
                request_json=body,
            )
        )
        return self._templates_from(candidate.exchanges[-1])

    @staticmethod
    def _templates_from(exchange: Exchange) -> list[dict]:
        """Parse the template list off a recorded resources/templates/list reply."""
        if exchange.error or (exchange.response_status or 0) != 200 or not exchange.response_body:
            return []
        try:
            data = json.loads(exchange.response_body)
            result = data.get("result", data)
            if isinstance(result, dict) and "resourceTemplates" in result:
                return result["resourceTemplates"]
            if isinstance(result, list):
                return result
        except (json.JSONDecodeError, TypeError):
            pass
        return []

    async def _probe_template(
        self, client, server_url: str, uri: str, scan_id: str, host: str, candidate
    ) -> Exchange:
        """Send one resources/read for a candidate URI and record it."""
        body = {"jsonrpc": "2.0", "method": "resources/read", "params": {"uri": uri}, "id": 1}
        resp = await client.post(server_url, json=body, headers=JSON_HEADERS)
        exchange = exchange_from_response(
            resp,
            check_name=self.name,
            scan_id=scan_id,
            host=host,
            method="POST",
            request_headers=JSON_HEADERS,
            request_json=body,
        )
        candidate.attach(exchange)
        return exchange

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        injection_results, vulns, templates_present = self._readings(list(evidence))

        verdicts: list[Verdict] = []
        seen: set[tuple[str, str]] = set()
        for vuln in vulns:
            key = (vuln["param"], vuln["injection_type"])
            if key in seen:
                continue
            seen.add(key)
            inj_type = vuln["injection_type"]
            probe = vuln["result"]
            confidence, why = self._confidence(inj_type, probe)
            verdicts.append(
                Verdict(
                    severity=self._injection_severity(inj_type, probe),
                    confidence=confidence,
                    discriminator=f"tmpl-{inj_type}-{vuln['param']}",
                    title=(
                        f"Resource template {inj_type} injection: parameter "
                        f"'{vuln['param']}' is vulnerable"
                    ),
                    description=(
                        f"Template '{vuln['template']}' parameter '{vuln['param']}' is "
                        f"vulnerable to {vuln['desc']}. Payload '{vuln['payload']}' was "
                        "processed without sanitization."
                    ),
                    evidence=(
                        f"Template: {vuln['template']}\n"
                        f"Parameter: {vuln['param']}\n"
                        f"Payload: {vuln['payload']}\n"
                        f"Response: {cap_response(probe.get('body', ''))[:200]}"
                    ),
                    reasoning=why,
                    signals={"indicator": probe.get("indicator"), "status": probe.get("status")},
                    references=self.references,
                    raw_data={
                        "template": vuln["template"],
                        "param": vuln["param"],
                        "payload": vuln["payload"],
                    },
                    tier=ctx.tier,
                    evidence_ids=[vuln["exchange_id"]],
                )
            )

        if templates_present and not verdicts:
            verdicts.append(
                Verdict(
                    severity="info",
                    confidence=0.55,
                    discriminator="template-safe",
                    title="Resource template parameters properly validated",
                    description="Tested resource templates, no injection vulnerabilities found.",
                    evidence=(
                        f"Payloads per param: {sum(len(p) for p in INJECTION_PAYLOADS.values())}"
                    ),
                    reasoning=(
                        "no payload produced an error string or reflected marker; detection is "
                        "bounded by a fixed indicator list, so an injection whose effect is not "
                        "reflected in the response is not seen"
                    ),
                    tier=ctx.tier,
                    evidence_ids=evidence.ids(),
                )
            )
        return verdicts

    @staticmethod
    def _confidence(inj_type: str, probe: dict) -> tuple[float, str]:
        indicator = probe.get("indicator")
        if inj_type == "sql":
            return 0.45, (
                "a database error string was reflected, which is consistent with an unsanitised "
                "parameter — but ordinary input validation and a generic 500 produce the same "
                "keywords, so a reflected error is not proof the payload reached a query engine"
            )
        if inj_type == "command":
            if indicator == "content_injection":
                return 0.5, (
                    "the command marker 'chainsmith-probe' appeared in the response, but that is "
                    "the exact string the payload asked to be echoed, so a reflection and an "
                    "executed command are indistinguishable here"
                )
            return 0.4, "a reflected signal only; nothing confirms the command ran server-side"
        if inj_type == "path_traversal":
            return 0.5, (
                "a traversal marker (root:/ /bin/bash) was reflected, but such strings can be "
                "echoed from the request or appear in unrelated content, so file disclosure is "
                "not established"
            )
        # template_nesting
        return 0.35, (
            "the template-expression result '49' (7*7) appeared, but 49 is a common two-digit "
            "value that arises by coincidence, so template evaluation is not established"
        )

    # ── The parser both halves share ─────────────────────────────────

    def _readings(self, exchanges: list[Exchange]) -> tuple[list[dict], list[dict], bool]:
        """(injection_results, vulnerable findings, templates_present) off the record.

        Each recorded `resources/read` request's `params.uri` is keyed back to
        its (template, param, injection type, payload) via the regenerated URI map.
        """
        templates: list[dict] = []
        for exchange in exchanges:
            if self._method_of(exchange) == "resources/templates/list":
                templates = self._templates_from(exchange)
                break

        uri_map = self._uri_map(templates)

        injection_results: list[dict] = []
        vulns: list[dict] = []
        for exchange in exchanges:
            if self._method_of(exchange) != "resources/read":
                continue
            uri = self._uri_of(exchange)
            meta = uri_map.get(uri)
            if meta is None:
                continue
            probe = self._probe_reading(exchange)
            entry = {
                "template": meta["template"],
                "param": meta["param"],
                "injection_type": meta["injection_type"],
                "payload": meta["payload"],
                "result": probe,
            }
            injection_results.append(entry)
            if probe["vulnerable"]:
                vulns.append({**entry, "desc": meta["desc"], "exchange_id": exchange.id})

        return injection_results, vulns, bool(templates)

    def _uri_map(self, templates: list[dict]) -> dict[str, dict]:
        """Every URI the probe could have built → its (template, param, type, payload)."""
        uri_map: dict[str, dict] = {}
        for template in templates:
            uri_template = template.get("uriTemplate", "")
            params = TEMPLATE_PARAM_RE.findall(uri_template)
            for param in params:
                for inj_type, payloads in INJECTION_PAYLOADS.items():
                    for payload, desc in payloads:
                        uri = self._build_uri(uri_template, params, param, payload)
                        uri_map.setdefault(
                            uri,
                            {
                                "template": uri_template,
                                "param": param,
                                "injection_type": inj_type,
                                "payload": payload,
                                "desc": desc,
                            },
                        )
        return uri_map

    @staticmethod
    def _method_of(exchange: Exchange) -> str:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return ""
        return body.get("method", "") if isinstance(body, dict) else ""

    @staticmethod
    def _uri_of(exchange: Exchange) -> str:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return ""
        params = body.get("params", {}) if isinstance(body, dict) else {}
        uri = params.get("uri", "") if isinstance(params, dict) else ""
        return uri if isinstance(uri, str) else ""

    def _probe_reading(self, exchange: Exchange) -> dict:
        """Re-derive the injection verdict for one recorded resources/read."""
        probe = {"vulnerable": False, "body": "", "status": None, "indicator": None}

        if exchange.error:
            return probe

        body = exchange.response_body or ""
        probe["body"] = body
        probe["status"] = exchange.response_status

        if (exchange.response_status or 0) != 200:
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
                result_str = str(result).lower()
                if any(kw in result_str for kw in ["root:", "/bin/bash", "chainsmith-probe", "49"]):
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
