"""
app/checks/mcp/notification_injection.py - MCP Notification/Event Injection

Tests if the MCP server accepts unsolicited notifications from the client
that could influence server state or trigger actions.

MCP uses bidirectional notifications — this check tests whether the server
validates notification direction (server→client vs client→server).

**Probe/grade.** The probe sends each notification and
records it; `grade()` re-reads the exchanges, pairs each to its notification
definition by the recorded request's `method` (never positionally, §0.16), and
re-derives acceptance from the recorded status and body. `_accepted()` is the
one parser both halves call (§0.12).

**Contextual**: whether an accepted notification really
manipulates server state is a judgement, so severity is the grader's (the planned LLM tier).
The rule tier keeps the original per-notification severities and states its
weakness in the confidence — **accepted is not effect**: a 2xx with no JSON-RPC
error means the server did not reject the frame, not that a tool list or root
set actually changed, and a catch-all endpoint that 200s everything looks
identical.

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/basic/lifecycle/
"""

import json
from typing import Any

from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict, exchange_from_response
from app.lib.http import AsyncHttpClient, HttpConfig

JSON_HEADERS = {"Content-Type": "application/json"}

# Notifications to test (client→server direction)
NOTIFICATION_TESTS = [
    {
        "method": "notifications/cancelled",
        "params": {"requestId": 999, "reason": "chainsmith-probe"},
        "severity": "medium",
        "title": "Client can cancel operations via notifications/cancelled",
        "description": "Server accepts operation cancellation notifications from the client.",
        "confidence": 0.45,
    },
    {
        "method": "notifications/progress",
        "params": {"progressToken": "probe", "progress": 50, "total": 100},
        "severity": "low",
        "title": "Server processes client progress notifications",
        "description": "Server accepts progress update notifications from the client.",
        "confidence": 0.5,
    },
    {
        "method": "notifications/tools/list_changed",
        "params": {},
        "severity": "high",
        "title": "Server accepts tools/list_changed from client (tool state manipulation)",
        "description": (
            "Server accepted a tools/list_changed notification from the client. "
            "This may allow influencing the server's tool registration state."
        ),
        "confidence": 0.4,
    },
    {
        "method": "notifications/resources/list_changed",
        "params": {},
        "severity": "medium",
        "title": "Server accepts resources/list_changed from client",
        "description": "Server accepted a resource list change notification from the client.",
        "confidence": 0.45,
    },
    {
        "method": "notifications/roots/list_changed",
        "params": {},
        "severity": "high",
        "title": "Server accepts roots/list_changed from client: root URI manipulation possible",
        "description": (
            "Server accepted a roots/list_changed notification from the client. "
            "This could allow manipulation of the server's root URI configuration, "
            "potentially redirecting file access to attacker-controlled paths."
        ),
        "confidence": 0.4,
    },
]

# Custom/non-standard notification methods to probe
CUSTOM_NOTIFICATIONS = [
    "notifications/custom/test",
    "notifications/debug",
    "admin/notify",
    "internal/event",
]

_TESTS_BY_METHOD = {test["method"]: test for test in NOTIFICATION_TESTS}


class MCPNotificationInjectionCheck(BaseCheck):
    """
    Test MCP server notification injection susceptibility.

    Sends unsolicited client→server notifications and observes
    whether the server accepts, rejects, or ignores them.
    """

    name = "mcp_notification_injection"
    description = "Test if MCP server accepts unsolicited client notifications"

    conditions = [CheckCondition("mcp_servers", "truthy")]
    produces = ["mcp_notification_status"]
    service_types = ["ai", "api", "http"]

    reason = "MCP bidirectional notifications may allow clients to manipulate server state"
    references = [
        "MCP Specification - Lifecycle - https://spec.modelcontextprotocol.io/specification/basic/lifecycle/",
        "MCP Specification - Notifications",
    ]
    techniques = ["protocol abuse", "notification injection", "state manipulation"]

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        scan_id = context.get("scan_id") or ""
        mcp_servers = context.get("mcp_servers", [])
        notification_status = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")

            if not server_url:
                continue

            candidate = self.create_candidate(
                host=host, discriminator="notification-injection", target_url=server_url
            )

            try:
                async with AsyncHttpClient(cfg) as client:
                    for test in NOTIFICATION_TESTS:
                        await self._send_notification(
                            client,
                            server_url,
                            test["method"],
                            test.get("params", {}),
                            scan_id,
                            host,
                            candidate,
                        )
                    for method in CUSTOM_NOTIFICATIONS:
                        await self._send_notification(
                            client, server_url, method, {}, scan_id, host, candidate
                        )
            except Exception as e:
                result.errors.append(f"Notification test on {server_url}: {e}")

            result.candidates.append(candidate)
            notification_status.append(self._status_reading(server_url, host, candidate.exchanges))

        if notification_status:
            result.outputs["mcp_notification_status"] = notification_status

        return result

    async def _send_notification(
        self, client, server_url: str, method: str, params: dict, scan_id: str, host: str, candidate
    ) -> None:
        """Send a JSON-RPC notification (no id field) and record the exchange."""
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params:
            payload["params"] = params

        resp = await client.post(server_url, json=payload, headers=JSON_HEADERS)
        candidate.attach(
            exchange_from_response(
                resp,
                check_name=self.name,
                scan_id=scan_id,
                host=host,
                method="POST",
                request_headers=JSON_HEADERS,
                request_json=payload,
            )
        )

    # ══ Grade (rule tier) ════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        exchanges = list(evidence)
        server_url = ctx.target_url or (ctx.target.url if ctx.target else "")

        verdicts: list[Verdict] = []
        accepted_any = False
        custom_accepted: list[str] = []

        for exchange in exchanges:
            method = self._method_of(exchange)
            accepted = self._accepted(exchange)

            if method in _TESTS_BY_METHOD:
                if not accepted:
                    continue
                accepted_any = True
                test = _TESTS_BY_METHOD[method]
                verdicts.append(
                    Verdict(
                        severity=test["severity"],
                        confidence=test["confidence"],
                        discriminator=f"notif-{method.replace('/', '-')}",
                        title=test["title"],
                        description=test["description"],
                        evidence=f"URL: {server_url}\nMethod: {method}\nStatus: accepted",
                        reasoning=(
                            "the server returned a 2xx with no JSON-RPC error, so it did not "
                            "reject the frame — but that is not proof the notification changed "
                            "server state; a catch-all endpoint that 200s everything is "
                            "indistinguishable, and no state was read back to confirm the effect"
                        ),
                        signals={"method": method, "accepted": True},
                        references=self.references,
                        raw_data={"method": method, "accepted": True},
                        tier=ctx.tier,
                        evidence_ids=[exchange.id],
                    )
                )
            elif method in CUSTOM_NOTIFICATIONS and accepted:
                custom_accepted.append(method)

        if custom_accepted:
            verdicts.append(
                Verdict(
                    severity="low",
                    confidence=0.4,
                    discriminator="custom-notif",
                    title="Server accepts arbitrary custom notification methods",
                    description=(
                        f"The MCP server accepted custom notification methods: "
                        f"{', '.join(custom_accepted)}. This indicates loose method validation."
                    ),
                    evidence=f"Custom methods accepted: {', '.join(custom_accepted)}",
                    reasoning=(
                        "the server 2xx'd non-standard methods, which suggests loose validation "
                        "— but a server that accepts everything and acts on nothing produces the "
                        "same responses, so acceptance is not proof of a handler"
                    ),
                    references=self.references,
                    raw_data={"custom_accepted": custom_accepted},
                    tier=ctx.tier,
                    evidence_ids=evidence.ids(),
                )
            )

        if not accepted_any and not custom_accepted:
            verdicts.append(
                Verdict(
                    severity="info",
                    confidence=0.6,
                    discriminator="notif-clean",
                    title="Server rejects unsolicited client notifications",
                    description="The MCP server properly rejects notification injection attempts.",
                    evidence=(
                        f"URL: {server_url}\n"
                        f"Methods tested: {len(NOTIFICATION_TESTS) + len(CUSTOM_NOTIFICATIONS)}"
                    ),
                    reasoning=(
                        "every probed notification drew a rejection; this is bounded by the fixed "
                        "method list, so a differently named client→server notification the server "
                        "does honour would not be seen"
                    ),
                    tier=ctx.tier,
                    evidence_ids=evidence.ids(),
                )
            )

        return verdicts

    # ── The parser both halves share ─────────────────────────────────

    def _status_reading(self, server_url: str, host: str, exchanges: list[Exchange]) -> dict:
        """Rebuild the per-server accepted/rejected summary off the record."""
        status = {
            "url": server_url,
            "host": host,
            "accepted": [],
            "rejected": [],
            "custom_accepted": [],
        }
        for exchange in exchanges:
            method = self._method_of(exchange)
            accepted = self._accepted(exchange)
            if method in _TESTS_BY_METHOD:
                status["accepted" if accepted else "rejected"].append(method)
            elif method in CUSTOM_NOTIFICATIONS and accepted:
                status["custom_accepted"].append(method)
        return status

    @staticmethod
    def _accepted(exchange: Exchange) -> bool:
        """True when the server appeared to accept/process the notification."""
        if exchange.error:
            return False
        if exchange.response_status in (200, 202, 204):
            if exchange.response_body:
                try:
                    data = json.loads(exchange.response_body)
                    if isinstance(data, dict) and "error" in data:
                        return False
                except json.JSONDecodeError:
                    pass
            return True
        return False

    @staticmethod
    def _method_of(exchange: Exchange) -> str:
        try:
            body = json.loads(exchange.request_body or "{}")
        except (ValueError, TypeError):
            return ""
        return body.get("method", "") if isinstance(body, dict) else ""
