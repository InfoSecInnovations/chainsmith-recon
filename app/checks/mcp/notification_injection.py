"""
app/checks/mcp/notification_injection.py - MCP Notification/Event Injection

Tests if the MCP server accepts unsolicited notifications from the client
that could influence server state or trigger actions.

MCP uses bidirectional notifications — this check tests whether the server
validates notification direction (server→client vs client→server).

References:
  https://modelcontextprotocol.io/specification
  https://spec.modelcontextprotocol.io/specification/basic/lifecycle/
"""

import json
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.observations import build_observation
from app.lib.http import AsyncHttpClient, HttpConfig

# Notifications to test (client→server direction)
NOTIFICATION_TESTS = [
    {
        "method": "notifications/cancelled",
        "params": {"requestId": 999, "reason": "chainsmith-probe"},
        "severity": "medium",
        "title": "Client can cancel operations via notifications/cancelled",
        "description": "Server accepts operation cancellation notifications from the client.",
    },
    {
        "method": "notifications/progress",
        "params": {"progressToken": "probe", "progress": 50, "total": 100},
        "severity": "low",
        "title": "Server processes client progress notifications",
        "description": "Server accepts progress update notifications from the client.",
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
    },
    {
        "method": "notifications/resources/list_changed",
        "params": {},
        "severity": "medium",
        "title": "Server accepts resources/list_changed from client",
        "description": "Server accepted a resource list change notification from the client.",
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
    },
]

# Custom/non-standard notification methods to probe
CUSTOM_NOTIFICATIONS = [
    "notifications/custom/test",
    "notifications/debug",
    "admin/notify",
    "internal/event",
]


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

    timeout_seconds = 60.0

    reason = "MCP bidirectional notifications may allow clients to manipulate server state"
    references = [
        "MCP Specification - Lifecycle - https://spec.modelcontextprotocol.io/specification/basic/lifecycle/",
        "MCP Specification - Notifications",
    ]
    techniques = ["protocol abuse", "notification injection", "state manipulation"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)
        mcp_servers = context.get("mcp_servers", [])
        notification_status = []

        cfg = HttpConfig(timeout_seconds=10.0, verify_ssl=False)

        for server in mcp_servers:
            server_url = server.get("url", "")
            service_data = server.get("service", {})
            host = service_data.get("host", "unknown")

            if not server_url:
                continue

            server_status = {
                "url": server_url,
                "host": host,
                "accepted": [],
                "rejected": [],
                "custom_accepted": [],
            }

            try:
                async with AsyncHttpClient(cfg) as client:
                    # Test standard notifications
                    for test in NOTIFICATION_TESTS:
                        accepted = await self._send_notification(
                            client, server_url, test["method"], test.get("params", {})
                        )

                        if accepted:
                            server_status["accepted"].append(test["method"])
                            result.observations.append(
                                build_observation(
                                    check_name=self.name,
                                    title=test["title"],
                                    description=test["description"],
                                    severity=test["severity"],
                                    evidence=(
                                        f"URL: {server_url}\n"
                                        f"Method: {test['method']}\n"
                                        f"Status: accepted"
                                    ),
                                    host=host,
                                    discriminator=f"notif-{test['method'].replace('/', '-')}",
                                    raw_data={"method": test["method"], "accepted": True},
                                )
                            )
                        else:
                            server_status["rejected"].append(test["method"])

                    # Test custom/non-standard notifications
                    for method in CUSTOM_NOTIFICATIONS:
                        accepted = await self._send_notification(client, server_url, method, {})

                        if accepted:
                            server_status["custom_accepted"].append(method)

                    if server_status["custom_accepted"]:
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Server accepts arbitrary custom notification methods",
                                description=(
                                    f"The MCP server accepted custom notification methods: "
                                    f"{', '.join(server_status['custom_accepted'])}. "
                                    "This indicates loose method validation."
                                ),
                                severity="low",
                                evidence=f"Custom methods accepted: {', '.join(server_status['custom_accepted'])}",
                                host=host,
                                discriminator="custom-notif",
                                raw_data={"custom_accepted": server_status["custom_accepted"]},
                            )
                        )

                    # If nothing was accepted, report clean
                    if not server_status["accepted"] and not server_status["custom_accepted"]:
                        result.observations.append(
                            build_observation(
                                check_name=self.name,
                                title="Server rejects unsolicited client notifications",
                                description="The MCP server properly rejects notification injection attempts.",
                                severity="info",
                                evidence=f"URL: {server_url}\nMethods tested: {len(NOTIFICATION_TESTS) + len(CUSTOM_NOTIFICATIONS)}",
                                host=host,
                                discriminator="notif-clean",
                            )
                        )

            except Exception as e:
                result.errors.append(f"Notification test on {server_url}: {e}")

            notification_status.append(server_status)

        if notification_status:
            result.outputs["mcp_notification_status"] = notification_status

        return result

    async def _send_notification(self, client, server_url: str, method: str, params: dict) -> bool:
        """
        Send a JSON-RPC notification (no id field) and check if accepted.

        Returns True if the server appeared to accept/process the notification.
        """
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params:
            payload["params"] = params

        resp = await client.post(
            server_url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if resp.error:
            return False

        # For notifications: accepted means 200/202/204 (server processed it)
        # Rejected means 400/404/405/500 with error
        if resp.status_code in (200, 202, 204):
            # Check if response body contains an error
            if resp.body:
                try:
                    data = json.loads(resp.body)
                    if isinstance(data, dict) and "error" in data:
                        return False
                except json.JSONDecodeError:
                    pass
            return True

        return False
