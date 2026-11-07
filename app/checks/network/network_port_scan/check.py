"""
Port Scanning Checks

TCP port scanning to discover open services.

**Probe/grade.** `run()` connects, records one `tcp`
exchange per *open* port, and emits a candidate; `grade()` reads the recorded
transport outcome and states that the port is open. Closed and filtered ports
are deliberately not recorded: this is the one check in the suite whose negative
count is unbounded — a `full` profile against a quiet host is thousands of
refused connects — and a corpus of refusals is volume without evidence. The
absence of a row is what "closed" looks like here, which is the same rule
`capture: observations_only` applies elsewhere.
"""

import asyncio
import time
from typing import Any

from app import capture
from app.checks.base import BaseCheck, CheckCondition, CheckResult, Service
from app.checks.network.port_profiles import resolve_ports
from app.config import get_config
from app.grading import Evidence, GradeContext, Verdict


class PortScanCheck(BaseCheck):
    """
    TCP port scan to discover open ports.

    Can be used standalone or to enrich existing host list.

    Port selection (highest priority wins):
        1. scope.in_scope_ports (hard ceiling from config)
        2. per-scan port_profile in context (CLI / web UI override)
        3. scope.port_profile from config (default: "lab")

    Reads from context:
        target_hosts - list[str] of hostnames or IP addresses to scan.
                       Accepts both DNS names (e.g., "www.example.com")
                       and raw IPs (e.g., "10.0.1.10").
        services     - list[Service] of existing services to preserve
        port_profile - optional per-scan profile override
                       ("web", "ai", "full", "lab")

    Note: CIDR range expansion is not supported. Callers must expand
    ranges before populating target_hosts.
    """

    name = "network_port_scan"
    description = "Scan TCP ports to discover services"

    conditions = [
        CheckCondition("target_hosts", "truthy"),
    ]

    produces = ["services"]

    sequential = True

    # Educational
    reason = "Port scanning identifies what services are accessible on target hosts"
    references = ["NIST SP 800-115", "PTES - Vulnerability Analysis"]
    techniques = ["port scanning", "service discovery", "TCP connect scan"]

    def __init__(self, ports: list[int] = None, profile: str = None):
        super().__init__()
        self._explicit_ports = ports
        self._explicit_profile = profile

    def _resolve_ports(self, context: dict[str, Any]) -> list[int]:
        """Resolve final port list from explicit args, context, and config."""
        # If caller passed explicit ports, use those (still filtered by scope)
        if self._explicit_ports:
            cfg = get_config()
            in_scope = cfg.scope.in_scope_ports
            if in_scope:
                return sorted(p for p in self._explicit_ports if p in set(in_scope))
            return self._explicit_ports

        # Determine profile: explicit arg > context > config
        cfg = get_config()
        profile = self._explicit_profile or context.get("port_profile") or cfg.scope.port_profile
        in_scope = cfg.scope.in_scope_ports

        return resolve_ports(profile=profile, in_scope_ports=in_scope)

    async def run(self, context: dict[str, Any]) -> CheckResult:
        hosts = context.get("target_hosts", [])
        existing_services = context.get("services", [])
        ports = self._resolve_ports(context)

        result = CheckResult(success=True)
        result.services = list(existing_services)  # Preserve existing

        for host in hosts:
            for port in ports:
                await self._rate_limit()

                started = time.perf_counter()
                try:
                    # TCP connect scan
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=2.0
                    )
                    writer.close()
                    await writer.wait_closed()

                    # Port is open - check if we already have this service
                    existing = any(s.host == host and s.port == port for s in result.services)

                    if not existing:
                        service = Service(
                            url=f"http://{host}:{port}",  # Assume HTTP, will be refined
                            host=host,
                            port=port,
                            scheme="http",
                            service_type="unknown",
                        )
                        result.services.append(service)

                        # A connect scan reads no bytes, so the exchange has no
                        # body — the protocol-native answer to "did the handshake
                        # complete" is transport metadata, and that is what
                        # `responded()`'s keyword arguments are for.
                        exchange = capture.record_exchange(
                            "tcp",
                            host,
                            request_body=f"connect {host}:{port}",
                            request_headers={"port": str(port)},
                            response_headers={"state": "open", "port": str(port)},
                            elapsed_ms=(time.perf_counter() - started) * 1000,
                        )
                        result.candidates.append(
                            self.create_candidate(
                                host=host,
                                discriminator=f"port-{port}",
                                target=service,
                            ).attach(exchange)
                        )

                except (TimeoutError, ConnectionRefusedError, OSError):
                    # Port closed or filtered - not an error, and not recorded
                    pass
                except Exception as e:
                    result.errors.append(f"Error scanning {host}:{port}: {e}")

        result.outputs["services"] = result.services
        result.targets_checked = len(hosts) * len(ports)

        return result

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """State that one port is open, from the recorded transport outcome."""
        exchange = next(
            (e for e in evidence if e.error is None and e.response_headers.get("state") == "open"),
            None,
        )
        if exchange is None:
            return []

        host = ctx.host
        port = exchange.response_headers.get("port", "")
        return [
            Verdict(
                severity="info",
                # A completed TCP handshake is not open to interpretation.
                confidence=0.99,
                title=f"Open port: {host}:{port}",
                description=f"TCP port {port} is accepting connections",
                evidence=f"TCP connect to {host}:{port} succeeded",
                reasoning="TCP handshake completed",
                signals={"port": port, "elapsed_ms": exchange.elapsed_ms},
                evidence_ids=[exchange.id],
            )
        ]
