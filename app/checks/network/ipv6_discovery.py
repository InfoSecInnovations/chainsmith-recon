"""
app/checks/network/ipv6_discovery.py

IPv6 Discovery

Resolves AAAA records for all discovered hostnames and compares
IPv6 service exposure against IPv4. Identifies potential firewall
bypass scenarios where IPv6 is reachable but IPv4 is not.

Depends on: target_hosts (needs discovered hostnames from dns_enumeration)
Feeds: additional attack surface for port scanning, security posture

Requirements:
  - dnspython (pip install dnspython) — for reliable AAAA queries
  - Falls back to socket.getaddrinfo if dnspython not available
"""

import asyncio
import logging
import socket
from typing import Any, Optional

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.findings import build_finding

logger = logging.getLogger(__name__)

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# RFC 4193 unique local address prefix
ULA_PREFIX = "fd"
# Link-local prefix
LINK_LOCAL_PREFIX = "fe80:"


class IPv6DiscoveryCheck(BaseCheck):
    """
    Discover IPv6 (AAAA) addresses for target hostnames.

    Resolves AAAA records for all known hostnames and identifies
    hosts with IPv6 connectivity. Flags potential firewall bypass
    scenarios where IPv6 endpoints may have different security
    postures than IPv4.

    Produces:
        ipv6_data - {
            hostname: {
                ipv6_addresses: [str],
                has_ipv4: bool,
                ipv6_only: bool,
                ula_detected: bool,
            }
        }
    """

    name = "ipv6_discovery"
    description = "IPv6 AAAA record resolution and dual-stack analysis"

    conditions = [
        CheckCondition("target_hosts", "truthy"),
    ]
    produces = ["ipv6_data"]

    timeout_seconds = 30.0
    requests_per_second = 20.0  # DNS queries are lightweight

    reason = (
        "Many targets have IPv6 endpoints with different security postures "
        "than IPv4. Firewalls and ACLs that restrict IPv4 access sometimes "
        "don't cover IPv6 equivalents. Services bound to 0.0.0.0 (all "
        "interfaces) are reachable on both stacks."
    )
    references = [
        "PTES - Intelligence Gathering",
        "CWE-923 — Improper Restriction of Communication Channel to Intended Endpoints",
        "https://attack.mitre.org/techniques/T1590/004/",
    ]
    techniques = [
        "IPv6 discovery",
        "AAAA record resolution",
        "dual-stack analysis",
    ]

    DNS_TIMEOUT = 5.0

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        target_hosts: list[str] = context.get("target_hosts", [])
        if not target_hosts:
            result.errors.append("No target_hosts in context")
            result.success = False
            return result

        # dns_records gives us IPv4 data for comparison
        dns_records: dict[str, str] = context.get("dns_records", {})

        ipv6_data: dict[str, dict] = {}
        hosts_with_ipv6 = 0

        for hostname in target_hosts:
            ipv6_addrs = await self._resolve_aaaa(hostname)

            has_ipv4 = hostname in dns_records and dns_records[hostname] is not None
            has_ipv6 = len(ipv6_addrs) > 0

            if has_ipv6:
                hosts_with_ipv6 += 1

                entry: dict[str, Any] = {
                    "ipv6_addresses": ipv6_addrs,
                    "has_ipv4": has_ipv4,
                    "ipv6_only": has_ipv6 and not has_ipv4,
                    "ula_detected": any(
                        addr.lower().startswith(ULA_PREFIX)
                        for addr in ipv6_addrs
                    ),
                    "link_local": any(
                        addr.lower().startswith(LINK_LOCAL_PREFIX)
                        for addr in ipv6_addrs
                    ),
                }
                ipv6_data[hostname] = entry
                self._generate_findings(result, hostname, entry, dns_records)

            result.targets_checked += 1

        result.outputs["ipv6_data"] = ipv6_data
        return result

    async def _resolve_aaaa(self, hostname: str) -> list[str]:
        """Resolve AAAA records for a hostname."""
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_resolve_aaaa, hostname),
                timeout=self.DNS_TIMEOUT,
            )
        except (asyncio.TimeoutError, Exception) as exc:
            logger.debug(f"AAAA resolution failed for {hostname}: {exc}")
            return []

    def _sync_resolve_aaaa(self, hostname: str) -> list[str]:
        """Synchronous AAAA record resolution."""
        addresses: list[str] = []

        # Prefer dnspython for reliable AAAA queries
        if HAS_DNSPYTHON:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.DNS_TIMEOUT
                resolver.lifetime = self.DNS_TIMEOUT
                answers = resolver.resolve(hostname, "AAAA")
                for rdata in answers:
                    addr = str(rdata)
                    if addr not in addresses:
                        addresses.append(addr)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout,
                    dns.exception.DNSException):
                pass
            except Exception as exc:
                logger.debug(f"dnspython AAAA error for {hostname}: {exc}")
        else:
            # Fallback: socket.getaddrinfo for AF_INET6
            try:
                results = socket.getaddrinfo(
                    hostname, None, socket.AF_INET6, socket.SOCK_STREAM
                )
                for family, type_, proto, canonname, sockaddr in results:
                    addr = sockaddr[0]
                    if addr not in addresses:
                        addresses.append(addr)
            except (socket.gaierror, OSError):
                pass

        return addresses

    def _generate_findings(
        self,
        result: CheckResult,
        hostname: str,
        entry: dict[str, Any],
        dns_records: dict[str, str],
    ) -> None:
        """Generate findings from IPv6 discovery results."""
        ipv6_addrs = entry["ipv6_addresses"]
        addr_str = ", ".join(ipv6_addrs[:3])
        if len(ipv6_addrs) > 3:
            addr_str += f" (+{len(ipv6_addrs) - 3} more)"

        # Info: IPv6 address discovered
        result.findings.append(build_finding(
            check_name=self.name,
            title=f"IPv6 address discovered: {hostname}",
            description=(
                f"{hostname} has {len(ipv6_addrs)} IPv6 address(es): {addr_str}. "
                f"Dual-stack: {'yes' if entry['has_ipv4'] else 'no (IPv6 only)'}."
            ),
            severity="info",
            evidence=f"Host: {hostname} | IPv6: {addr_str} | IPv4: {entry['has_ipv4']}",
            host=hostname,
            discriminator="ipv6",
            raw_data=entry,
        ))

        # Medium: IPv6-only host (reachable on IPv6 but not IPv4 — possible firewall bypass)
        if entry["ipv6_only"]:
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"Service reachable on IPv6 but not IPv4: {hostname}",
                description=(
                    f"{hostname} resolves to IPv6 ({addr_str}) but has no "
                    f"IPv4 (A record) entry. This could indicate an IPv6-only "
                    f"service or a potential firewall bypass if IPv4 ACLs were "
                    f"configured but IPv6 was overlooked."
                ),
                severity="medium",
                evidence=(
                    f"Host: {hostname} | IPv6: {addr_str} | "
                    f"IPv4: not resolved | Possible firewall bypass"
                ),
                host=hostname,
                discriminator="ipv6-only",
            ))

        # Low: ULA address exposed
        if entry.get("ula_detected"):
            ula_addrs = [
                a for a in ipv6_addrs if a.lower().startswith(ULA_PREFIX)
            ]
            result.findings.append(build_finding(
                check_name=self.name,
                title=f"RFC 4193 unique local address exposed: {hostname}",
                description=(
                    f"{hostname} resolves to a unique local address (ULA) "
                    f"in the fd00::/8 range ({', '.join(ula_addrs)}). "
                    f"ULA addresses are intended for local communication only "
                    f"and may indicate internal infrastructure leaking into DNS."
                ),
                severity="low",
                evidence=f"Host: {hostname} | ULA: {', '.join(ula_addrs)}",
                host=hostname,
                discriminator="ula",
            ))
