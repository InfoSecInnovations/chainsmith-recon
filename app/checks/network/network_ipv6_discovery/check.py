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

**Probe/grade.** `run()` resolves AAAA and records one
exchange per hostname; `grade()` reads the addresses back off the exchange and
places severity. `ipv6_data` is an output downstream checks read, so the probe
still parses the address list for itself (§6.2's two parses). The dual-stack
comparison is the grader's, and it is the one judgement in this check that needs
more than its own evidence: *"IPv6 but no IPv4"* is a statement about
`dns_records`, which reaches `grade()` through `GradeContext.context`.
"""

import asyncio
import logging
import socket
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict

logger = logging.getLogger(__name__)

try:
    import dns.exception
    import dns.resolver

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

    name = "network_ipv6_discovery"
    description = "IPv6 AAAA record resolution and dual-stack analysis"

    conditions = [
        CheckCondition("target_hosts", "truthy"),
    ]
    produces = ["ipv6_data"]

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
            exchange = await self._resolve_aaaa(hostname)
            ipv6_addrs = _addresses(exchange)

            has_ipv4 = hostname in dns_records and dns_records[hostname] is not None
            has_ipv6 = len(ipv6_addrs) > 0

            if has_ipv6:
                hosts_with_ipv6 += 1

                entry: dict[str, Any] = {
                    "ipv6_addresses": ipv6_addrs,
                    "has_ipv4": has_ipv4,
                    "ipv6_only": has_ipv6 and not has_ipv4,
                    "ula_detected": any(addr.lower().startswith(ULA_PREFIX) for addr in ipv6_addrs),
                    "link_local": any(
                        addr.lower().startswith(LINK_LOCAL_PREFIX) for addr in ipv6_addrs
                    ),
                }
                ipv6_data[hostname] = entry
                result.candidates.append(self.create_candidate(host=hostname).attach(exchange))

            result.targets_checked += 1

        result.outputs["ipv6_data"] = ipv6_data
        return result

    async def _resolve_aaaa(self, hostname: str) -> Exchange | None:
        """Resolve AAAA records for a hostname and return the recorded exchange.

        The addresses are the exchange's comma-joined `response_body`, which is
        what both `ipv6_data` and `grade()` read (57.4 wave 2) — one
        representation of the resolver's answer rather than two.
        """
        loop = asyncio.get_event_loop()
        prb = None
        try:
            async with capture.probe("dns", hostname, request_body="AAAA", qtype="AAAA") as prb:
                addresses = await asyncio.wait_for(
                    loop.run_in_executor(None, self._sync_resolve_aaaa, hostname),
                    timeout=self.DNS_TIMEOUT,
                )
                prb.responded(", ".join(addresses))
        except (TimeoutError, Exception) as exc:
            logger.debug(f"AAAA resolution failed for {hostname}: {exc}")
        return prb.exchange if prb is not None else None

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
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
                dns.exception.DNSException,
            ):
                pass
            except Exception as exc:
                logger.debug(f"dnspython AAAA error for {hostname}: {exc}")
        else:
            # Fallback: socket.getaddrinfo for AF_INET6
            try:
                results = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
                for _family, _type, _proto, _canonname, sockaddr in results:
                    addr = sockaddr[0]
                    if addr not in addresses:
                        addresses.append(addr)
            except (socket.gaierror, OSError):
                pass

        return addresses

    # ══ Grade ════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one host's recorded AAAA answer."""
        exchange = next((e for e in evidence if _addresses(e)), None)
        if exchange is None:
            return []

        hostname = ctx.host
        ipv6_addrs = _addresses(exchange)
        # `dns_records` is the IPv4 half of the dual-stack comparison. It is an
        # upstream check's output rather than this check's evidence, which is
        # why `GradeContext` carries the scan context at all.
        dns_records: dict[str, str] = ctx.context.get("dns_records") or {}
        has_ipv4 = hostname in dns_records and dns_records[hostname] is not None

        ula_addrs = [a for a in ipv6_addrs if a.lower().startswith(ULA_PREFIX)]
        entry = {
            "ipv6_addresses": ipv6_addrs,
            "has_ipv4": has_ipv4,
            "ipv6_only": not has_ipv4,
            "ula_detected": bool(ula_addrs),
            "link_local": any(a.lower().startswith(LINK_LOCAL_PREFIX) for a in ipv6_addrs),
        }

        addr_str = ", ".join(ipv6_addrs[:3])
        if len(ipv6_addrs) > 3:
            addr_str += f" (+{len(ipv6_addrs) - 3} more)"

        evidence_ids = [exchange.id]
        verdicts: list[Verdict] = []

        # ── IPv6 address discovered ───────────────────────
        verdicts.append(
            Verdict(
                severity="info",
                # An AAAA record either answered or it did not.
                confidence=0.99,
                discriminator="ipv6",
                title=f"IPv6 address discovered: {hostname}",
                description=(
                    f"{hostname} has {len(ipv6_addrs)} IPv6 address(es): {addr_str}. "
                    f"Dual-stack: {'yes' if has_ipv4 else 'no (IPv6 only)'}."
                ),
                evidence=f"Host: {hostname} | IPv6: {addr_str} | IPv4: {has_ipv4}",
                reasoning=f"AAAA query returned {len(ipv6_addrs)} address(es)",
                signals={"ipv6_addresses": ipv6_addrs, "has_ipv4": has_ipv4},
                raw_data=entry,
                evidence_ids=evidence_ids,
            )
        )

        # ── IPv6 reachable, IPv4 not ──────────────────────
        if entry["ipv6_only"]:
            verdicts.append(
                Verdict(
                    severity="medium",
                    # The absence of an A record here is the absence of one in
                    # `dns_records`, which only holds what the wordlist asked
                    # for. A host with an A record nobody queried reads as
                    # IPv6-only and is not.
                    confidence=0.65,
                    discriminator="ipv6-only",
                    title=f"Service reachable on IPv6 but not IPv4: {hostname}",
                    description=(
                        f"{hostname} resolves to IPv6 ({addr_str}) but has no "
                        f"IPv4 (A record) entry. This could indicate an IPv6-only "
                        f"service or a potential firewall bypass if IPv4 ACLs were "
                        f"configured but IPv6 was overlooked."
                    ),
                    evidence=(
                        f"Host: {hostname} | IPv6: {addr_str} | "
                        f"IPv4: not resolved | Possible firewall bypass"
                    ),
                    reasoning="AAAA answered and the host has no A record in dns_records",
                    signals={"ipv6_addresses": ipv6_addrs, "dns_records_size": len(dns_records)},
                    evidence_ids=evidence_ids,
                )
            )

        # ── RFC 4193 unique local address ─────────────────
        if ula_addrs:
            verdicts.append(
                Verdict(
                    severity="low",
                    # fd00::/8 membership is arithmetic.
                    confidence=0.95,
                    discriminator="ula",
                    title=f"RFC 4193 unique local address exposed: {hostname}",
                    description=(
                        f"{hostname} resolves to a unique local address (ULA) "
                        f"in the fd00::/8 range ({', '.join(ula_addrs)}). "
                        f"ULA addresses are intended for local communication only "
                        f"and may indicate internal infrastructure leaking into DNS."
                    ),
                    evidence=f"Host: {hostname} | ULA: {', '.join(ula_addrs)}",
                    reasoning=f"{len(ula_addrs)} address(es) in the fd00::/8 range",
                    signals={"ula_addresses": ula_addrs},
                    evidence_ids=evidence_ids,
                )
            )

        return verdicts


def _addresses(exchange: Exchange | None) -> list[str]:
    """The AAAA addresses one recorded exchange came back with.

    `probe()` records an empty body for a query that completed and answered
    nothing, which is exactly NXDOMAIN or NOERROR/NODATA, so an empty list here
    is the honest reading of both.
    """
    if exchange is None or exchange.error is not None or not exchange.response_body:
        return []
    return [a for a in (part.strip() for part in exchange.response_body.split(",")) if a]
