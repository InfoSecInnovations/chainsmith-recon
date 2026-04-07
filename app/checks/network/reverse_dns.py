"""
app/checks/network/reverse_dns.py

Reverse DNS Lookup

PTR record lookup for each discovered IP address. Reveals:
- Services sharing IPs with the target (virtual hosting)
- Internal naming conventions (ip-10-0-1-42.ec2.internal)
- Cloud provider infrastructure patterns
- CDN/load balancer presence (multiple PTR records)

Depends on: dns_records (needs hostname -> IP mapping from dns_enumeration)
Feeds: additional hostname discovery, infrastructure context
"""

import asyncio
import logging
import socket
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.observations import build_observation

logger = logging.getLogger(__name__)

try:
    import dns.exception
    import dns.resolver
    import dns.reversename

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# Patterns indicating internal/infrastructure hostnames
INTERNAL_PATTERNS = [
    ".internal.",
    ".local.",
    ".corp.",
    ".lan.",
    ".private.",
    ".intranet.",
    "ip-",  # AWS internal naming
    ".ec2.internal",
    ".compute.internal",
    ".googleapis.com",
]


class ReverseDnsCheck(BaseCheck):
    """
    Perform PTR (reverse DNS) lookups for discovered IP addresses.

    Reveals virtual hosting, internal naming conventions, and
    infrastructure patterns. Additional hostnames are fed back
    into the scan pipeline.

    Produces:
        reverse_dns - dict[ip, {ptr_records: list[str], internal: bool}]
        reverse_dns_hosts - list[str] of new hostnames from PTR records
    """

    name = "reverse_dns"
    description = "Reverse DNS (PTR) lookup for discovered IP addresses"

    conditions = [
        CheckCondition("dns_records", "truthy"),
    ]
    produces = ["reverse_dns", "reverse_dns_hosts"]

    timeout_seconds = 30.0
    requests_per_second = 20.0

    reason = (
        "PTR records reveal internal hostnames, virtual hosting relationships, "
        "and cloud infrastructure patterns. Internal naming conventions "
        "(*.internal, ip-*) expose infrastructure details useful for "
        "reconnaissance."
    )
    references = [
        "OWASP WSTG-INFO-03 — Review Webserver Metafiles for Information Leakage",
        "PTES - Intelligence Gathering",
        "https://attack.mitre.org/techniques/T1596/001/",
    ]
    techniques = ["reverse DNS lookup", "PTR record enumeration", "virtual hosting detection"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        # Get IP addresses from dns_records
        dns_records: dict[str, str] = context.get("dns_records", {})
        if not dns_records:
            result.errors.append("No dns_records in context (need hostname -> IP mapping)")
            result.success = False
            return result

        # Deduplicate IPs
        ip_to_hosts: dict[str, list[str]] = {}
        for hostname, ip in dns_records.items():
            ip_to_hosts.setdefault(ip, []).append(hostname)

        # Known hostnames (to detect new ones from PTR)
        known_hosts: set[str] = set(dns_records.keys())
        base_domain = context.get("base_domain", "")

        reverse_dns_data: dict[str, dict] = {}
        new_hosts: set[str] = set()

        for ip, forward_hosts in ip_to_hosts.items():
            ptr_records = await self._ptr_lookup(ip)
            is_internal = any(
                any(pat in ptr.lower() for pat in INTERNAL_PATTERNS) for ptr in ptr_records
            )

            reverse_dns_data[ip] = {
                "ptr_records": ptr_records,
                "forward_hosts": forward_hosts,
                "internal": is_internal,
            }

            result.targets_checked += 1

            if not ptr_records:
                continue

            # Generate observations
            self._generate_observations(
                result,
                ip,
                forward_hosts,
                ptr_records,
                is_internal,
                known_hosts,
                base_domain,
            )

            # Collect genuinely new hostnames
            for ptr in ptr_records:
                cleaned = ptr.rstrip(".")
                if cleaned not in known_hosts and cleaned != ip:
                    new_hosts.add(cleaned)

        result.outputs["reverse_dns"] = reverse_dns_data
        result.outputs["reverse_dns_hosts"] = sorted(new_hosts)

        return result

    async def _ptr_lookup(self, ip: str) -> list[str]:
        """Perform a PTR lookup for a single IP address."""
        if HAS_DNSPYTHON:
            return await self._ptr_lookup_dnspython(ip)
        return await self._ptr_lookup_socket(ip)

    async def _ptr_lookup_dnspython(self, ip: str) -> list[str]:
        """PTR lookup using dnspython for proper multi-record support."""
        loop = asyncio.get_event_loop()
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: dns.resolver.resolve(rev_name, "PTR"),
                ),
                timeout=5.0,
            )
            return [str(rdata.target).rstrip(".") for rdata in answers]
        except (TimeoutError, dns.exception.DNSException, Exception) as exc:
            logger.debug(f"PTR lookup failed for {ip}: {exc}")
            return []

    async def _ptr_lookup_socket(self, ip: str) -> list[str]:
        """Fallback PTR lookup using socket.gethostbyaddr."""
        loop = asyncio.get_event_loop()
        try:
            hostname, aliases, _ = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=5.0,
            )
            records = [hostname] + list(aliases)
            return [r for r in records if r]
        except (TimeoutError, socket.herror, socket.gaierror, OSError):
            return []

    def _generate_observations(
        self,
        result: CheckResult,
        ip: str,
        forward_hosts: list[str],
        ptr_records: list[str],
        is_internal: bool,
        known_hosts: set[str],
        base_domain: str,
    ) -> None:
        """Generate observations from PTR record results."""
        host_label = forward_hosts[0] if forward_hosts else ip
        ptr_str = ", ".join(ptr_records)

        # Base info observation: PTR record(s)
        result.observations.append(
            build_observation(
                check_name=self.name,
                title=f"Reverse DNS: {ip} -> {ptr_records[0]}",
                description=(
                    f"PTR lookup for {ip} (forward: {', '.join(forward_hosts)}) "
                    f"returned {len(ptr_records)} record(s)."
                ),
                severity="info",
                evidence=f"IP: {ip} | PTR: {ptr_str}",
                host=host_label,
                discriminator=f"ptr-{ip}",
            )
        )

        # Multiple PTR records — possible virtual hosting
        if len(ptr_records) > 1:
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Multiple PTR records for {ip} (possible virtual hosting)",
                    description=(
                        f"{ip} has {len(ptr_records)} PTR records, suggesting "
                        f"multiple services or virtual hosts share this IP address."
                    ),
                    severity="info",
                    evidence=f"IP: {ip} | PTR records: {ptr_str}",
                    host=host_label,
                    discriminator=f"multi-ptr-{ip}",
                )
            )

        # Internal hostname in PTR — infrastructure leak
        if is_internal:
            internal_ptrs = [
                ptr for ptr in ptr_records if any(pat in ptr.lower() for pat in INTERNAL_PATTERNS)
            ]
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"Internal hostname in PTR: {ip}",
                    description=(
                        f"PTR record for {ip} reveals internal infrastructure "
                        f"naming convention(s). This exposes details about the "
                        f"hosting environment and internal network structure."
                    ),
                    severity="low",
                    evidence=f"IP: {ip} | Internal PTR: {', '.join(internal_ptrs)}",
                    host=host_label,
                    discriminator=f"internal-{ip}",
                )
            )

        # PTR mismatch — forward host doesn't match reverse
        for ptr in ptr_records:
            cleaned = ptr.rstrip(".")
            if (
                cleaned not in known_hosts
                and cleaned != ip
                and base_domain
                and base_domain not in cleaned
            ):
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"PTR/forward mismatch: {ip}",
                        description=(
                            f"PTR record for {ip} points to {cleaned}, which does "
                            f"not match any known forward DNS records and is outside "
                            f"the target domain ({base_domain}). This may indicate "
                            f"shared hosting or infrastructure reuse."
                        ),
                        severity="info",
                        evidence=(
                            f"IP: {ip} | PTR: {cleaned} | Forward hosts: {', '.join(forward_hosts)}"
                        ),
                        host=host_label,
                        discriminator=f"mismatch-{ip}",
                    )
                )
                break  # One mismatch observation per IP is sufficient
