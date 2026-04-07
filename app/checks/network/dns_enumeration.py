"""
app/checks/network/dns_enumeration.py

DNS Enumeration Check

Entry point for reconnaissance — discovers hosts via DNS resolution.
Resolves a list of candidate hostnames against the target domain
and returns confirmed hostnames and IP mappings.

This check does NOT create Service objects — it only discovers what exists.
Port scanning (port_scan) determines what's open, and service probing
(service_probe) determines how to connect.

Real implementation: uses stdlib asyncio DNS resolution.
For simulated environments, use SimulatedCheck with a network/*.yaml config.
"""

import asyncio
import socket
from typing import Any

from app.checks.base import BaseCheck, CheckResult
from app.lib.observations import build_observation

# Common subdomain wordlist for active enumeration
DEFAULT_WORDLIST = [
    "www",
    "api",
    "chat",
    "app",
    "admin",
    "portal",
    "auth",
    "login",
    "docs",
    "dev",
    "staging",
    "test",
    "internal",
    "backend",
    "frontend",
    "cdn",
    "static",
    "media",
    "mail",
    "smtp",
    "ftp",
    "vpn",
    "remote",
]


class DnsEnumerationCheck(BaseCheck):
    """
    Enumerate subdomains via DNS resolution.

    Given a base domain, attempts to resolve a wordlist of common
    subdomain prefixes. Confirmed hosts are returned as hostnames
    for downstream port scanning.

    Produces:
        target_hosts  - list[str] of resolved hostnames (or IPs)
        dns_records   - dict[str, str] mapping hostname -> IP
    """

    name = "dns_enumeration"
    description = "Enumerate subdomains via DNS resolution against a target domain"

    conditions = []  # Entry point — no upstream dependencies
    produces = ["target_hosts", "dns_records"]

    timeout_seconds = 30.0
    requests_per_second = 20.0  # DNS is cheap; be reasonably fast

    reason = (
        "DNS enumeration reveals subdomains and services in the target's "
        "infrastructure, expanding attack surface visibility."
    )
    references = [
        "OWASP WSTG-INFO-03",
        "PTES - Intelligence Gathering",
        "https://attack.mitre.org/techniques/T1590/002/",
    ]
    techniques = ["T1590.002", "subdomain enumeration", "DNS brute-force"]

    def __init__(
        self,
        base_domain: str = "",
        wordlist: list[str] = None,
    ):
        super().__init__()
        self.base_domain = base_domain
        self.wordlist = wordlist or DEFAULT_WORDLIST

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        base_domain = self.base_domain or context.get("base_domain", "")
        if not base_domain:
            result.errors.append(
                "No base_domain provided. Set via constructor or context['base_domain']."
            )
            result.success = False
            return result

        candidates = [f"{prefix}.{base_domain}" for prefix in self.wordlist]
        resolved_hosts: list[str] = []
        dns_records: dict[str, str] = {}

        # Resolve in batches to avoid hammering the resolver
        batch_size = 10
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i : i + batch_size]
            tasks = [self._resolve_host(hostname) for hostname in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

            for hostname, res in zip(batch, batch_results):
                if isinstance(res, Exception):
                    # Resolution failed — host doesn't exist or unreachable
                    continue
                if res is None:
                    continue

                ip = res
                resolved_hosts.append(hostname)
                dns_records[hostname] = ip

                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"Host discovered: {hostname}",
                        description=f"DNS resolved {hostname} to {ip}",
                        severity="info",
                        evidence=f"Host: {hostname} | IP: {ip}",
                        host=hostname,
                        target=None,
                        target_url=None,
                    )
                )

            await asyncio.sleep(0.05)  # brief pause between batches

        result.outputs["target_hosts"] = resolved_hosts
        result.outputs["dns_records"] = dns_records
        result.targets_checked = len(candidates)
        result.targets_failed = len(candidates) - len(resolved_hosts)

        return result

    async def _resolve_host(self, hostname: str) -> str | None:
        """
        Attempt to resolve a hostname. Returns IP address or None.

        Uses getaddrinfo via asyncio executor to avoid blocking the event loop.
        """
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.run_in_executor(
                None, lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
            )
            if infos:
                ip = infos[0][4][0]
                return ip
        except (socket.gaierror, OSError):
            pass
        return None
