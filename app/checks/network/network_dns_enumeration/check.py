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

**Probe/grade.** `run()` resolves and records one exchange
per candidate label; `grade()` reads the answer back off the exchange and states
that the host exists. Like `network_wildcard_dns` this is a probe that parses
twice (§0.11) — `target_hosts` and `dns_records` are what the rest of the
pipeline runs on, so the probe cannot defer reading the address until a grader
gets to it.
"""

import asyncio
import socket
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckResult
from app.grading import Evidence, GradeContext, Verdict
from app.lib.datafiles import load_wordlist

# Common subdomain wordlist for active enumeration. The shipped list lives in
# app/data/wordlists/subdomains.txt (operator-editable, per-engagement); this
# inline copy is the fallback if that file is missing.
_FALLBACK_WORDLIST = [
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
    "mcp",
    "agent",
    "rag",
    "cache",
    "vector",
    "ml",
    "ai",
    "llm",
    "tools",
    "embeddings",
]

DEFAULT_WORDLIST = load_wordlist("wordlists/subdomains.txt", _FALLBACK_WORDLIST)


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

    name = "network_dns_enumeration"
    description = "Enumerate subdomains via DNS resolution against a target domain"

    conditions = []  # Entry point — no upstream dependencies
    produces = ["target_hosts", "dns_records"]

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
                if isinstance(res, Exception) or res is None:
                    # Resolution failed — host doesn't exist or unreachable
                    continue
                if res.error is not None or not res.response_body:
                    continue

                resolved_hosts.append(hostname)
                dns_records[hostname] = res.response_body

                # One candidate per host, with no discriminator: the observation
                # id stays `network_dns_enumeration-<hostname>`, which is what
                # downstream consumers already key on.
                result.candidates.append(self.create_candidate(host=hostname).attach(res))

            await asyncio.sleep(0.05)  # brief pause between batches

        result.outputs["target_hosts"] = resolved_hosts
        result.outputs["dns_records"] = dns_records
        result.targets_checked = len(candidates)
        result.targets_failed = len(candidates) - len(resolved_hosts)

        return result

    async def _resolve_host(self, hostname: str) -> Exchange | None:
        """
        Attempt to resolve a hostname. Returns the recorded exchange, or None.

        Uses getaddrinfo via asyncio executor to avoid blocking the event loop.

        The address is the exchange's `response_body` rather than a return value
        (57.4 wave 2): the probe reads it for `dns_records` and `grade()` reads
        the same field off the corpus, so there is one representation of the
        resolver's answer instead of two.
        """
        loop = asyncio.get_event_loop()
        prb = None
        try:
            # This check runs its resolution in an executor, so it
            # records its own evidence rather than going through the HTTP
            # interceptor. `dns` is opt-in per protocol — see settings.py.
            async with capture.probe("dns", hostname, request_body="A", qtype="A") as prb:
                infos = await loop.run_in_executor(
                    None, lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
                )
                if infos:
                    prb.responded(infos[0][4][0])
        except (socket.gaierror, OSError):
            pass
        return prb.exchange if prb is not None else None

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """State that one host exists, from the recorded resolver answer."""
        exchange = next((e for e in evidence if e.error is None and e.response_body), None)
        if exchange is None:
            return []

        hostname = ctx.host
        ip = exchange.response_body
        return [
            Verdict(
                severity="info",
                # An A record that answered is the least ambiguous evidence in
                # the suite: either the resolver returned an address or it did
                # not.
                confidence=0.99,
                title=f"Host discovered: {hostname}",
                description=f"DNS resolved {hostname} to {ip}",
                evidence=f"Host: {hostname} | IP: {ip}",
                reasoning="A record returned an address for a wordlist candidate",
                signals={"ip": ip},
                evidence_ids=[exchange.id],
            )
        ]
