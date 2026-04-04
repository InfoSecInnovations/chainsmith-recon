"""
app/checks/network/wildcard_dns.py

Wildcard DNS Detection

Resolves random, non-existent subdomains to detect wildcard DNS records.
If a wildcard exists, all subdomain enumeration results are suspect —
downstream checks should deprioritize or filter them.

Should run early (parallel with dns_enumeration).
"""

import asyncio
import random
import socket
import string
from typing import Any

from app.checks.base import BaseCheck, CheckResult
from app.lib.findings import build_finding


def _random_subdomain(length: int = 12) -> str:
    """Generate a random subdomain label that almost certainly doesn't exist."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


class WildcardDnsCheck(BaseCheck):
    """
    Detect wildcard DNS records on the target domain.

    Resolves 3 random subdomains. If all resolve to the same IP,
    the domain has a wildcard record and subdomain enumeration
    results should be treated with suspicion.

    Produces:
        wildcard_dns - dict with 'detected' (bool), 'ip' (str|None)
    """

    name = "wildcard_dns"
    description = "Detect wildcard DNS records that cause false subdomain discoveries"

    conditions = []  # Entry point — no upstream dependencies
    produces = ["wildcard_dns"]

    timeout_seconds = 15.0
    requests_per_second = 10.0

    reason = (
        "Wildcard DNS records cause subdomain enumeration to report "
        "every candidate as 'discovered', producing misleading results. "
        "Detecting wildcards early prevents wasted effort downstream."
    )
    references = [
        "OWASP WSTG-INFO-03",
        "RFC 4592 — The Role of Wildcards in the DNS",
    ]
    techniques = ["wildcard DNS detection", "DNS reconnaissance"]

    PROBE_COUNT = 3

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        base_domain = context.get("base_domain", "")
        if not base_domain:
            result.errors.append("No base_domain in context.")
            result.success = False
            return result

        # Resolve PROBE_COUNT random subdomains
        probes = [f"{_random_subdomain()}.{base_domain}" for _ in range(self.PROBE_COUNT)]

        resolved_ips: list[str] = []
        for hostname in probes:
            ip = await self._resolve(hostname)
            if ip is not None:
                resolved_ips.append(ip)

        if not resolved_ips:
            # No random subdomains resolved — no wildcard
            result.outputs["wildcard_dns"] = {"detected": False, "ip": None}
            return result

        # If all probes resolved (and ideally to the same IP), it's a wildcard
        unique_ips = set(resolved_ips)
        wildcard_ip = resolved_ips[0] if len(unique_ips) == 1 else None

        result.outputs["wildcard_dns"] = {
            "detected": True,
            "ip": wildcard_ip,
            "resolved_ips": list(unique_ips),
            "probes_resolved": len(resolved_ips),
            "probes_total": self.PROBE_COUNT,
        }

        severity = "info"
        if wildcard_ip:
            evidence = f"*.{base_domain} -> {wildcard_ip}"
            desc = (
                f"All {self.PROBE_COUNT} random subdomains resolved to {wildcard_ip}. "
                f"This domain has a wildcard DNS record. Subdomain enumeration "
                f"results should be cross-validated."
            )
        else:
            evidence = f"*.{base_domain} -> {', '.join(unique_ips)}"
            desc = (
                f"{len(resolved_ips)}/{self.PROBE_COUNT} random subdomains resolved "
                f"to multiple IPs ({', '.join(unique_ips)}). Possible wildcard with "
                f"round-robin or geo-DNS."
            )

        result.findings.append(
            build_finding(
                check_name=self.name,
                title=f"Wildcard DNS detected: *.{base_domain}",
                description=desc,
                severity=severity,
                evidence=evidence,
                host=base_domain,
            )
        )

        return result

    async def _resolve(self, hostname: str) -> str | None:
        """Attempt to resolve a hostname. Returns IP or None."""
        loop = asyncio.get_event_loop()
        try:
            infos = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, None, socket.AF_INET),
            )
            if infos:
                return infos[0][4][0]
        except (socket.gaierror, OSError):
            pass
        return None
