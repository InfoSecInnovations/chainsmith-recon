"""
app/checks/network/network_wildcard_dns/check.py

Wildcard DNS Detection

Resolves random, non-existent subdomains to detect wildcard DNS records.
If a wildcard exists, all subdomain enumeration results are suspect —
downstream checks should deprioritize or filter them.

Should run early (parallel with dns_enumeration).

**Probe/grade.** `run()` resolves and records; `grade()`
reads the recorded answers back and places the severity. This check is §0.11's
named example of a probe that *parses twice*: it has to know whether a wildcard
exists in order to populate `wildcard_dns`, which downstream checks depend on,
so the probe keeps that parse for its outputs and the grader re-derives its
verdict from the exchanges. The duplicated read is one `set()` over three
strings, and what it buys is a verdict that can be re-derived from the corpus
without a resolver.
"""

import asyncio
import random
import socket
import string
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckResult
from app.grading import Evidence, GradeContext, Verdict


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

    name = "network_wildcard_dns"
    description = "Detect wildcard DNS records that cause false subdomain discoveries"

    conditions = []  # Entry point — no upstream dependencies
    produces = ["wildcard_dns"]

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

    # ══ Probe ════════════════════════════════════════════════════════

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        base_domain = context.get("base_domain", "")
        if not base_domain:
            result.errors.append("No base_domain in context.")
            result.success = False
            return result

        # Resolve PROBE_COUNT random subdomains
        probes = [f"{_random_subdomain()}.{base_domain}" for _ in range(self.PROBE_COUNT)]

        exchanges = [e for e in [await self._resolve(hostname) for hostname in probes] if e]
        resolved_ips = [e.response_body for e in exchanges if _answered(e)]

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

        candidate = self.create_candidate(host=base_domain)
        for exchange in exchanges:
            candidate.attach(exchange)
        result.candidates.append(candidate)

        return result

    async def _resolve(self, hostname: str) -> Exchange | None:
        """Resolve one hostname and return the recorded exchange.

        The answer is the exchange's `response_body`, not a return value: the
        probe reads it for its outputs and `grade()` reads the same field off
        the corpus, so there is one representation of "what DNS said" rather
        than two that can drift.
        """
        loop = asyncio.get_event_loop()
        prb = None
        try:
            async with capture.probe("dns", hostname, request_body="A", qtype="A") as prb:
                infos = await loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(hostname, None, socket.AF_INET),
                )
                if infos:
                    prb.responded(infos[0][4][0])
        except (socket.gaierror, OSError):
            # Recorded as a failure by `probe()` before it re-raised; NXDOMAIN
            # for a random label is the expected answer, not an error.
            pass
        return prb.exchange if prb is not None else None

    # ══ Grade ════════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on the recorded resolver answers."""
        base_domain = ctx.host
        resolved_ips = [e.response_body for e in evidence if _answered(e)]
        if not resolved_ips:
            return []

        unique_ips = sorted(set(resolved_ips))
        single_ip = unique_ips[0] if len(unique_ips) == 1 else None

        if single_ip:
            evidence_text = f"*.{base_domain} -> {single_ip}"
            description = (
                f"All {self.PROBE_COUNT} random subdomains resolved to {single_ip}. "
                f"This domain has a wildcard DNS record. Subdomain enumeration "
                f"results should be cross-validated."
            )
            # Three random labels answering with one identical address is as
            # close to proof of a wildcard as a resolver can give.
            confidence = 0.97
            reasoning = (
                f"{len(resolved_ips)}/{self.PROBE_COUNT} random labels resolved, all to {single_ip}"
            )
        else:
            joined = ", ".join(unique_ips)
            evidence_text = f"*.{base_domain} -> {joined}"
            description = (
                f"{len(resolved_ips)}/{self.PROBE_COUNT} random subdomains resolved "
                f"to multiple IPs ({joined}). Possible wildcard with "
                f"round-robin or geo-DNS."
            )
            # Several addresses are also what a round-robin or geo-DNS front end
            # looks like, so this is a weaker reading of the same evidence.
            confidence = 0.7
            reasoning = (
                f"{len(resolved_ips)}/{self.PROBE_COUNT} random labels resolved to "
                f"{len(unique_ips)} distinct addresses"
            )

        return [
            Verdict(
                severity="info",
                confidence=confidence,
                title=f"Wildcard DNS detected: *.{base_domain}",
                description=description,
                evidence=evidence_text,
                reasoning=reasoning,
                signals={
                    "resolved_ips": unique_ips,
                    "probes_resolved": len(resolved_ips),
                    "probes_total": self.PROBE_COUNT,
                    "single_ip": single_ip,
                },
                evidence_ids=evidence.ids(),
            )
        ]


def _answered(exchange: Exchange) -> bool:
    """True when this resolver exchange came back with an address."""
    return exchange.error is None and bool(exchange.response_body)
