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

**Probe/grade.** `run()` looks up PTR records and records one
exchange per IP; `grade()` reads the records back off the exchange and places
severity. `reverse_dns` and `reverse_dns_hosts` are outputs the pipeline feeds
back into discovery, so the probe parses the record list for itself (§6.2's two
parses).

Three of the four judgements here are *relative* — "new hostname", "outside the
target domain", "not in the forward map" — and none of them is answerable from
the PTR answer alone. They are read from `dns_records` and `base_domain` via
`GradeContext.context`, which is the same place the probe read them.
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

    name = "network_reverse_dns"
    description = "Reverse DNS (PTR) lookup for discovered IP addresses"

    conditions = [
        CheckCondition("dns_records", "truthy"),
    ]
    produces = ["reverse_dns", "reverse_dns_hosts"]

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

        # Known hostnames (to detect new ones from PTR). `base_domain` is now
        # read on the grade side, where the judgement that needs it lives.
        known_hosts: set[str] = set(dns_records.keys())

        reverse_dns_data: dict[str, dict] = {}
        new_hosts: set[str] = set()

        for ip, forward_hosts in ip_to_hosts.items():
            exchange = await self._ptr_lookup(ip)
            ptr_records = _records(exchange)
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

            # One candidate per IP, labelled by its forward host the way the
            # observations always were. The grader names each discriminator, so
            # the ids stay `...-ptr-<ip>`, `...-internal-<ip>` and so on.
            result.candidates.append(
                self.create_candidate(host=forward_hosts[0] if forward_hosts else ip).attach(
                    exchange
                )
            )

            # Collect genuinely new hostnames
            for ptr in ptr_records:
                cleaned = ptr.rstrip(".")
                if cleaned not in known_hosts and cleaned != ip:
                    new_hosts.add(cleaned)

        result.outputs["reverse_dns"] = reverse_dns_data
        result.outputs["reverse_dns_hosts"] = sorted(new_hosts)

        return result

    async def _ptr_lookup(self, ip: str) -> Exchange | None:
        """Perform a PTR lookup for a single IP address.

        Returns the recorded exchange rather than the record list (57.4 wave 2):
        the records are its comma-joined `response_body`, which is what both
        `reverse_dns` and `grade()` read.
        """
        if HAS_DNSPYTHON:
            return await self._ptr_lookup_dnspython(ip)
        return await self._ptr_lookup_socket(ip)

    async def _ptr_lookup_dnspython(self, ip: str) -> Exchange | None:
        """PTR lookup using dnspython for proper multi-record support."""
        loop = asyncio.get_event_loop()
        prb = None
        try:
            rev_name = dns.reversename.from_address(ip)
            async with capture.probe("dns", ip, request_body=f"PTR {rev_name}", qtype="PTR") as prb:
                answers = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: dns.resolver.resolve(rev_name, "PTR"),
                    ),
                    timeout=5.0,
                )
                records = [str(rdata.target).rstrip(".") for rdata in answers]
                prb.responded(", ".join(records))
        except (TimeoutError, dns.exception.DNSException, Exception) as exc:
            logger.debug(f"PTR lookup failed for {ip}: {exc}")
        return prb.exchange if prb is not None else None

    async def _ptr_lookup_socket(self, ip: str) -> Exchange | None:
        """Fallback PTR lookup using socket.gethostbyaddr."""
        loop = asyncio.get_event_loop()
        prb = None
        try:
            async with capture.probe("dns", ip, request_body=f"PTR {ip}", qtype="PTR") as prb:
                hostname, aliases, _ = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.gethostbyaddr, ip),
                    timeout=5.0,
                )
                records = [r for r in [hostname] + list(aliases) if r]
                prb.responded(", ".join(records))
        except (TimeoutError, socket.herror, socket.gaierror, OSError):
            pass
        return prb.exchange if prb is not None else None

    # ══ Grade ════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one IP's recorded PTR answer."""
        exchange = next((e for e in evidence if _records(e)), None)
        if exchange is None:
            return []

        ptr_records = _records(exchange)
        # The PTR query was addressed to the IP, so the exchange carries it.
        ip = exchange.host
        # The forward map and the target domain are upstream outputs, not this
        # check's evidence — the same two values the probe read.
        dns_records: dict[str, str] = ctx.context.get("dns_records") or {}
        base_domain: str = ctx.context.get("base_domain") or ""
        forward_hosts = [host for host, addr in dns_records.items() if addr == ip]
        known_hosts = set(dns_records)

        ptr_str = ", ".join(ptr_records)
        evidence_ids = [exchange.id]
        verdicts: list[Verdict] = []

        # ── The PTR record itself ─────────────────────────
        verdicts.append(
            Verdict(
                severity="info",
                # The resolver either returned a PTR record or it did not.
                confidence=0.99,
                discriminator=f"ptr-{ip}",
                title=f"Reverse DNS: {ip} -> {ptr_records[0]}",
                description=(
                    f"PTR lookup for {ip} (forward: {', '.join(forward_hosts)}) "
                    f"returned {len(ptr_records)} record(s)."
                ),
                evidence=f"IP: {ip} | PTR: {ptr_str}",
                reasoning=f"PTR query returned {len(ptr_records)} record(s)",
                signals={"ptr_records": ptr_records, "forward_hosts": forward_hosts},
                evidence_ids=evidence_ids,
            )
        )

        # ── Several PTR records — possible virtual hosting ───
        if len(ptr_records) > 1:
            verdicts.append(
                Verdict(
                    severity="info",
                    # Counting records is exact; reading the count as virtual
                    # hosting is the inference, and a reverse zone with stale
                    # entries looks identical.
                    confidence=0.7,
                    discriminator=f"multi-ptr-{ip}",
                    title=f"Multiple PTR records for {ip} (possible virtual hosting)",
                    description=(
                        f"{ip} has {len(ptr_records)} PTR records, suggesting "
                        f"multiple services or virtual hosts share this IP address."
                    ),
                    evidence=f"IP: {ip} | PTR records: {ptr_str}",
                    reasoning=f"{len(ptr_records)} PTR records on one address",
                    signals={"record_count": len(ptr_records)},
                    evidence_ids=evidence_ids,
                )
            )

        # ── Internal naming convention exposed ────────────
        internal_ptrs = [
            ptr for ptr in ptr_records if any(pat in ptr.lower() for pat in INTERNAL_PATTERNS)
        ]
        if internal_ptrs:
            verdicts.append(
                Verdict(
                    severity="low",
                    # A substring match on a naming convention. `ip-` in
                    # particular matches plenty of hostnames that are not AWS
                    # internal names.
                    confidence=0.75,
                    discriminator=f"internal-{ip}",
                    title=f"Internal hostname in PTR: {ip}",
                    description=(
                        f"PTR record for {ip} reveals internal infrastructure "
                        f"naming convention(s). This exposes details about the "
                        f"hosting environment and internal network structure."
                    ),
                    evidence=f"IP: {ip} | Internal PTR: {', '.join(internal_ptrs)}",
                    reasoning=(
                        f"{len(internal_ptrs)} PTR record(s) match an internal naming pattern"
                    ),
                    signals={"internal_ptrs": internal_ptrs},
                    evidence_ids=evidence_ids,
                )
            )

        # ── PTR target outside the forward map ────────────
        for ptr in ptr_records:
            cleaned = ptr.rstrip(".")
            if (
                cleaned not in known_hosts
                and cleaned != ip
                and base_domain
                and base_domain not in cleaned
            ):
                verdicts.append(
                    Verdict(
                        severity="info",
                        # "Not a known forward host" means "not in a map built
                        # from one wordlist", so this is the weakest judgement
                        # the check makes.
                        confidence=0.6,
                        discriminator=f"mismatch-{ip}",
                        title=f"PTR/forward mismatch: {ip}",
                        description=(
                            f"PTR record for {ip} points to {cleaned}, which does "
                            f"not match any known forward DNS records and is outside "
                            f"the target domain ({base_domain}). This may indicate "
                            f"shared hosting or infrastructure reuse."
                        ),
                        evidence=(
                            f"IP: {ip} | PTR: {cleaned} | Forward hosts: {', '.join(forward_hosts)}"
                        ),
                        reasoning=(
                            f"PTR target {cleaned} is outside {base_domain} and absent "
                            f"from the forward map"
                        ),
                        signals={"ptr": cleaned, "base_domain": base_domain},
                        evidence_ids=evidence_ids,
                    )
                )
                break  # One mismatch observation per IP is sufficient

        return verdicts


def _records(exchange: Exchange | None) -> list[str]:
    """The PTR records one recorded exchange came back with."""
    if exchange is None or exchange.error is not None or not exchange.response_body:
        return []
    return [r for r in (part.strip() for part in exchange.response_body.split(",")) if r]
