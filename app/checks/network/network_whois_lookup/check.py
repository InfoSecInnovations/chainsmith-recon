"""
app/checks/network/whois_lookup.py

WHOIS / ASN Lookup

Queries WHOIS data for the target domain and performs ASN lookups
for resolved IP addresses. Provides infrastructure context for
reporting and engagement scoping.

Depends on: dns_enumeration (needs dns_records with hostname -> IP mapping)
Feeds: infrastructure context, reporting, engagement scoping

Requirements:
  - ipwhois library (pip install ipwhois) — for ASN/RDAP lookups
  - No external account needed (uses public WHOIS/RDAP services)

**Probe/grade.** `run()` queries and records; `grade()` reads
the answers back. 57.2 already serialised both the parsed WHOIS record and the
RDAP result into `response_body` as JSON, so `grade()` reads back rather than
re-derives, and `whois_data` is the same structure parsed from the same bytes.

This check grades **two kinds of subject** — one domain and one per resolved IP —
so it emits one candidate per subject and `grade()` tells them apart by the
request it is looking at: a bare domain for WHOIS, `RDAP <ip>` for the network
lookup. One `grade()`, two dispatches, because a check declares one grader.

As with certificate expiry, `recent-registration` compares against *now* and is
therefore not reproducible from the corpus alone; `grade()` says so.
"""

import asyncio
import contextlib
import json
import logging
import socket
from datetime import UTC, datetime
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict

logger = logging.getLogger(__name__)

try:
    from ipwhois import IPWhois
    from ipwhois.exceptions import (
        ASNRegistryError,
        IPDefinedError,
        WhoisLookupError,
        WhoisRateLimitError,
    )

    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False
    # Stub exceptions for when library is not installed
    IPDefinedError = Exception
    ASNRegistryError = Exception
    WhoisLookupError = Exception
    WhoisRateLimitError = Exception

# Domain WHOIS via socket (port 43) — lightweight, no extra dependency
WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "eu": "whois.eu",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "nl": "whois.sidn.nl",
    "ru": "whois.tcinet.ru",
    "jp": "whois.jprs.jp",
}

# Recently-registered domain threshold (days)
RECENT_REGISTRATION_DAYS = 90


class WhoisLookupCheck(BaseCheck):
    """
    WHOIS and ASN lookup for the target domain and resolved IPs.

    Queries domain registration data (registrar, dates, nameservers)
    via WHOIS protocol, and ASN/network ownership for IPs via RDAP.
    Flags recently-registered domains and provides infrastructure context.

    Produces:
        whois_data - {
            "domain": {registrar, created, expires, nameservers, ...},
            "asn": {ip -> {asn, org, cidr, country, registry}},
        }
    """

    name = "network_whois_lookup"
    description = "WHOIS domain registration and ASN lookup for resolved IPs"

    conditions = [
        CheckCondition("dns_records", "truthy"),
    ]
    produces = ["whois_data"]

    reason = (
        "WHOIS data reveals domain registration details (registrar, age, "
        "nameservers) and IP network ownership. Recently-registered domains "
        "hosting services may indicate phishing or shadow IT. ASN data "
        "complements GeoIP with network-level ownership context."
    )
    references = [
        "PTES - Intelligence Gathering",
        "https://attack.mitre.org/techniques/T1596/002/",
        "CWE-200 — Exposure of Sensitive Information",
    ]
    techniques = [
        "WHOIS lookup",
        "ASN enumeration",
        "domain registration analysis",
        "RDAP query",
    ]

    WHOIS_TIMEOUT = 10.0
    RDAP_TIMEOUT = 10.0

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        dns_records: dict[str, str] = context.get("dns_records", {})
        if not dns_records:
            result.errors.append("No dns_records in context")
            result.success = False
            return result

        base_domain = context.get("base_domain", "")
        whois_data: dict[str, Any] = {"domain": {}, "asn": {}}

        # Step 1: Domain WHOIS lookup
        if base_domain:
            exchange = await self._domain_whois(base_domain)
            domain_info = _payload_of(exchange)
            if domain_info:
                whois_data["domain"] = domain_info
                result.candidates.append(self.create_candidate(host=base_domain).attach(exchange))

        # Step 2: ASN/RDAP lookups for unique IPs
        if HAS_IPWHOIS:
            unique_ips = set(dns_records.values())
            ip_to_hosts: dict[str, list[str]] = {}
            for hostname, ip in dns_records.items():
                ip_to_hosts.setdefault(ip, []).append(hostname)

            for ip in unique_ips:
                exchange = await self._asn_lookup(ip)
                asn_info = _payload_of(exchange)
                if asn_info:
                    whois_data["asn"][ip] = asn_info
                    hostnames = ip_to_hosts.get(ip, [])
                    result.candidates.append(
                        self.create_candidate(host=hostnames[0] if hostnames else ip).attach(
                            exchange
                        )
                    )
                result.targets_checked += 1

                # Rate limiting between lookups
                await asyncio.sleep(1.0 / self.requests_per_second)
        else:
            result.errors.append(
                "ipwhois not installed — ASN lookups skipped. Install with: pip install ipwhois"
            )

        result.outputs["whois_data"] = whois_data
        return result

    async def _domain_whois(self, domain: str) -> Exchange | None:
        """Query WHOIS for domain registration data.

        Returns the recorded exchange (57.4 wave 2). The parsed record is its
        JSON `response_body`, which is what both `whois_data` and `grade()` read.
        """
        loop = asyncio.get_event_loop()
        prb = None
        try:
            async with capture.probe("whois", domain, request_body=domain) as prb:
                info = await asyncio.wait_for(
                    loop.run_in_executor(None, self._sync_domain_whois, domain),
                    timeout=self.WHOIS_TIMEOUT,
                )
                prb.responded(json.dumps(info, default=str) if info else "")
        except (TimeoutError, Exception) as exc:
            logger.debug(f"Domain WHOIS failed for {domain}: {exc}")
        return prb.exchange if prb is not None else None

    def _sync_domain_whois(self, domain: str) -> dict[str, Any] | None:
        """Synchronous WHOIS query via socket (port 43)."""
        # Determine TLD and WHOIS server
        parts = domain.rsplit(".", 1)
        if len(parts) < 2:
            return None

        tld = parts[-1].lower()
        whois_server = WHOIS_SERVERS.get(tld)
        if not whois_server:
            # Try whois.iana.org as fallback
            whois_server = "whois.iana.org"

        try:
            with socket.create_connection((whois_server, 43), timeout=self.WHOIS_TIMEOUT) as sock:
                sock.sendall(f"{domain}\r\n".encode())

                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 32768:  # Cap at 32KB
                        break

            if not response:
                return None

            text = response.decode("utf-8", errors="replace")
            return self._parse_whois_response(text, domain)

        except OSError as exc:
            logger.debug(f"WHOIS socket error for {domain}: {exc}")
            return None

    def _parse_whois_response(self, text: str, domain: str) -> dict[str, Any]:
        """Parse raw WHOIS response into structured data."""
        info: dict[str, Any] = {
            "domain": domain,
            "registrar": None,
            "created": None,
            "expires": None,
            "updated": None,
            "nameservers": [],
            "status": [],
            "dnssec": None,
            "raw_length": len(text),
        }

        # Field mapping: WHOIS field names vary by registrar/TLD
        field_map = {
            "registrar": [
                "Registrar:",
                "registrar:",
                "Registrar Name:",
                "registrar name:",
                "Sponsoring Registrar:",
            ],
            "created": [
                "Creation Date:",
                "created:",
                "Created Date:",
                "Registration Date:",
                "Registered on:",
                "created date:",
                "Domain Registration Date:",
                "Creation date:",
            ],
            "expires": [
                "Registry Expiry Date:",
                "Expiration Date:",
                "expires:",
                "Expiry Date:",
                "Expiry date:",
                "paid-till:",
                "Domain Expiration Date:",
                "Registrar Registration Expiration Date:",
            ],
            "updated": [
                "Updated Date:",
                "Last Updated:",
                "updated:",
                "Last Modified:",
                "changed:",
                "last-update:",
            ],
        }

        lines = text.split("\n")
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("%") or stripped.startswith("#"):
                continue

            # Registrar, dates
            for field, prefixes in field_map.items():
                for prefix in prefixes:
                    if stripped.lower().startswith(prefix.lower()):
                        value = stripped[len(prefix) :].strip()
                        if value and not info[field]:
                            info[field] = value
                        break

            # Nameservers
            lower = stripped.lower()
            if lower.startswith("name server:") or lower.startswith("nserver:"):
                ns = stripped.split(":", 1)[1].strip().lower().rstrip(".")
                if ns and ns not in info["nameservers"]:
                    info["nameservers"].append(ns)

            # Status
            if lower.startswith("domain status:") or lower.startswith("status:"):
                status = stripped.split(":", 1)[1].strip()
                # Extract just the status code (before any URL)
                status_code = status.split()[0] if status else ""
                if status_code and status_code not in info["status"]:
                    info["status"].append(status_code)

            # DNSSEC
            if lower.startswith("dnssec:"):
                info["dnssec"] = stripped.split(":", 1)[1].strip()

        # Check for GDPR redaction
        text_lower = text.lower()
        info["redacted"] = any(
            marker in text_lower
            for marker in [
                "redacted for privacy",
                "data redacted",
                "gdpr",
                "not disclosed",
                "privacy protect",
            ]
        )

        return info

    async def _asn_lookup(self, ip: str) -> Exchange | None:
        """Look up ASN/network data for an IP via RDAP.

        Returns the recorded exchange (57.4 wave 2). Its `RDAP <ip>` request body
        is also how `grade()` knows it is grading a network rather than a domain.
        """
        if not HAS_IPWHOIS:
            return None

        loop = asyncio.get_event_loop()
        prb = None
        try:
            async with capture.probe("whois", ip, request_body=f"RDAP {ip}", method="rdap") as prb:
                info = await asyncio.wait_for(
                    loop.run_in_executor(None, self._sync_asn_lookup, ip),
                    timeout=self.RDAP_TIMEOUT,
                )
                prb.responded(json.dumps(info, default=str) if info else "")
        except (TimeoutError, Exception) as exc:
            logger.debug(f"ASN lookup failed for {ip}: {exc}")
        return prb.exchange if prb is not None else None

    def _sync_asn_lookup(self, ip: str) -> dict[str, Any] | None:
        """Synchronous ASN lookup via ipwhois RDAP."""
        try:
            obj = IPWhois(ip)
            # Use RDAP (modern replacement for WHOIS)
            rdap = obj.lookup_rdap(depth=0, asn_methods=["dns", "whois"])

            info: dict[str, Any] = {
                "ip": ip,
                "asn": None,
                "asn_description": None,
                "asn_country": None,
                "asn_registry": None,
                "network_name": None,
                "network_cidr": None,
                "network_country": None,
            }

            info["asn"] = rdap.get("asn")
            info["asn_description"] = rdap.get("asn_description")
            info["asn_country"] = rdap.get("asn_country_code")
            info["asn_registry"] = rdap.get("asn_registry")

            network = rdap.get("network", {})
            if network:
                info["network_name"] = network.get("name")
                info["network_cidr"] = rdap.get("asn_cidr")
                info["network_country"] = network.get("country")

            # Convert ASN to int if possible
            if info["asn"]:
                with contextlib.suppress(ValueError, TypeError):
                    info["asn"] = int(info["asn"])

            return info

        except IPDefinedError:
            # Private/reserved IP — expected for internal addresses
            logger.debug(f"Private/reserved IP: {ip}")
            return {"ip": ip, "asn": None, "private": True}
        except (ASNRegistryError, WhoisLookupError, WhoisRateLimitError) as exc:
            logger.debug(f"ASN lookup error for {ip}: {exc}")
            return None
        except Exception as exc:
            logger.debug(f"Unexpected ASN lookup error for {ip}: {exc}")
            return None

    # ══ Grade ════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one recorded WHOIS or RDAP answer.

        One grader, two subjects: the exchange says which. A bare domain in the
        request is the registration lookup; `RDAP <ip>` is the network one.
        """
        exchange = next((e for e in evidence if _payload_of(e)), None)
        if exchange is None:
            return []

        info = _payload_of(exchange)
        if _is_rdap(exchange):
            dns_records: dict[str, str] = ctx.context.get("dns_records") or {}
            ip = info.get("ip") or exchange.host
            hostnames = [h for h, addr in dns_records.items() if addr == ip] or [ctx.host]
            return self._asn_verdicts(ip, hostnames, info, exchange.id)
        return self._domain_verdicts(ctx.host, info, exchange.id)

    def _domain_verdicts(
        self, domain: str, info: dict[str, Any], evidence_id: str
    ) -> list[Verdict]:
        """Grade one domain's WHOIS record."""
        ids = [evidence_id]
        verdicts: list[Verdict] = []
        registrar = info.get("registrar", "unknown")
        created = info.get("created", "unknown")
        expires = info.get("expires", "unknown")
        nameservers = info.get("nameservers", [])
        ns_str = ", ".join(nameservers[:5]) if nameservers else "none found"

        # Info: domain registration details
        evidence_parts = [f"Domain: {domain}"]
        if registrar:
            evidence_parts.append(f"Registrar: {registrar}")
        if created:
            evidence_parts.append(f"Created: {created}")
        if expires:
            evidence_parts.append(f"Expires: {expires}")
        if nameservers:
            evidence_parts.append(f"NS: {ns_str}")

        verdicts.append(
            Verdict(
                severity="info",
                # WHOIS text has no schema. `_parse_whois_response` matches about
                # thirty field-name spellings across registrars and still leaves
                # fields null on TLDs it has not seen.
                confidence=0.9,
                discriminator="registration",
                title=f"Domain registrar: {registrar or 'unknown'}",
                description=(
                    f"WHOIS registration data for {domain}. "
                    f"Registrar: {registrar}. Created: {created}. Expires: {expires}. "
                    f"Nameservers: {ns_str}."
                ),
                evidence=" | ".join(evidence_parts),
                reasoning="Fields read from the registry's WHOIS response",
                signals={
                    "registrar": registrar,
                    "created": created,
                    "expires": expires,
                    "nameservers": nameservers,
                },
                raw_data=info,
                evidence_ids=ids,
            )
        )

        # ── A domain registered recently ───────────────────
        #
        # Not reproducible from the corpus alone: the age is measured against
        # *now*, so the same stored record grades differently in four months.
        if created and created != "unknown":
            days_old = self._domain_age_days(created)
            if days_old is not None and 0 <= days_old <= RECENT_REGISTRATION_DAYS:
                verdicts.append(
                    Verdict(
                        severity="low",
                        # The arithmetic is exact once the date parses, but the
                        # creation field is sometimes a transfer or re-registration
                        # date rather than the domain's first registration.
                        confidence=0.85,
                        discriminator="recent-registration",
                        title=f"Domain registered within last {RECENT_REGISTRATION_DAYS} days",
                        description=(
                            f"{domain} was registered approximately {days_old} days ago "
                            f"(created: {created}). Recently-registered domains hosting "
                            f"services may indicate phishing, shadow IT, or a new project."
                        ),
                        evidence=(f"Domain: {domain} | Created: {created} | Age: ~{days_old} days"),
                        reasoning=(
                            f"Creation date {created} is ~{days_old} days before the date "
                            f"this was graded"
                        ),
                        signals={"created": created, "days_old": days_old},
                        evidence_ids=ids,
                    )
                )

        # ── Registrant data withheld ───────────────────────
        if info.get("redacted"):
            verdicts.append(
                Verdict(
                    severity="info",
                    # Detected by substring — "gdpr" anywhere in the response
                    # counts, including in a registry's boilerplate footer.
                    confidence=0.85,
                    discriminator="redacted",
                    title=f"WHOIS data redacted (privacy/GDPR): {domain}",
                    description=(
                        f"WHOIS registrant data for {domain} is redacted for privacy. "
                        f"This is common under GDPR and does not indicate a problem."
                    ),
                    evidence=f"Domain: {domain} | Redacted: True",
                    reasoning="Response contains a privacy-redaction marker",
                    signals={"redacted": True},
                    evidence_ids=ids,
                )
            )

        return verdicts

    def _asn_verdicts(
        self,
        ip: str,
        hostnames: list[str],
        info: dict[str, Any],
        evidence_id: str,
    ) -> list[Verdict]:
        """Grade one IP's RDAP answer."""
        ids = [evidence_id]
        if info.get("private"):
            return [
                Verdict(
                    severity="info",
                    # `ipwhois` raised IPDefinedError, which is arithmetic over
                    # the reserved ranges rather than a lookup.
                    confidence=0.99,
                    discriminator=f"private-{ip}",
                    title=f"Private/reserved IP: {ip}",
                    description=(
                        f"IP {ip} ({', '.join(hostnames)}) is in a private or "
                        f"reserved address range."
                    ),
                    evidence=f"IP: {ip} | Hosts: {', '.join(hostnames)} | Private: True",
                    reasoning="Address falls in a reserved range",
                    signals={"private": True},
                    evidence_ids=ids,
                )
            ]

        asn = info.get("asn")
        asn_desc = info.get("asn_description", "unknown")
        asn_country = info.get("asn_country", "unknown")
        network_name = info.get("network_name", "unknown")
        cidr = info.get("network_cidr", "unknown")

        asn_str = f"AS{asn}" if asn else "unknown ASN"

        return [
            Verdict(
                severity="info",
                # The registry's own answer about its own allocation.
                confidence=0.95,
                discriminator=f"asn-{ip}",
                title=f"IP {ip} belongs to {asn_str} ({asn_desc})",
                description=(
                    f"ASN/network data for {ip} ({', '.join(hostnames)}). "
                    f"Network: {network_name} ({cidr}). "
                    f"ASN: {asn_str} — {asn_desc}. Country: {asn_country}."
                ),
                evidence=(
                    f"IP: {ip} | ASN: {asn_str} | Org: {asn_desc} | "
                    f"Network: {network_name} ({cidr}) | Country: {asn_country}"
                ),
                reasoning="RDAP returned the allocation for this address",
                signals={
                    "asn": asn,
                    "asn_description": asn_desc,
                    "network_cidr": cidr,
                    "asn_country": asn_country,
                },
                raw_data=info,
                evidence_ids=ids,
            )
        ]

    @staticmethod
    def _domain_age_days(created_str: str) -> int | None:
        """Parse a creation date string and return domain age in days."""
        # Common WHOIS date formats
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%d-%b-%Y",
            "%d/%m/%Y",
            "%Y/%m/%d",
            "%Y.%m.%d",
            "%d.%m.%Y",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(created_str.strip(), fmt)  # noqa: DTZ007
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                now = datetime.now(UTC)
                return (now - dt).days
            except ValueError:
                continue
        return None


def _payload_of(exchange: Exchange | None) -> dict[str, Any] | None:
    """The WHOIS record or RDAP result one recorded lookup came back with.

    57.2 wrote it into `response_body` as JSON, so this reads back rather than
    re-parsing the registry's text a second time.
    """
    if exchange is None or exchange.error is not None or not exchange.response_body:
        return None
    try:
        payload = json.loads(exchange.response_body)
    except (ValueError, TypeError):
        logger.debug("Could not read WHOIS payload from exchange %s", exchange.id)
        return None
    return payload if isinstance(payload, dict) else None


def _is_rdap(exchange: Exchange) -> bool:
    """True for a network lookup, false for a domain registration lookup."""
    if (exchange.request_headers or {}).get("method") == "rdap":
        return True
    return (exchange.request_body or "").startswith("RDAP ")
