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
"""

import asyncio
import contextlib
import logging
import socket
from datetime import UTC, datetime
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.findings import build_finding

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

    name = "whois_lookup"
    description = "WHOIS domain registration and ASN lookup for resolved IPs"

    conditions = [
        CheckCondition("dns_records", "truthy"),
    ]
    produces = ["whois_data"]

    timeout_seconds = 60.0
    requests_per_second = 2.0  # WHOIS servers rate-limit aggressively

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
            domain_info = await self._domain_whois(base_domain)
            if domain_info:
                whois_data["domain"] = domain_info
                self._generate_domain_findings(result, base_domain, domain_info)

        # Step 2: ASN/RDAP lookups for unique IPs
        if HAS_IPWHOIS:
            unique_ips = set(dns_records.values())
            ip_to_hosts: dict[str, list[str]] = {}
            for hostname, ip in dns_records.items():
                ip_to_hosts.setdefault(ip, []).append(hostname)

            for ip in unique_ips:
                asn_info = await self._asn_lookup(ip)
                if asn_info:
                    whois_data["asn"][ip] = asn_info
                    self._generate_asn_findings(result, ip, ip_to_hosts.get(ip, []), asn_info)
                result.targets_checked += 1

                # Rate limiting between lookups
                await asyncio.sleep(1.0 / self.requests_per_second)
        else:
            result.errors.append(
                "ipwhois not installed — ASN lookups skipped. Install with: pip install ipwhois"
            )

        result.outputs["whois_data"] = whois_data
        return result

    async def _domain_whois(self, domain: str) -> dict[str, Any] | None:
        """Query WHOIS for domain registration data."""
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_domain_whois, domain),
                timeout=self.WHOIS_TIMEOUT,
            )
        except (TimeoutError, Exception) as exc:
            logger.debug(f"Domain WHOIS failed for {domain}: {exc}")
            return None

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

    async def _asn_lookup(self, ip: str) -> dict[str, Any] | None:
        """Look up ASN/network data for an IP via RDAP."""
        if not HAS_IPWHOIS:
            return None

        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, self._sync_asn_lookup, ip),
                timeout=self.RDAP_TIMEOUT,
            )
        except (TimeoutError, Exception) as exc:
            logger.debug(f"ASN lookup failed for {ip}: {exc}")
            return None

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

    def _generate_domain_findings(
        self,
        result: CheckResult,
        domain: str,
        info: dict[str, Any],
    ) -> None:
        """Generate findings from domain WHOIS data."""
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

        result.findings.append(
            build_finding(
                check_name=self.name,
                title=f"Domain registrar: {registrar or 'unknown'}",
                description=(
                    f"WHOIS registration data for {domain}. "
                    f"Registrar: {registrar}. Created: {created}. Expires: {expires}. "
                    f"Nameservers: {ns_str}."
                ),
                severity="info",
                evidence=" | ".join(evidence_parts),
                host=domain,
                discriminator="registration",
                raw_data=info,
            )
        )

        # Low: recently registered domain
        if created and created != "unknown":
            days_old = self._domain_age_days(created)
            if days_old is not None and 0 <= days_old <= RECENT_REGISTRATION_DAYS:
                result.findings.append(
                    build_finding(
                        check_name=self.name,
                        title=f"Domain registered within last {RECENT_REGISTRATION_DAYS} days",
                        description=(
                            f"{domain} was registered approximately {days_old} days ago "
                            f"(created: {created}). Recently-registered domains hosting "
                            f"services may indicate phishing, shadow IT, or a new project."
                        ),
                        severity="low",
                        evidence=f"Domain: {domain} | Created: {created} | Age: ~{days_old} days",
                        host=domain,
                        discriminator="recent-registration",
                    )
                )

        # Info: WHOIS data redacted (GDPR)
        if info.get("redacted"):
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"WHOIS data redacted (privacy/GDPR): {domain}",
                    description=(
                        f"WHOIS registrant data for {domain} is redacted for privacy. "
                        f"This is common under GDPR and does not indicate a problem."
                    ),
                    severity="info",
                    evidence=f"Domain: {domain} | Redacted: True",
                    host=domain,
                    discriminator="redacted",
                )
            )

    def _generate_asn_findings(
        self,
        result: CheckResult,
        ip: str,
        hostnames: list[str],
        info: dict[str, Any],
    ) -> None:
        """Generate findings from ASN/RDAP data."""
        if info.get("private"):
            host_label = hostnames[0] if hostnames else ip
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Private/reserved IP: {ip}",
                    description=(
                        f"IP {ip} ({', '.join(hostnames)}) is in a private or "
                        f"reserved address range."
                    ),
                    severity="info",
                    evidence=f"IP: {ip} | Hosts: {', '.join(hostnames)} | Private: True",
                    host=host_label,
                    discriminator=f"private-{ip}",
                )
            )
            return

        asn = info.get("asn")
        asn_desc = info.get("asn_description", "unknown")
        asn_country = info.get("asn_country", "unknown")
        network_name = info.get("network_name", "unknown")
        cidr = info.get("network_cidr", "unknown")
        host_label = hostnames[0] if hostnames else ip

        asn_str = f"AS{asn}" if asn else "unknown ASN"

        result.findings.append(
            build_finding(
                check_name=self.name,
                title=f"IP {ip} belongs to {asn_str} ({asn_desc})",
                description=(
                    f"ASN/network data for {ip} ({', '.join(hostnames)}). "
                    f"Network: {network_name} ({cidr}). "
                    f"ASN: {asn_str} — {asn_desc}. Country: {asn_country}."
                ),
                severity="info",
                evidence=(
                    f"IP: {ip} | ASN: {asn_str} | Org: {asn_desc} | "
                    f"Network: {network_name} ({cidr}) | Country: {asn_country}"
                ),
                host=host_label,
                discriminator=f"asn-{ip}",
                raw_data=info,
            )
        )

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
                dt = datetime.strptime(created_str.strip(), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                now = datetime.now(UTC)
                return (now - dt).days
            except ValueError:
                continue
        return None
