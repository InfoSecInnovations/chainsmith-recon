"""
app/checks/network/dns_records.py

DNS Record Extraction

Queries MX, NS, TXT, CNAME, SOA, AAAA records for the target domain
using dnspython. Extracts infrastructure context, verification tokens,
cloud provider info, and additional hostnames.

Depends on: base_domain (no prior check needed)
Feeds: all downstream checks with additional hostnames and infrastructure context
"""

import logging
import re
from typing import Any

from app.checks.base import BaseCheck, CheckResult
from app.lib.observations import build_observation

logger = logging.getLogger(__name__)

try:
    import dns.exception
    import dns.resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# Patterns that indicate interesting TXT record content
VERIFICATION_PATTERNS = [
    (r"google-site-verification[=:]", "Google site verification token"),
    (r"MS=ms\d+", "Microsoft domain verification token"),
    (r"facebook-domain-verification=", "Facebook domain verification token"),
    (r"apple-domain-verification=", "Apple domain verification token"),
    (r"docusign=", "DocuSign domain verification token"),
    (r"atlassian-domain-verification=", "Atlassian domain verification token"),
    (r"_?globalsign-domain-verification=", "GlobalSign domain verification token"),
    (r"stripe-verification=", "Stripe domain verification token"),
    (r"hubspot-developer-verification=", "HubSpot domain verification token"),
]

# Cloud/service providers detectable from SPF includes
SPF_PROVIDERS = {
    "_spf.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "amazonses.com": "Amazon SES",
    "sendgrid.net": "SendGrid",
    "mailgun.org": "Mailgun",
    "servers.mcsv.net": "Mailchimp",
    "firebasemail.com": "Firebase",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
}


class DnsRecordCheck(BaseCheck):
    """
    Extract DNS records (MX, NS, TXT, CNAME, SOA, AAAA) for the target domain.

    Discovers mail infrastructure, DNS hosting, cloud providers,
    verification tokens, and additional hostnames.

    Produces:
        dns_extra_records - dict of record type -> list of record values
        dns_extra_hosts   - list[str] of additional hostnames found in records
    """

    name = "dns_records"
    description = "Extract MX, NS, TXT, CNAME, SOA, AAAA records for infrastructure context"

    conditions = []  # Entry point — no upstream dependencies
    produces = ["dns_extra_records", "dns_extra_hosts"]

    timeout_seconds = 30.0
    requests_per_second = 10.0

    reason = (
        "DNS records reveal mail infrastructure, DNS hosting, cloud providers, "
        "and service relationships. TXT records frequently leak verification "
        "tokens and SPF configurations."
    )
    references = [
        "OWASP WSTG-INFO-03",
        "RFC 1035 — Domain Names",
        "RFC 7208 — SPF",
    ]
    techniques = ["DNS record extraction", "infrastructure enumeration"]

    RECORD_TYPES = ["MX", "NS", "TXT", "CNAME", "SOA", "AAAA"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        if not HAS_DNSPYTHON:
            result.errors.append("dnspython not installed. Install with: pip install dnspython")
            result.success = False
            return result

        base_domain = context.get("base_domain", "")
        if not base_domain:
            result.errors.append("No base_domain in context.")
            result.success = False
            return result

        records: dict[str, list[str]] = {}
        extra_hosts: list[str] = []

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        for rtype in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(base_domain, rtype)
                rdata_list = [rdata.to_text() for rdata in answers]
                records[rtype] = rdata_list

                for rdata_str in rdata_list:
                    self._process_record(result, base_domain, rtype, rdata_str, extra_hosts)

            except dns.resolver.NoAnswer:
                logger.debug(f"No {rtype} records for {base_domain}")
            except dns.resolver.NXDOMAIN:
                result.errors.append(f"Domain {base_domain} does not exist (NXDOMAIN)")
                result.success = False
                return result
            except dns.exception.DNSException as e:
                logger.debug(f"DNS query failed for {rtype}/{base_domain}: {e}")

        # Deduplicate extra hosts
        extra_hosts = list(dict.fromkeys(extra_hosts))

        result.outputs["dns_extra_records"] = records
        result.outputs["dns_extra_hosts"] = extra_hosts

        return result

    def _process_record(
        self,
        result: CheckResult,
        base_domain: str,
        rtype: str,
        rdata: str,
        extra_hosts: list[str],
    ) -> None:
        """Process a single DNS record, generating observations and extracting hosts."""

        if rtype == "MX":
            # MX format: "10 mail.example.com."
            parts = rdata.split()
            if len(parts) >= 2:
                priority = parts[0]
                mx_host = parts[1].rstrip(".")
                extra_hosts.append(mx_host)
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"MX record: {mx_host} (priority {priority})",
                        description=f"Mail exchange server for {base_domain}",
                        severity="info",
                        evidence=f"MX {priority} {mx_host}",
                        host=base_domain,
                        discriminator=f"mx-{mx_host}",
                    )
                )

        elif rtype == "NS":
            ns_host = rdata.rstrip(".")
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"NS record: {ns_host}",
                    description=f"Nameserver for {base_domain}",
                    severity="info",
                    evidence=f"NS {ns_host}",
                    host=base_domain,
                    discriminator=f"ns-{ns_host}",
                )
            )

        elif rtype == "TXT":
            self._process_txt_record(result, base_domain, rdata)

        elif rtype == "CNAME":
            cname_host = rdata.rstrip(".")
            extra_hosts.append(cname_host)
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"CNAME record: {base_domain} -> {cname_host}",
                    description="Canonical name alias reveals target infrastructure",
                    severity="info",
                    evidence=f"CNAME {cname_host}",
                    host=base_domain,
                    discriminator=f"cname-{cname_host}",
                )
            )

        elif rtype == "SOA":
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"SOA record for {base_domain}",
                    description="Start of Authority record reveals primary NS and admin contact",
                    severity="info",
                    evidence=f"SOA {rdata}",
                    host=base_domain,
                    discriminator="soa",
                )
            )

        elif rtype == "AAAA":
            result.observations.append(
                build_observation(
                    check_name=self.name,
                    title=f"IPv6 address: {base_domain} -> {rdata}",
                    description=f"AAAA record for {base_domain}",
                    severity="info",
                    evidence=f"AAAA {rdata}",
                    host=base_domain,
                    discriminator=f"aaaa-{rdata}",
                )
            )

    def _process_txt_record(self, result: CheckResult, base_domain: str, rdata: str) -> None:
        """Analyze a TXT record for verification tokens and SPF data."""
        # Strip surrounding quotes from TXT rdata
        txt_value = rdata.strip('"')

        # Check for verification tokens
        for pattern, label in VERIFICATION_PATTERNS:
            if re.search(pattern, txt_value, re.IGNORECASE):
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"TXT record: {label}",
                        description=(
                            "Verification token found in TXT record. "
                            "Reveals third-party service integration."
                        ),
                        severity="low",
                        evidence=f"TXT {txt_value[:200]}",
                        host=base_domain,
                        discriminator=f"txt-{label[:30]}",
                    )
                )
                return  # One observation per TXT record

        # Check for SPF records
        if txt_value.lower().startswith("v=spf1"):
            providers_found = []
            for domain_pattern, provider_name in SPF_PROVIDERS.items():
                if domain_pattern in txt_value.lower():
                    providers_found.append(provider_name)

            if providers_found:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"SPF reveals providers: {', '.join(providers_found)}",
                        description=(
                            "SPF record includes mail providers, revealing "
                            "third-party service relationships."
                        ),
                        severity="low",
                        evidence=f"TXT {txt_value[:200]}",
                        host=base_domain,
                        discriminator="txt-spf",
                    )
                )
            else:
                result.observations.append(
                    build_observation(
                        check_name=self.name,
                        title=f"SPF record for {base_domain}",
                        description="SPF record found",
                        severity="info",
                        evidence=f"TXT {txt_value[:200]}",
                        host=base_domain,
                        discriminator="txt-spf",
                    )
                )
            return

        # Generic TXT record
        result.observations.append(
            build_observation(
                check_name=self.name,
                title=f"TXT record for {base_domain}",
                description="TXT record found",
                severity="info",
                evidence=f"TXT {txt_value[:200]}",
                host=base_domain,
                discriminator=f"txt-{txt_value[:20]}",
            )
        )
