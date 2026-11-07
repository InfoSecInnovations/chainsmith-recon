"""
app/checks/network/dns_records.py

DNS Record Extraction

Queries MX, NS, TXT, CNAME, SOA, AAAA records for the target domain
using dnspython. Extracts infrastructure context, verification tokens,
cloud provider info, and additional hostnames.

Depends on: base_domain (no prior check needed)
Feeds: all downstream checks with additional hostnames and infrastructure context

**Probe/grade.** `run()` queries each record type and records
one `dns` exchange per type — the query in `request_body`, the answers
newline-joined in `response_body`; `grade()` reads those answers back and places
severity on each one. This check had no capture at all before wave 2, because it
calls the resolver directly rather than through `capture.probe()`; it records via
`capture.record_exchange()`, which is the same writer without the timing context
manager.

`dns_extra_hosts` feeds hostnames back into discovery, so the probe parses MX and
CNAME targets for itself (§6.2's two parses). Newline-joined rather than
comma-joined, unlike the other resolver checks: a TXT record's own content
routinely contains commas.
"""

import logging
import re
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckResult
from app.grading import Evidence, GradeContext, Verdict

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

    name = "network_dns_records"
    description = "Extract MX, NS, TXT, CNAME, SOA, AAAA records for infrastructure context"

    conditions = []  # Entry point — no upstream dependencies
    produces = ["dns_extra_records", "dns_extra_hosts"]

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

                exchange = capture.record_exchange(
                    "dns",
                    base_domain,
                    request_body=rtype,
                    request_headers={"qtype": rtype},
                    response_body="\n".join(rdata_list),
                )
                # One candidate per record type. The discriminator matters only
                # if grading is deferred — the verdicts below name their own —
                # but without it every unheard type would share one id.
                result.candidates.append(
                    self.create_candidate(host=base_domain, discriminator=rtype.lower()).attach(
                        exchange
                    )
                )

                for rdata_str in rdata_list:
                    extra_hosts.extend(self._extra_hosts(rtype, rdata_str))

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

    @staticmethod
    def _extra_hosts(rtype: str, rdata: str) -> list[str]:
        """Hostnames one record contributes to `dns_extra_hosts`.

        The probe's half of the double parse: these feed back into discovery, so
        they cannot wait for a grader.
        """
        if rtype == "MX":
            parts = rdata.split()
            return [parts[1].rstrip(".")] if len(parts) >= 2 else []
        if rtype == "CNAME":
            return [rdata.rstrip(".")]
        return []

    # ══ Grade ════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on the records one query came back with."""
        base_domain = ctx.host
        verdicts: list[Verdict] = []
        for exchange in evidence:
            rtype = exchange.request_body
            for rdata in _records(exchange):
                verdicts.extend(self._verdicts_for(base_domain, rtype, rdata, exchange.id))
        return verdicts

    def _verdicts_for(
        self, base_domain: str, rtype: str, rdata: str, evidence_id: str
    ) -> list[Verdict]:
        """Grade a single DNS record."""
        ids = [evidence_id]

        if rtype == "MX":
            # MX format: "10 mail.example.com."
            parts = rdata.split()
            if len(parts) < 2:
                return []
            priority, mx_host = parts[0], parts[1].rstrip(".")
            return [
                Verdict(
                    severity="info",
                    # A record is a record.
                    confidence=0.99,
                    discriminator=f"mx-{mx_host}",
                    title=f"MX record: {mx_host} (priority {priority})",
                    description=f"Mail exchange server for {base_domain}",
                    evidence=f"MX {priority} {mx_host}",
                    reasoning="MX record returned by the authoritative resolver",
                    signals={"mx_host": mx_host, "priority": priority},
                    evidence_ids=ids,
                )
            ]

        if rtype == "NS":
            ns_host = rdata.rstrip(".")
            return [
                Verdict(
                    severity="info",
                    confidence=0.99,
                    discriminator=f"ns-{ns_host}",
                    title=f"NS record: {ns_host}",
                    description=f"Nameserver for {base_domain}",
                    evidence=f"NS {ns_host}",
                    reasoning="NS record returned by the authoritative resolver",
                    signals={"ns_host": ns_host},
                    evidence_ids=ids,
                )
            ]

        if rtype == "TXT":
            return self._txt_verdicts(base_domain, rdata, ids)

        if rtype == "CNAME":
            cname_host = rdata.rstrip(".")
            return [
                Verdict(
                    severity="info",
                    confidence=0.99,
                    discriminator=f"cname-{cname_host}",
                    title=f"CNAME record: {base_domain} -> {cname_host}",
                    description="Canonical name alias reveals target infrastructure",
                    evidence=f"CNAME {cname_host}",
                    reasoning="CNAME record returned by the authoritative resolver",
                    signals={"cname_host": cname_host},
                    evidence_ids=ids,
                )
            ]

        if rtype == "SOA":
            return [
                Verdict(
                    severity="info",
                    confidence=0.99,
                    discriminator="soa",
                    title=f"SOA record for {base_domain}",
                    description=("Start of Authority record reveals primary NS and admin contact"),
                    evidence=f"SOA {rdata}",
                    reasoning="SOA record returned by the authoritative resolver",
                    signals={"soa": rdata},
                    evidence_ids=ids,
                )
            ]

        if rtype == "AAAA":
            return [
                Verdict(
                    severity="info",
                    confidence=0.99,
                    discriminator=f"aaaa-{rdata}",
                    title=f"IPv6 address: {base_domain} -> {rdata}",
                    description=f"AAAA record for {base_domain}",
                    evidence=f"AAAA {rdata}",
                    reasoning="AAAA record returned by the authoritative resolver",
                    signals={"address": rdata},
                    evidence_ids=ids,
                )
            ]

        return []

    def _txt_verdicts(self, base_domain: str, rdata: str, ids: list[str]) -> list[Verdict]:
        """Grade one TXT record: verification token, SPF, or neither."""
        # Strip surrounding quotes from TXT rdata
        txt_value = rdata.strip('"')

        # ── Third-party verification tokens ──────────────
        for pattern, label in VERIFICATION_PATTERNS:
            if re.search(pattern, txt_value, re.IGNORECASE):
                return [  # One verdict per TXT record
                    Verdict(
                        severity="low",
                        # The token formats are vendor-documented and specific
                        # enough that a false match is unlikely but not absurd.
                        confidence=0.95,
                        discriminator=f"txt-{label[:30]}",
                        title=f"TXT record: {label}",
                        description=(
                            "Verification token found in TXT record. "
                            "Reveals third-party service integration."
                        ),
                        evidence=f"TXT {txt_value[:200]}",
                        reasoning=f"TXT value matches the {label} format",
                        signals={"label": label},
                        evidence_ids=ids,
                    )
                ]

        # ── SPF ─────────────────────────────────────────
        if txt_value.lower().startswith("v=spf1"):
            providers_found = [
                name for pattern, name in SPF_PROVIDERS.items() if pattern in txt_value.lower()
            ]

            if providers_found:
                return [
                    Verdict(
                        severity="low",
                        # Matched against include domains the providers publish.
                        confidence=0.9,
                        discriminator="txt-spf",
                        title=f"SPF reveals providers: {', '.join(providers_found)}",
                        description=(
                            "SPF record includes mail providers, revealing "
                            "third-party service relationships."
                        ),
                        evidence=f"TXT {txt_value[:200]}",
                        reasoning=(f"SPF includes {len(providers_found)} recognised provider(s)"),
                        signals={"providers": providers_found},
                        evidence_ids=ids,
                    )
                ]

            return [
                Verdict(
                    severity="info",
                    confidence=0.99,
                    discriminator="txt-spf",
                    title=f"SPF record for {base_domain}",
                    description="SPF record found",
                    evidence=f"TXT {txt_value[:200]}",
                    reasoning="TXT value begins with v=spf1",
                    signals={"providers": []},
                    evidence_ids=ids,
                )
            ]

        # ── Anything else ────────────────────────────────
        return [
            Verdict(
                severity="info",
                confidence=0.99,
                discriminator=f"txt-{txt_value[:20]}",
                title=f"TXT record for {base_domain}",
                description="TXT record found",
                evidence=f"TXT {txt_value[:200]}",
                reasoning="TXT record present, matching no known token or SPF shape",
                signals={},
                evidence_ids=ids,
            )
        ]


def _records(exchange: Exchange) -> list[str]:
    """The records one recorded query came back with, one per line."""
    if exchange.error is not None or not exchange.response_body:
        return []
    return [line for line in exchange.response_body.split("\n") if line]
