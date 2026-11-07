"""
app/checks/network/geoip.py

GeoIP and IP Classification

Looks up resolved IPs against MaxMind GeoLite2 databases for geolocation
and ASN data. Classifies IPs as hosting vs residential based on ASN.

Depends on: dns_enumeration (needs dns_records output with hostname -> IP mapping)
Feeds: enriches host metadata for all downstream checks and reporting

Requirements:
  - geoip2 Python library (pip install geoip2)
  - MaxMind GeoLite2-City.mmdb and GeoLite2-ASN.mmdb database files
  - Database files require a free MaxMind account + license key to download
  - Set GEOIP_DB_DIR env var to point to the directory containing .mmdb files,
    or place them in ./data/geoip/

If database files are not available, the check skips gracefully.

**Probe/grade.** `run()` queries the databases and records one
`local` exchange per IP — the address asked for, the answer as JSON; `grade()`
reads that answer back and places severity. This is the first check to record the
`local` protocol, and it is worth saying why a database lookup is capture at all:
the grader reads evidence and nothing else, so a verdict derived from a GeoLite2
row needs that row on the record. A corpus copy also pins *which* answer was
given, which matters here more than elsewhere — these databases are reissued
weekly and an ASN's classification moves.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any

from app import capture
from app.capture.models import Exchange
from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.grading import Evidence, GradeContext, Verdict

logger = logging.getLogger(__name__)

try:
    import geoip2.database
    import geoip2.errors

    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False


# Known hosting/cloud provider ASNs (ASN number -> provider name)
HOSTING_ASNS: dict[int, str] = {
    # Major cloud
    16509: "Amazon AWS",
    14618: "Amazon AWS",
    8075: "Microsoft Azure",
    15169: "Google Cloud",
    396982: "Google Cloud",
    19527: "Google Cloud",
    # CDN / Edge
    13335: "Cloudflare",
    20940: "Akamai",
    16625: "Akamai",
    54113: "Fastly",
    13238: "Yandex Cloud",
    # VPS / Hosting
    14061: "DigitalOcean",
    63949: "Linode/Akamai",
    20473: "Vultr",
    24940: "Hetzner",
    16276: "OVHcloud",
    51167: "Contabo",
    212238: "Datacamp (budget VPS)",
    # Other infrastructure
    36351: "SoftLayer/IBM Cloud",
    19844: "Rackspace",
    46606: "Unity Technologies",
    8100: "QuadraNet",
    55286: "Scaleway",
    197540: "Netcup",
}

# ASNs known to be residential / consumer ISPs (sample)
RESIDENTIAL_ASNS: dict[int, str] = {
    7922: "Comcast",
    7018: "AT&T",
    701: "Verizon",
    22773: "Cox Communications",
    20115: "Charter/Spectrum",
    6128: "CenturyLink",
    5650: "Frontier",
    6327: "Shaw Communications",
    577: "Bell Canada",
    2856: "BT (British Telecom)",
    3320: "Deutsche Telekom",
    12322: "Free (France)",
    3215: "Orange (France)",
    3269: "Telecom Italia",
    3352: "Telefonica",
}

# Default locations to search for GeoIP databases
DEFAULT_DB_DIRS = [
    "./data/geoip",
    os.path.expanduser("~/.geoip"),
    "/usr/share/GeoIP",
    "/var/lib/GeoIP",
]


def _find_db_file(filename: str) -> str | None:
    """Search for a GeoIP database file in standard locations."""
    # Check env var first
    env_dir = os.environ.get("GEOIP_DB_DIR")
    if env_dir:
        path = Path(env_dir) / filename
        if path.exists():
            return str(path)

    for d in DEFAULT_DB_DIRS:
        path = Path(d) / filename
        if path.exists():
            return str(path)

    return None


class GeoIpCheck(BaseCheck):
    """
    Look up resolved IPs for geolocation and ASN classification.

    Uses MaxMind GeoLite2 databases (free, requires account for download).
    Classifies IPs as hosting/cloud vs residential/consumer.
    Skips gracefully if databases are unavailable.

    Produces:
        geoip_data - dict[ip_str, {country, region, city, asn, org, classification}]
    """

    name = "network_geoip"
    description = "GeoIP and ASN lookup for resolved IP addresses"

    conditions = [
        CheckCondition("dns_records", "truthy"),
    ]
    produces = ["geoip_data"]

    reason = (
        "IP geolocation and ASN data reveal hosting providers, geographic "
        "distribution, and unexpected infrastructure (e.g., residential IPs "
        "hosting production services)."
    )
    references = [
        "PTES - Intelligence Gathering",
        "https://attack.mitre.org/techniques/T1590/",
    ]
    techniques = ["IP geolocation", "ASN classification", "infrastructure mapping"]

    async def run(self, context: dict[str, Any]) -> CheckResult:
        result = CheckResult(success=True)

        if not HAS_GEOIP2:
            result.errors.append("geoip2 not installed. Install with: pip install geoip2")
            result.success = False
            return result

        # Find database files
        city_db_path = _find_db_file("GeoLite2-City.mmdb")
        asn_db_path = _find_db_file("GeoLite2-ASN.mmdb")

        if not city_db_path and not asn_db_path:
            result.errors.append(
                "No GeoLite2 database files found. Download from MaxMind "
                "(requires free account + license key). Set GEOIP_DB_DIR "
                "env var or place files in ./data/geoip/"
            )
            result.success = False
            return result

        # Get IP addresses from dns_records context
        dns_records: dict[str, str] = context.get("dns_records", {})
        if not dns_records:
            result.errors.append("No dns_records in context (need hostname -> IP mapping)")
            return result

        # Deduplicate IPs (multiple hosts may resolve to the same IP)
        ip_to_hosts: dict[str, list[str]] = {}
        for hostname, ip in dns_records.items():
            ip_to_hosts.setdefault(ip, []).append(hostname)

        geoip_data: dict[str, dict] = {}

        # Which databases answered is part of the record: the same IP grades
        # differently against a City-only corpus than against City + ASN.
        databases = {name for name, path in (("city", city_db_path), ("asn", asn_db_path)) if path}

        # Open database readers
        city_reader = None
        asn_reader = None
        try:
            if city_db_path:
                city_reader = geoip2.database.Reader(city_db_path)
            if asn_db_path:
                asn_reader = geoip2.database.Reader(asn_db_path)

            for ip, hostnames in ip_to_hosts.items():
                entry = self._lookup_ip(ip, city_reader, asn_reader)
                geoip_data[ip] = entry

                exchange = capture.record_exchange(
                    "local",
                    ip,
                    request_body=f"geoip {ip}",
                    request_headers={"databases": ",".join(sorted(databases))},
                    response_body=json.dumps(entry, default=str),
                )
                result.candidates.append(
                    self.create_candidate(host=hostnames[0] if hostnames else ip).attach(exchange)
                )

        finally:
            if city_reader:
                city_reader.close()
            if asn_reader:
                asn_reader.close()

        result.outputs["geoip_data"] = geoip_data
        result.targets_checked = len(ip_to_hosts)

        return result

    def _lookup_ip(
        self,
        ip: str,
        city_reader: Any,
        asn_reader: Any,
    ) -> dict:
        """Look up a single IP in the GeoIP databases."""
        entry: dict[str, Any] = {
            "ip": ip,
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "asn": None,
            "org": None,
            "classification": "unknown",
        }

        # City/Geo lookup
        if city_reader:
            try:
                resp = city_reader.city(ip)
                entry["country"] = resp.country.name
                entry["country_code"] = resp.country.iso_code
                entry["region"] = (
                    resp.subdivisions.most_specific.name if resp.subdivisions else None
                )
                entry["city"] = resp.city.name
                entry["latitude"] = resp.location.latitude
                entry["longitude"] = resp.location.longitude
            except (geoip2.errors.AddressNotFoundError, ValueError):
                logger.debug(f"No city data for {ip}")

        # ASN lookup
        if asn_reader:
            try:
                resp = asn_reader.asn(ip)
                entry["asn"] = resp.autonomous_system_number
                entry["org"] = resp.autonomous_system_organization
            except (geoip2.errors.AddressNotFoundError, ValueError):
                logger.debug(f"No ASN data for {ip}")

        # Classify
        asn = entry["asn"]
        if asn in HOSTING_ASNS:
            entry["classification"] = "hosting"
            entry["provider"] = HOSTING_ASNS[asn]
        elif asn in RESIDENTIAL_ASNS:
            entry["classification"] = "residential"
            entry["provider"] = RESIDENTIAL_ASNS[asn]
        elif asn is not None:
            entry["classification"] = "other"

        return entry

    # ══ Grade ════════════════════════════════════════════════════

    def grade(self, evidence: Evidence, ctx: GradeContext) -> list[Verdict]:
        """Place severity on one IP's recorded GeoIP answer."""
        exchange = next((e for e in evidence if _entry_from(e)), None)
        if exchange is None:
            return []

        entry = _entry_from(exchange)
        ip = entry.get("ip") or exchange.host
        host_label = ctx.host
        # The hostnames behind this address are an upstream output, not this
        # check's evidence — the same map the probe grouped by.
        dns_records: dict[str, str] = ctx.context.get("dns_records") or {}
        hostnames = [host for host, addr in dns_records.items() if addr == ip] or [host_label]

        location_parts = [
            p for p in [entry.get("country_code"), entry.get("region"), entry.get("city")] if p
        ]
        location = ", ".join(location_parts) if location_parts else "unknown location"
        org = entry.get("org", "unknown")
        asn = entry.get("asn")
        asn_str = f"AS{asn}" if asn else "unknown ASN"
        classification = entry.get("classification", "unknown")

        evidence_ids = [exchange.id]
        verdicts: list[Verdict] = []

        # ── Where the address is, and whose it is ─────────
        verdicts.append(
            Verdict(
                severity="info",
                # GeoLite2 is reliable at country level and frequently wrong at
                # city level, so the *more specific* claim is the less confident
                # one. Anycast makes any single location partly fictional.
                confidence=0.75 if entry.get("city") else 0.9,
                discriminator=f"geo-{ip}",
                title=f"Host geo: {host_label} -> {location} ({org})",
                description=(
                    f"Geolocation and ASN data for {', '.join(hostnames)} "
                    f"({ip}). Classification: {classification}."
                ),
                evidence=f"IP: {ip} | Location: {location} | {org} ({asn_str})",
                reasoning=(
                    f"GeoLite2 placed {ip} in {location}"
                    + (" at city granularity" if entry.get("city") else " at country granularity")
                ),
                signals={
                    "country_code": entry.get("country_code"),
                    "city": entry.get("city"),
                    "asn": asn,
                    "classification": classification,
                },
                evidence_ids=evidence_ids,
            )
        )

        # ── A consumer ISP serving a production host ──────
        if classification == "residential":
            provider = entry.get("provider", org)
            verdicts.append(
                Verdict(
                    severity="medium",
                    # The ASN match is exact; reading it as "someone's house" is
                    # not. Consumer ISPs sell business lines off the same ASN,
                    # and `RESIDENTIAL_ASNS` holds fifteen of them.
                    confidence=0.8,
                    discriminator=f"residential-{ip}",
                    title=f"Residential IP hosting service: {host_label}",
                    description=(
                        f"{host_label} ({ip}) belongs to a residential ISP ({provider}). "
                        f"This may indicate a developer's home machine, misconfigured "
                        f"tunnel, or compromised host."
                    ),
                    evidence=(
                        f"IP: {ip} | ISP: {provider} ({asn_str}) | Hosts: {', '.join(hostnames)}"
                    ),
                    reasoning=f"{asn_str} is a known consumer ISP ({provider})",
                    signals={"asn": asn, "provider": provider},
                    evidence_ids=evidence_ids,
                )
            )

        # ── An ASN in neither list ─────────────────────────
        elif classification == "other" and asn is not None:
            verdicts.append(
                Verdict(
                    severity="low",
                    # This judgement is the absence of a match against two
                    # hand-maintained lists of about forty ASNs between them.
                    # Most of the internet is "not in the list", so it is the
                    # weakest thing this check says.
                    confidence=0.5,
                    discriminator=f"other-hosting-{ip}",
                    title=f"Non-standard hosting: {host_label}",
                    description=(
                        f"{host_label} ({ip}) is hosted on a network not in the "
                        f"known hosting provider list ({org}, {asn_str}). "
                        f"May warrant investigation."
                    ),
                    evidence=f"IP: {ip} | Org: {org} ({asn_str})",
                    reasoning=f"{asn_str} is in neither the hosting nor the residential list",
                    signals={"asn": asn, "org": org},
                    evidence_ids=evidence_ids,
                )
            )

        return verdicts


def _entry_from(exchange: Exchange | None) -> dict[str, Any] | None:
    """The GeoIP answer one recorded lookup came back with."""
    if exchange is None or exchange.error is not None or not exchange.response_body:
        return None
    try:
        entry = json.loads(exchange.response_body)
    except (ValueError, TypeError):
        logger.debug("Could not read GeoIP entry from exchange %s", exchange.id)
        return None
    return entry if isinstance(entry, dict) else None
