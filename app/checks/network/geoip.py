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
"""

import logging
import os
from pathlib import Path
from typing import Any

from app.checks.base import BaseCheck, CheckCondition, CheckResult
from app.lib.findings import build_finding

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

    name = "geoip"
    description = "GeoIP and ASN lookup for resolved IP addresses"

    conditions = [
        CheckCondition("dns_records", "truthy"),
    ]
    produces = ["geoip_data"]

    timeout_seconds = 30.0
    requests_per_second = 50.0  # Local DB lookups are fast

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

                self._generate_findings(
                    result, ip, hostnames, entry, context.get("base_domain", "")
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

    def _generate_findings(
        self,
        result: CheckResult,
        ip: str,
        hostnames: list[str],
        entry: dict,
        base_domain: str,
    ) -> None:
        """Generate findings based on GeoIP/ASN data for an IP."""
        host_label = hostnames[0] if hostnames else ip
        location_parts = [
            p for p in [entry.get("country_code"), entry.get("region"), entry.get("city")] if p
        ]
        location = ", ".join(location_parts) if location_parts else "unknown location"
        org = entry.get("org", "unknown")
        asn = entry.get("asn")
        asn_str = f"AS{asn}" if asn else "unknown ASN"
        classification = entry.get("classification", "unknown")

        # Base info finding for every IP
        evidence = f"IP: {ip} | Location: {location} | {org} ({asn_str})"
        result.findings.append(
            build_finding(
                check_name=self.name,
                title=f"Host geo: {host_label} -> {location} ({org})",
                description=(
                    f"Geolocation and ASN data for {', '.join(hostnames)} "
                    f"({ip}). Classification: {classification}."
                ),
                severity="info",
                evidence=evidence,
                host=host_label,
                discriminator=f"geo-{ip}",
            )
        )

        # Residential IP hosting a service — notable finding
        if classification == "residential":
            provider = entry.get("provider", org)
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Residential IP hosting service: {host_label}",
                    description=(
                        f"{host_label} ({ip}) belongs to a residential ISP ({provider}). "
                        f"This may indicate a developer's home machine, misconfigured "
                        f"tunnel, or compromised host."
                    ),
                    severity="medium",
                    evidence=f"IP: {ip} | ISP: {provider} ({asn_str}) | Hosts: {', '.join(hostnames)}",
                    host=host_label,
                    discriminator=f"residential-{ip}",
                )
            )

        # Non-standard hosting (ASN exists but not in our known lists)
        elif classification == "other" and asn is not None:
            result.findings.append(
                build_finding(
                    check_name=self.name,
                    title=f"Non-standard hosting: {host_label}",
                    description=(
                        f"{host_label} ({ip}) is hosted on a network not in the "
                        f"known hosting provider list ({org}, {asn_str}). "
                        f"May warrant investigation."
                    ),
                    severity="low",
                    evidence=f"IP: {ip} | Org: {org} ({asn_str})",
                    host=host_label,
                    discriminator=f"other-hosting-{ip}",
                )
            )
