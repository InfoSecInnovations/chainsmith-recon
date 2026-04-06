"""Tests for GeoIpCheck — GeoIP classification and findings."""

from unittest.mock import MagicMock, patch

import pytest

from app.checks.network.geoip import HOSTING_ASNS, RESIDENTIAL_ASNS, GeoIpCheck


class TestGeoIpCheckInit:
    """Tests for GeoIpCheck initialization."""

    def test_metadata(self):
        check = GeoIpCheck()
        assert check.name == "geoip"
        assert "geoip_data" in check.produces
        assert len(check.conditions) == 1  # depends on dns_records

    def test_hosting_asn_list(self):
        """Hosting ASN list contains major providers."""
        assert 16509 in HOSTING_ASNS  # AWS
        assert 13335 in HOSTING_ASNS  # Cloudflare
        assert 15169 in HOSTING_ASNS  # Google Cloud

    def test_residential_asn_list(self):
        """Residential ASN list contains major ISPs."""
        assert 7922 in RESIDENTIAL_ASNS  # Comcast
        assert 7018 in RESIDENTIAL_ASNS  # AT&T


class TestGeoIpCheckRun:
    """Tests for GeoIpCheck run behavior."""

    @patch("app.checks.network.geoip._find_db_file")
    async def test_no_dns_records(self, mock_find):
        """Check returns early if no dns_records in context."""
        mock_find.side_effect = lambda f: f"/fake/{f}"
        check = GeoIpCheck()
        result = await check.run({"dns_records": {}})
        assert any("dns_records" in e for e in result.errors)

    @patch("app.checks.network.geoip.HAS_GEOIP2", False)
    async def test_missing_geoip2(self):
        """Check fails gracefully without geoip2."""
        check = GeoIpCheck()
        result = await check.run({"dns_records": {"example.com": "1.2.3.4"}})
        assert result.success is False
        assert any("geoip2" in e for e in result.errors)

    @patch("app.checks.network.geoip._find_db_file")
    async def test_missing_db_files(self, mock_find):
        """Check fails gracefully without database files."""
        mock_find.return_value = None
        check = GeoIpCheck()
        result = await check.run({"dns_records": {"example.com": "1.2.3.4"}})
        assert result.success is False
        assert any("GeoLite2" in e for e in result.errors)

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_hosting_ip_classification(self, MockReader, mock_find):
        """AWS IP is classified as hosting."""
        mock_find.side_effect = lambda f: f"/fake/{f}"

        city_reader = MagicMock()
        asn_reader = MagicMock()

        # City response
        city_resp = MagicMock()
        city_resp.country.name = "United States"
        city_resp.country.iso_code = "US"
        city_resp.subdivisions.most_specific.name = "Virginia"
        city_resp.subdivisions.__bool__ = lambda self: True
        city_resp.city.name = "Ashburn"
        city_resp.location.latitude = 39.0438
        city_resp.location.longitude = -77.4874
        city_reader.city.return_value = city_resp

        # ASN response — AWS
        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 16509
        asn_resp.autonomous_system_organization = "Amazon.com, Inc."
        asn_reader.asn.return_value = asn_resp

        MockReader.side_effect = [city_reader, asn_reader]

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {"api.example.com": "54.239.28.85"},
            }
        )

        assert result.success is True
        data = result.outputs["geoip_data"]["54.239.28.85"]
        assert data["classification"] == "hosting"
        assert data["provider"] == "Amazon AWS"
        assert data["country_code"] == "US"

        # Should have one info finding (geo) and no medium findings (not residential)
        severities = [f.severity for f in result.findings]
        assert "info" in severities
        assert "medium" not in severities

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_residential_ip_flagged(self, MockReader, mock_find):
        """Residential ISP IP generates a medium severity finding."""
        mock_find.side_effect = lambda f: f"/fake/{f}"

        city_reader = MagicMock()
        asn_reader = MagicMock()

        city_resp = MagicMock()
        city_resp.country.name = "United States"
        city_resp.country.iso_code = "US"
        city_resp.subdivisions.most_specific.name = "Pennsylvania"
        city_resp.subdivisions.__bool__ = lambda self: True
        city_resp.city.name = "Philadelphia"
        city_resp.location.latitude = 39.95
        city_resp.location.longitude = -75.16
        city_reader.city.return_value = city_resp

        # ASN response — Comcast (residential)
        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 7922
        asn_resp.autonomous_system_organization = "Comcast Cable Communications"
        asn_reader.asn.return_value = asn_resp

        MockReader.side_effect = [city_reader, asn_reader]

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {"dev.example.com": "73.100.50.25"},
            }
        )

        data = result.outputs["geoip_data"]["73.100.50.25"]
        assert data["classification"] == "residential"

        residential_findings = [f for f in result.findings if f.severity == "medium"]
        assert len(residential_findings) == 1
        assert "Residential IP" in residential_findings[0].title

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_unknown_asn_flagged_low(self, MockReader, mock_find):
        """Unknown ASN (not in hosting or residential list) generates low finding."""
        mock_find.side_effect = lambda f: f"/fake/{f}"

        city_reader = MagicMock()
        asn_reader = MagicMock()

        city_resp = MagicMock()
        city_resp.country.name = "Germany"
        city_resp.country.iso_code = "DE"
        city_resp.subdivisions.most_specific.name = "Bavaria"
        city_resp.subdivisions.__bool__ = lambda self: True
        city_resp.city.name = "Munich"
        city_resp.location.latitude = 48.1
        city_resp.location.longitude = 11.5
        city_reader.city.return_value = city_resp

        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 99999
        asn_resp.autonomous_system_organization = "Obscure Hosting GmbH"
        asn_reader.asn.return_value = asn_resp

        MockReader.side_effect = [city_reader, asn_reader]

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {"ml.example.com": "185.1.2.3"},
            }
        )

        data = result.outputs["geoip_data"]["185.1.2.3"]
        assert data["classification"] == "other"

        low_findings = [f for f in result.findings if f.severity == "low"]
        assert len(low_findings) == 1
        assert "Non-standard" in low_findings[0].title

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_multiple_hosts_same_ip(self, MockReader, mock_find):
        """Multiple hostnames resolving to the same IP are grouped."""
        mock_find.side_effect = lambda f: f"/fake/{f}"

        city_reader = MagicMock()
        asn_reader = MagicMock()

        city_resp = MagicMock()
        city_resp.country.name = "United States"
        city_resp.country.iso_code = "US"
        city_resp.subdivisions.most_specific.name = "Virginia"
        city_resp.subdivisions.__bool__ = lambda self: True
        city_resp.city.name = "Ashburn"
        city_resp.location.latitude = 39.0
        city_resp.location.longitude = -77.4
        city_reader.city.return_value = city_resp

        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 16509
        asn_resp.autonomous_system_organization = "Amazon.com, Inc."
        asn_reader.asn.return_value = asn_resp

        MockReader.side_effect = [city_reader, asn_reader]

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {
                    "api.example.com": "54.1.2.3",
                    "www.example.com": "54.1.2.3",
                },
            }
        )

        # Should only look up the IP once (deduplicated)
        assert result.targets_checked == 1
        assert "54.1.2.3" in result.outputs["geoip_data"]

    @patch("app.checks.network.geoip._find_db_file")
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_asn_only_db(self, MockReader, mock_find):
        """Check works with only ASN database (no city)."""
        mock_find.side_effect = lambda f: f"/fake/{f}" if "ASN" in f else None

        asn_reader = MagicMock()
        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 13335
        asn_resp.autonomous_system_organization = "Cloudflare, Inc."
        asn_reader.asn.return_value = asn_resp

        MockReader.return_value = asn_reader

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {"cdn.example.com": "104.16.1.1"},
            }
        )

        assert result.success is True
        data = result.outputs["geoip_data"]["104.16.1.1"]
        assert data["classification"] == "hosting"
        assert data["provider"] == "Cloudflare"
        assert data["country"] is None  # No city DB


class TestGeoIpRegistration:
    """Verify GeoIP check is properly registered."""

    def test_geoip_in_resolver(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "geoip" in names
