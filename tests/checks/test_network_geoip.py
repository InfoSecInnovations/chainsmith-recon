"""Tests for GeoIpCheck -- GeoIP classification and observations."""

from unittest.mock import MagicMock, patch

import pytest

from app.checks.network.geoip import HOSTING_ASNS, RESIDENTIAL_ASNS, GeoIpCheck

# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _make_city_response(
    country="United States",
    iso_code="US",
    region="Virginia",
    city="Ashburn",
    lat=39.0438,
    lon=-77.4874,
):
    """Build a mock geoip2 city response."""
    resp = MagicMock()
    resp.country.name = country
    resp.country.iso_code = iso_code
    resp.subdivisions.most_specific.name = region
    resp.subdivisions.__bool__ = lambda self: True
    resp.city.name = city
    resp.location.latitude = lat
    resp.location.longitude = lon
    return resp


def _make_asn_response(asn_number, org_name):
    """Build a mock geoip2 ASN response."""
    resp = MagicMock()
    resp.autonomous_system_number = asn_number
    resp.autonomous_system_organization = org_name
    return resp


def _setup_readers(mock_reader_cls, city_resp, asn_resp, city_available=True, asn_available=True):
    """Wire a patched geoip2.database.Reader to return pre-built city/asn readers.

    Returns (city_reader, asn_reader) so tests can make per-IP assertions on
    the reader objects if needed.
    """
    city_reader = MagicMock()
    asn_reader = MagicMock()

    if city_resp is not None:
        city_reader.city.return_value = city_resp
    if asn_resp is not None:
        asn_reader.asn.return_value = asn_resp

    if city_available and asn_available:
        mock_reader_cls.side_effect = [city_reader, asn_reader]
    elif asn_available:
        mock_reader_cls.return_value = asn_reader
    elif city_available:
        mock_reader_cls.return_value = city_reader

    return city_reader, asn_reader


def _find_db_stub(filename):
    """Stub for _find_db_file that returns a fake path for any filename."""
    return f"/fake/{filename}"


def _find_db_asn_only(filename):
    """Stub for _find_db_file that only finds the ASN database."""
    return f"/fake/{filename}" if "ASN" in filename else None


# ---------------------------------------------------------------------------
# Init / metadata
# ---------------------------------------------------------------------------


class TestGeoIpCheckInit:
    """Tests for GeoIpCheck initialization."""

    def test_metadata(self):
        check = GeoIpCheck()
        assert check.name == "geoip"
        assert "geoip_data" in check.produces
        assert len(check.conditions) == 1  # depends on dns_records

    def test_hosting_asn_list_contains_major_providers(self):
        assert HOSTING_ASNS[16509] == "Amazon AWS"
        assert HOSTING_ASNS[13335] == "Cloudflare"
        assert HOSTING_ASNS[15169] == "Google Cloud"

    def test_residential_asn_list_contains_major_isps(self):
        assert RESIDENTIAL_ASNS[7922] == "Comcast"
        assert RESIDENTIAL_ASNS[7018] == "AT&T"


# ---------------------------------------------------------------------------
# Run – early exits
# ---------------------------------------------------------------------------


class TestGeoIpCheckEarlyExits:
    """Tests for error handling before lookups."""

    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_stub)
    async def test_no_dns_records(self, _mock_find):
        check = GeoIpCheck()
        result = await check.run({"dns_records": {}})
        assert any("dns_records" in e for e in result.errors)

    @patch("app.checks.network.geoip.HAS_GEOIP2", False)
    async def test_missing_geoip2_library(self):
        check = GeoIpCheck()
        result = await check.run({"dns_records": {"example.com": "1.2.3.4"}})
        assert result.success is False
        assert any("geoip2 not installed" in e for e in result.errors)

    @patch("app.checks.network.geoip._find_db_file", return_value=None)
    async def test_missing_db_files(self, _mock_find):
        check = GeoIpCheck()
        result = await check.run({"dns_records": {"example.com": "1.2.3.4"}})
        assert result.success is False
        assert any("GeoLite2" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Run – classification logic
# ---------------------------------------------------------------------------


class TestGeoIpClassification:
    """Tests proving real classification logic in _lookup_ip (HOSTING_ASNS / RESIDENTIAL_ASNS)."""

    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_stub)
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_hosting_asn_classified_as_hosting(self, MockReader, _mock_find):
        """ASN 16509 (AWS) maps to classification='hosting', provider='Amazon AWS'."""
        city_resp = _make_city_response()
        asn_resp = _make_asn_response(16509, "Amazon.com, Inc.")
        _setup_readers(MockReader, city_resp, asn_resp)

        check = GeoIpCheck()
        result = await check.run({"dns_records": {"api.example.com": "54.239.28.85"}})

        assert result.success is True
        data = result.outputs["geoip_data"]["54.239.28.85"]
        assert data["classification"] == "hosting"
        assert data["provider"] == "Amazon AWS"  # from HOSTING_ASNS lookup, not the mock org
        assert data["country_code"] == "US"
        assert data["asn"] == 16509
        assert data["org"] == "Amazon.com, Inc."

        # Hosting IPs produce exactly one info-level geo observation
        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.severity == "info"
        assert obs.title == "Host geo: api.example.com -> US, Virginia, Ashburn (Amazon.com, Inc.)"
        assert "54.239.28.85" in obs.evidence
        assert obs.check_name == "geoip"

    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_stub)
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_non_hosting_asn_not_classified_as_hosting(self, MockReader, _mock_find):
        """ASN 7922 (Comcast) must NOT be classified as 'hosting' -- proves the
        lookup table gate is real, not just round-tripping mock values."""
        city_resp = _make_city_response(region="Pennsylvania", city="Philadelphia")
        asn_resp = _make_asn_response(7922, "Comcast Cable Communications")
        _setup_readers(MockReader, city_resp, asn_resp)

        check = GeoIpCheck()
        result = await check.run({"dns_records": {"dev.example.com": "73.100.50.25"}})

        data = result.outputs["geoip_data"]["73.100.50.25"]
        assert data["classification"] != "hosting"
        assert data["classification"] == "residential"
        assert data["provider"] == "Comcast"  # from RESIDENTIAL_ASNS, not mock org

    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_stub)
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_unknown_asn_classified_as_other(self, MockReader, _mock_find):
        """ASN not in either lookup table gets classification='other'."""
        city_resp = _make_city_response(
            country="Germany",
            iso_code="DE",
            region="Bavaria",
            city="Munich",
            lat=48.1,
            lon=11.5,
        )
        asn_resp = _make_asn_response(99999, "Obscure Hosting GmbH")
        _setup_readers(MockReader, city_resp, asn_resp)

        check = GeoIpCheck()
        result = await check.run({"dns_records": {"ml.example.com": "185.1.2.3"}})

        data = result.outputs["geoip_data"]["185.1.2.3"]
        assert data["classification"] == "other"
        assert data["asn"] == 99999
        assert data["country_code"] == "DE"
        assert "provider" not in data  # 'other' classification does not set provider

    @pytest.mark.parametrize(
        "asn_number,expected_provider",
        [
            (13335, "Cloudflare"),
            (8075, "Microsoft Azure"),
            (14061, "DigitalOcean"),
        ],
    )
    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_stub)
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_multiple_hosting_asns(
        self,
        MockReader,
        _mock_find,
        asn_number,
        expected_provider,
    ):
        """Several hosting ASNs are classified correctly via HOSTING_ASNS table."""
        city_resp = _make_city_response()
        asn_resp = _make_asn_response(asn_number, "SomeOrg")
        _setup_readers(MockReader, city_resp, asn_resp)

        check = GeoIpCheck()
        result = await check.run({"dns_records": {"svc.example.com": "10.0.0.1"}})

        data = result.outputs["geoip_data"]["10.0.0.1"]
        assert data["classification"] == "hosting"
        assert data["provider"] == expected_provider


# ---------------------------------------------------------------------------
# Run – observation generation
# ---------------------------------------------------------------------------


class TestGeoIpObservations:
    """Tests for observation content, severity, and evidence fields."""

    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_stub)
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_residential_ip_generates_medium_observation(self, MockReader, _mock_find):
        """Residential ISP IP (Comcast, ASN 7922) emits a medium-severity observation."""
        city_resp = _make_city_response(
            region="Pennsylvania", city="Philadelphia", lat=39.95, lon=-75.16
        )
        asn_resp = _make_asn_response(7922, "Comcast Cable Communications")
        _setup_readers(MockReader, city_resp, asn_resp)

        check = GeoIpCheck()
        result = await check.run({"dns_records": {"dev.example.com": "73.100.50.25"}})

        # Should have info geo obs + medium residential obs
        assert len(result.observations) == 2
        info_obs = [o for o in result.observations if o.severity == "info"]
        med_obs = [o for o in result.observations if o.severity == "medium"]
        assert len(info_obs) == 1
        assert len(med_obs) == 1

        obs = med_obs[0]
        assert obs.title == "Residential IP hosting service: dev.example.com"
        assert obs.check_name == "geoip"
        assert "73.100.50.25" in obs.evidence
        assert "Comcast" in obs.evidence
        assert "AS7922" in obs.evidence
        assert (
            "residential ISP" in obs.description.lower() or "residential" in obs.description.lower()
        )

    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_stub)
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_unknown_asn_generates_low_observation(self, MockReader, _mock_find):
        """Non-standard hosting (ASN not in known lists) emits a low-severity observation."""
        city_resp = _make_city_response(
            country="Germany",
            iso_code="DE",
            region="Bavaria",
            city="Munich",
            lat=48.1,
            lon=11.5,
        )
        asn_resp = _make_asn_response(99999, "Obscure Hosting GmbH")
        _setup_readers(MockReader, city_resp, asn_resp)

        check = GeoIpCheck()
        result = await check.run({"dns_records": {"ml.example.com": "185.1.2.3"}})

        low_obs = [o for o in result.observations if o.severity == "low"]
        assert len(low_obs) == 1
        obs = low_obs[0]
        assert obs.title == "Non-standard hosting: ml.example.com"
        assert obs.check_name == "geoip"
        assert "185.1.2.3" in obs.evidence
        assert "AS99999" in obs.evidence
        assert "Obscure Hosting GmbH" in obs.evidence

    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_stub)
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_hosting_ip_no_medium_or_low_observations(self, MockReader, _mock_find):
        """A known hosting ASN should only produce an info observation -- no warnings."""
        city_resp = _make_city_response()
        asn_resp = _make_asn_response(16509, "Amazon.com, Inc.")
        _setup_readers(MockReader, city_resp, asn_resp)

        check = GeoIpCheck()
        result = await check.run({"dns_records": {"api.example.com": "54.239.28.85"}})

        severities = {o.severity for o in result.observations}
        assert severities == {"info"}, f"Expected only info observations, got {severities}"


# ---------------------------------------------------------------------------
# Run – deduplication & partial DB
# ---------------------------------------------------------------------------


class TestGeoIpEdgeCases:
    """Tests for deduplication, partial databases, etc."""

    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_stub)
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_multiple_hosts_same_ip_deduplicated(self, MockReader, _mock_find):
        """Multiple hostnames resolving to the same IP produce a single lookup."""
        city_resp = _make_city_response()
        asn_resp = _make_asn_response(16509, "Amazon.com, Inc.")
        _setup_readers(MockReader, city_resp, asn_resp)

        check = GeoIpCheck()
        result = await check.run(
            {
                "dns_records": {
                    "api.example.com": "54.1.2.3",
                    "www.example.com": "54.1.2.3",
                },
            }
        )

        assert result.targets_checked == 1
        assert "54.1.2.3" in result.outputs["geoip_data"]
        assert result.outputs["geoip_data"]["54.1.2.3"]["classification"] == "hosting"

    @patch("app.checks.network.geoip._find_db_file", side_effect=_find_db_asn_only)
    @patch("app.checks.network.geoip.geoip2.database.Reader")
    async def test_asn_only_db(self, MockReader, _mock_find):
        """Check works with only ASN database (no city DB)."""
        asn_resp = _make_asn_response(13335, "Cloudflare, Inc.")
        _setup_readers(MockReader, city_resp=None, asn_resp=asn_resp, city_available=False)

        check = GeoIpCheck()
        result = await check.run({"dns_records": {"cdn.example.com": "104.16.1.1"}})

        assert result.success is True
        data = result.outputs["geoip_data"]["104.16.1.1"]
        assert data["classification"] == "hosting"
        assert data["provider"] == "Cloudflare"
        assert data["country"] is None  # No city DB
        assert data["asn"] == 13335


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestGeoIpRegistration:
    """Verify GeoIP check is properly registered."""

    def test_geoip_in_resolver(self):
        from app.check_resolver import get_real_checks

        checks = get_real_checks()
        names = [c.name for c in checks]
        assert "geoip" in names
