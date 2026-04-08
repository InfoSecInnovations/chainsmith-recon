"""Tests for BannerGrabCheck: non-HTTP banner grabbing, service identification, Redis auth probing."""

from unittest.mock import patch

import pytest

from app.checks.base import Service

# ═══════════════════════════════════════════════════════════════════
# Banner Grabbing Check Tests
# ═══════════════════════════════════════════════════════════════════

# Path to the synchronous TCP reader that all I/O flows through.
# We mock this instead of _grab_banner so the real banner-parsing,
# service identification, and auth-checking logic all execute.
_SYNC_TCP_READ = "app.checks.network.banner_grab.BannerGrabCheck._sync_tcp_read"


class TestBannerGrabCheckInit:
    """Test BannerGrabCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        assert check.name == "banner_grab"
        assert "banner" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "services"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        assert "banner_data" in check.produces

    def test_references(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        assert len(check.references) > 0
        assert any("CWE" in r for r in check.references)

    def test_banner_signatures_defined(self):
        from app.checks.network.banner_grab import BANNER_SIGNATURES

        service_names = [sig["name"] for sig in BANNER_SIGNATURES]
        assert "Redis" in service_names
        assert "PostgreSQL" in service_names
        assert "SSH" in service_names
        assert "MySQL" in service_names
        assert "Memcached" in service_names

    def test_http_ports_excluded(self):
        from app.checks.network.banner_grab import HTTP_PORTS

        assert 80 in HTTP_PORTS
        assert 443 in HTTP_PORTS
        assert 8080 in HTTP_PORTS
        # Database ports should NOT be in HTTP_PORTS
        assert 6379 not in HTTP_PORTS
        assert 5432 not in HTTP_PORTS


class TestBannerGrabCheckRun:
    """Test BannerGrabCheck runtime behavior with real _grab_banner execution.

    All tests in this class mock _sync_tcp_read (the raw socket layer) so
    the full _grab_banner -> _tcp_read -> _identify_service pipeline runs.
    """

    @pytest.mark.asyncio
    async def test_no_services_fails(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        result = await check.run({"services": []})
        assert result.success is False
        assert any("services" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_only_http_services_empty_output(self):
        """HTTP-only services on HTTP ports should produce empty output."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://web.example.com:80", host="web.example.com", port=80, scheme="http"
        )
        result = await check.run({"services": [svc]})
        assert result.success is True
        assert result.outputs["banner_data"] == {}

    @pytest.mark.asyncio
    async def test_ssh_banner_detection(self):
        """SSH-2.0 banner should be identified as SSH with version extracted."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://server.example.com:22",
            host="server.example.com",
            port=22,
            scheme="http",
            service_type="unknown",
        )

        ssh_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"

        # First call is passive read (no probe) -> returns the SSH banner.
        # SSH has no probe defined, so only one call is made.
        with patch(_SYNC_TCP_READ, return_value=ssh_banner):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert result.targets_checked == 1

        data = result.outputs["banner_data"]["server.example.com:22"]
        assert data["service"] == "SSH"
        assert data["version"] == "OpenSSH_8.9p1"
        assert "SSH-2.0-OpenSSH_8.9p1" in data["banner"]

        # Should have info observation for service detection
        info_obs = [o for o in result.observations if o.severity == "info"]
        assert len(info_obs) >= 1
        assert "SSH" in info_obs[0].title
        assert "detected" in info_obs[0].title
        assert "server.example.com:22" in info_obs[0].title
        assert "Banner:" in info_obs[0].evidence

        # Should have low-severity version disclosure
        version_obs = [o for o in result.observations if "version disclosed" in o.title.lower()]
        assert len(version_obs) == 1
        assert version_obs[0].severity == "low"
        assert "OpenSSH_8.9p1" in version_obs[0].evidence

    @pytest.mark.asyncio
    async def test_redis_banner_with_auth_required(self):
        """Redis on port 6379 responding to PING with +PONG, auth required."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://redis.example.com:6379",
            host="redis.example.com",
            port=6379,
            scheme="http",
            service_type="unknown",
        )

        def fake_tcp(host, port, probe):
            if probe is None:
                # Passive read: Redis doesn't speak first
                return None
            if probe == b"PING\r\n":
                return b"+PONG\r\n"
            if probe == b"INFO\r\n":
                # Auth check: Redis requires auth
                return b"-NOAUTH Authentication required.\r\n"
            return None

        with patch(_SYNC_TCP_READ, side_effect=fake_tcp):
            result = await check.run({"services": [svc]})

        assert result.success is True
        data = result.outputs["banner_data"]["redis.example.com:6379"]
        assert data["service"] == "Redis"
        assert data["auth_required"] is True

        # Info observation for Redis detection
        info_obs = [o for o in result.observations if o.severity == "info"]
        assert len(info_obs) >= 1
        assert "Redis" in info_obs[0].title
        assert "detected" in info_obs[0].title
        assert "redis.example.com:6379" in info_obs[0].title

        # No critical observation because auth IS required
        critical_obs = [o for o in result.observations if o.severity == "critical"]
        assert len(critical_obs) == 0

    @pytest.mark.asyncio
    async def test_redis_no_auth_critical_observation(self):
        """Redis without auth should produce a critical no-auth observation."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://redis.example.com:6379",
            host="redis.example.com",
            port=6379,
            scheme="http",
            service_type="unknown",
        )

        def fake_tcp(host, port, probe):
            if probe is None:
                return None
            if probe == b"PING\r\n":
                return b"+PONG\r\n"
            if probe == b"INFO\r\n":
                # No auth: returns server info freely
                return b"# Server\r\nredis_version:7.2.1\r\n"
            return None

        with patch(_SYNC_TCP_READ, side_effect=fake_tcp):
            result = await check.run({"services": [svc]})

        data = result.outputs["banner_data"]["redis.example.com:6379"]
        assert data["service"] == "Redis"
        assert data["auth_required"] is False

        # Critical no-auth observation
        noauth_obs = [o for o in result.observations if "without authentication" in o.title.lower()]
        assert len(noauth_obs) == 1
        assert noauth_obs[0].severity == "critical"
        assert "Redis" in noauth_obs[0].title
        assert "redis.example.com:6379" in noauth_obs[0].title
        assert "Auth required: False" in noauth_obs[0].evidence

    @pytest.mark.asyncio
    async def test_smtp_banner_detection(self):
        """SMTP 220 banner on port 25 should be identified as SMTP."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://mail.example.com:25",
            host="mail.example.com",
            port=25,
            scheme="http",
            service_type="unknown",
        )

        smtp_banner = b"220 mail.example.com ESMTP Postfix\r\n"

        with patch(_SYNC_TCP_READ, return_value=smtp_banner):
            result = await check.run({"services": [svc]})

        assert result.success is True
        data = result.outputs["banner_data"]["mail.example.com:25"]
        assert data["service"] == "SMTP"

        info_obs = [o for o in result.observations if o.severity == "info"]
        assert any("SMTP" in o.title and "detected" in o.title for o in info_obs)

    @pytest.mark.asyncio
    async def test_memcached_no_auth_high_observation(self):
        """Memcached returning VERSION without auth should produce high severity."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://cache.example.com:11211",
            host="cache.example.com",
            port=11211,
            scheme="http",
            service_type="unknown",
        )

        def fake_tcp(host, port, probe):
            if probe is None:
                # Memcached doesn't speak first
                return None
            if probe == b"version\r\n":
                return b"VERSION 1.6.21\r\n"
            return None

        with patch(_SYNC_TCP_READ, side_effect=fake_tcp):
            result = await check.run({"services": [svc]})

        data = result.outputs["banner_data"]["cache.example.com:11211"]
        assert data["service"] == "Memcached"
        assert data["version"] == "1.6.21"
        assert data["auth_required"] is False

        # High severity no-auth observation
        noauth_obs = [o for o in result.observations if "without authentication" in o.title.lower()]
        assert len(noauth_obs) == 1
        assert noauth_obs[0].severity == "high"
        assert "Memcached" in noauth_obs[0].title
        assert "cache.example.com:11211" in noauth_obs[0].title

        # Version disclosure observation
        version_obs = [o for o in result.observations if "version disclosed" in o.title.lower()]
        assert len(version_obs) == 1
        assert version_obs[0].severity == "low"
        assert "1.6.21" in version_obs[0].evidence

    @pytest.mark.asyncio
    async def test_unknown_service_banner_observation(self):
        """Unknown service with a banner should produce medium severity observation."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://mystery.example.com:9999",
            host="mystery.example.com",
            port=9999,
            scheme="http",
            service_type="unknown",
        )

        custom_banner = b"CUSTOM-PROTOCOL v3.1 READY\r\n"

        with patch(_SYNC_TCP_READ, return_value=custom_banner):
            result = await check.run({"services": [svc]})

        data = result.outputs["banner_data"]["mystery.example.com:9999"]
        assert data["service"] == "unknown"
        assert "CUSTOM-PROTOCOL" in data["banner"]

        unknown_obs = [o for o in result.observations if "unidentified" in o.title.lower()]
        assert len(unknown_obs) == 1
        assert unknown_obs[0].severity == "medium"
        assert "mystery.example.com:9999" in unknown_obs[0].title
        assert "CUSTOM-PROTOCOL" in unknown_obs[0].evidence

    @pytest.mark.asyncio
    async def test_no_banner_no_observations(self):
        """Service returning no banner bytes should produce zero observations."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://silent.example.com:9999",
            host="silent.example.com",
            port=9999,
            scheme="http",
            service_type="unknown",
        )

        # All TCP reads return None (no response / connection refused)
        with patch(_SYNC_TCP_READ, return_value=None):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert result.targets_checked == 1
        assert len(result.observations) == 0
        assert "silent.example.com:9999" not in result.outputs["banner_data"]

    @pytest.mark.asyncio
    async def test_connection_closes_immediately_no_observations(self):
        """A service that accepts the connection but sends zero bytes should
        produce no banner observations (negative test)."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://empty.example.com:4444",
            host="empty.example.com",
            port=4444,
            scheme="http",
            service_type="unknown",
        )

        # Connection succeeds but recv returns empty bytes (peer closed)
        with patch(_SYNC_TCP_READ, return_value=b""):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert result.targets_checked == 1
        assert len(result.observations) == 0
        assert "empty.example.com:4444" not in result.outputs["banner_data"]

    @pytest.mark.asyncio
    async def test_version_disclosure_observation(self):
        """Identified service with version should produce low severity version observation."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://db.example.com:5432",
            host="db.example.com",
            port=5432,
            scheme="http",
            service_type="unknown",
        )

        # PostgreSQL sends error bytes on connect containing SFATAL indicator
        pg_banner = b"E\x00\x00\x00\x8dSFATAL\x00"

        with patch(_SYNC_TCP_READ, return_value=pg_banner):
            result = await check.run({"services": [svc]})

        data = result.outputs["banner_data"]["db.example.com:5432"]
        assert data["service"] == "PostgreSQL"

        info_obs = [o for o in result.observations if o.severity == "info"]
        assert len(info_obs) >= 1
        assert "PostgreSQL" in info_obs[0].title
        assert "detected" in info_obs[0].title
        assert "db.example.com:5432" in info_obs[0].title

    @pytest.mark.asyncio
    async def test_deduplication_same_host_port(self):
        """Same host:port appearing twice should only be grabbed once."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc1 = Service(
            url="http://redis.example.com:6379",
            host="redis.example.com",
            port=6379,
            scheme="http",
            service_type="unknown",
        )
        svc2 = Service(
            url="http://redis.example.com:6379",
            host="redis.example.com",
            port=6379,
            scheme="http",
            service_type="unknown",
        )

        call_count = 0

        def counting_tcp_read(host, port, probe):
            nonlocal call_count
            call_count += 1
            if probe == b"PING\r\n":
                return b"+PONG\r\n"
            if probe == b"INFO\r\n":
                return b"-NOAUTH Authentication required.\r\n"
            return None

        with patch(_SYNC_TCP_READ, side_effect=counting_tcp_read):
            result = await check.run({"services": [svc1, svc2]})

        # Only one target should be checked (dedup)
        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_tcp_service_type_included(self):
        """Services with service_type='tcp' should be probed."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="tcp://custom.example.com:12345",
            host="custom.example.com",
            port=12345,
            scheme="tcp",
            service_type="tcp",
        )

        with patch(_SYNC_TCP_READ, return_value=None):
            result = await check.run({"services": [svc]})

        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_multiple_non_http_services(self):
        """Multiple non-HTTP services should each be probed independently."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc_ssh = Service(
            url="http://server.example.com:22",
            host="server.example.com",
            port=22,
            scheme="http",
            service_type="unknown",
        )
        svc_smtp = Service(
            url="http://mail.example.com:25",
            host="mail.example.com",
            port=25,
            scheme="http",
            service_type="unknown",
        )

        def fake_tcp(host, port, probe):
            if host == "server.example.com" and port == 22:
                return b"SSH-2.0-OpenSSH_8.9p1\r\n"
            if host == "mail.example.com" and port == 25:
                return b"220 mail.example.com ESMTP Postfix\r\n"
            return None

        with patch(_SYNC_TCP_READ, side_effect=fake_tcp):
            result = await check.run({"services": [svc_ssh, svc_smtp]})

        assert result.targets_checked == 2
        assert result.outputs["banner_data"]["server.example.com:22"]["service"] == "SSH"
        assert result.outputs["banner_data"]["mail.example.com:25"]["service"] == "SMTP"

    @pytest.mark.asyncio
    async def test_ftp_banner_detection(self):
        """FTP 220 banner on port 21 should be identified as FTP, not SMTP."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://files.example.com:21",
            host="files.example.com",
            port=21,
            scheme="http",
            service_type="unknown",
        )

        ftp_banner = b"220 Welcome to FTP server\r\n"

        with patch(_SYNC_TCP_READ, return_value=ftp_banner):
            result = await check.run({"services": [svc]})

        data = result.outputs["banner_data"]["files.example.com:21"]
        assert data["service"] == "FTP"

        info_obs = [o for o in result.observations if o.severity == "info"]
        assert any("FTP" in o.title and "detected" in o.title for o in info_obs)


class TestBannerGrabServiceIdentification:
    """Test _identify_service internal method."""

    def test_redis_identified_by_pong(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        result = check._identify_service("+PONG", b"+PONG", 6379)
        assert result["service"] == "Redis"

    def test_ssh_identified_and_version_extracted(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
        result = check._identify_service(banner, banner.encode(), 22)
        assert result["service"] == "SSH"
        assert result["version"] == "OpenSSH_8.9p1"

    def test_smtp_identified_by_220(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        banner = "220 mail.example.com ESMTP Postfix"
        result = check._identify_service(banner, banner.encode(), 25)
        assert result["service"] == "SMTP"

    def test_ftp_identified_by_220(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        banner = "220 Welcome to FTP server"
        result = check._identify_service(banner, banner.encode(), 21)
        assert result["service"] == "FTP"

    def test_memcached_version_extracted(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        banner = "VERSION 1.6.21"
        result = check._identify_service(banner, banner.encode(), 11211)
        assert result["service"] == "Memcached"
        assert result["version"] == "1.6.21"

    def test_unknown_service_fallback(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        banner = "CUSTOM-PROTOCOL READY"
        result = check._identify_service(banner, banner.encode(), 9999)
        assert result["service"] == "unknown"

    def test_postgresql_identified_by_indicator(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        raw = b"E\x00\x00\x00\x8dSFATAL\x00"
        banner = raw.decode("utf-8", errors="replace")
        result = check._identify_service(banner, raw, 5432)
        assert result["service"] == "PostgreSQL"

    def test_mysql_identified_by_banner(self):
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()
        raw = b"J\x00\x00\x008.0.35\x00mysql_native_password"
        banner = raw.decode("utf-8", errors="replace")
        result = check._identify_service(banner, raw, 3306)
        assert result["service"] == "MySQL"


class TestBannerGrabRedisAuth:
    """Test Redis auth checking."""

    @pytest.mark.asyncio
    async def test_redis_noauth_response(self):
        """Redis returning -NOAUTH means auth IS required."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        with patch.object(check, "_tcp_read", return_value=b"-NOAUTH Authentication required.\r\n"):
            auth_required = await check._check_redis_auth("redis.example.com", 6379)

        assert auth_required is True

    @pytest.mark.asyncio
    async def test_redis_info_response_no_auth(self):
        """Redis returning INFO data means auth is NOT required."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        info_response = b"# Server\r\nredis_version:7.2.1\r\n"
        with patch.object(check, "_tcp_read", return_value=info_response):
            auth_required = await check._check_redis_auth("redis.example.com", 6379)

        assert auth_required is False

    @pytest.mark.asyncio
    async def test_redis_no_response_assume_auth(self):
        """No response from Redis should assume auth required."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        with patch.object(check, "_tcp_read", return_value=None):
            auth_required = await check._check_redis_auth("redis.example.com", 6379)

        assert auth_required is True
