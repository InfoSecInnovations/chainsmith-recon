"""Tests for BannerGrabCheck: non-HTTP banner grabbing, service identification, Redis auth probing."""

from unittest.mock import patch

import pytest

from app.checks.base import Service

# ═══════════════════════════════════════════════════════════════════
# Banner Grabbing Check Tests
# ═══════════════════════════════════════════════════════════════════


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
    """Test BannerGrabCheck runtime behavior."""

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
    async def test_redis_banner_detection(self):
        """Redis service should be identified from +PONG banner."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://redis.example.com:6379",
            host="redis.example.com",
            port=6379,
            scheme="http",
            service_type="unknown",
        )

        banner_info = {
            "service": "Redis",
            "banner": "+PONG",
            "version": "7.2.1",
            "auth_required": True,
            "raw_bytes": "2b504f4e47",
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert "redis.example.com:6379" in result.outputs["banner_data"]
        data = result.outputs["banner_data"]["redis.example.com:6379"]
        assert data["service"] == "Redis"
        assert data["version"] == "7.2.1"
        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_redis_no_auth_critical_observation(self):
        """Redis without auth should produce critical severity observation."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://redis.example.com:6379",
            host="redis.example.com",
            port=6379,
            scheme="http",
            service_type="unknown",
        )

        banner_info = {
            "service": "Redis",
            "banner": "+PONG",
            "version": "7.2.1",
            "auth_required": False,
            "raw_bytes": "2b504f4e47",
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        noauth_observations = [
            f for f in result.observations if "without authentication" in f.title.lower()
        ]
        assert len(noauth_observations) == 1
        assert noauth_observations[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_redis_with_auth_no_critical(self):
        """Redis with auth should NOT produce critical observation."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://redis.example.com:6379",
            host="redis.example.com",
            port=6379,
            scheme="http",
            service_type="unknown",
        )

        banner_info = {
            "service": "Redis",
            "banner": "+PONG",
            "version": "7.2.1",
            "auth_required": True,
            "raw_bytes": "2b504f4e47",
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        noauth_observations = [
            f for f in result.observations if "without authentication" in f.title.lower()
        ]
        assert len(noauth_observations) == 0

    @pytest.mark.asyncio
    async def test_ssh_banner_detection(self):
        """SSH service should be identified from SSH-2.0 banner."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://server.example.com:22",
            host="server.example.com",
            port=22,
            scheme="http",
            service_type="unknown",
        )

        banner_info = {
            "service": "SSH",
            "banner": "SSH-2.0-OpenSSH_8.9p1",
            "version": "OpenSSH_8.9p1",
            "auth_required": None,
            "raw_bytes": None,
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        assert "server.example.com:22" in result.outputs["banner_data"]
        data = result.outputs["banner_data"]["server.example.com:22"]
        assert data["service"] == "SSH"

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

        banner_info = {
            "service": "PostgreSQL",
            "banner": "PostgreSQL 15.3",
            "version": "15.3",
            "auth_required": None,
            "raw_bytes": None,
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        version_observations = [f for f in result.observations if "version disclosed" in f.title.lower()]
        assert len(version_observations) == 1
        assert version_observations[0].severity == "low"

    @pytest.mark.asyncio
    async def test_unknown_service_banner_observation(self):
        """Unknown service with banner should produce medium severity observation."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://mystery.example.com:9999",
            host="mystery.example.com",
            port=9999,
            scheme="http",
            service_type="unknown",
        )

        banner_info = {
            "service": "unknown",
            "banner": "CUSTOM-PROTOCOL v3.1 READY",
            "version": None,
            "auth_required": None,
            "raw_bytes": None,
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        unknown_observations = [f for f in result.observations if "unidentified" in f.title.lower()]
        assert len(unknown_observations) == 1
        assert unknown_observations[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_no_banner_no_observations(self):
        """Service with no banner should produce no observations."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://silent.example.com:9999",
            host="silent.example.com",
            port=9999,
            scheme="http",
            service_type="unknown",
        )

        with patch.object(check, "_grab_banner", return_value=None):
            result = await check.run({"services": [svc]})

        assert result.success is True
        assert result.targets_checked == 1
        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_deduplication_same_host_port(self):
        """Same host:port should only be grabbed once."""
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

        async def counting_grab(host, port):
            nonlocal call_count
            call_count += 1
            return {
                "service": "Redis",
                "banner": "+PONG",
                "version": None,
                "auth_required": True,
                "raw_bytes": None,
            }

        with patch.object(check, "_grab_banner", side_effect=counting_grab):
            await check.run({"services": [svc1, svc2]})

        assert call_count == 1

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

        with patch.object(check, "_grab_banner", return_value=None):
            result = await check.run({"services": [svc]})

        # Should have attempted the grab
        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_memcached_no_auth_high_observation(self):
        """Memcached without auth should produce high severity observation."""
        from app.checks.network.banner_grab import BannerGrabCheck

        check = BannerGrabCheck()

        svc = Service(
            url="http://cache.example.com:11211",
            host="cache.example.com",
            port=11211,
            scheme="http",
            service_type="unknown",
        )

        banner_info = {
            "service": "Memcached",
            "banner": "VERSION 1.6.21",
            "version": "1.6.21",
            "auth_required": False,
            "raw_bytes": None,
        }

        with patch.object(check, "_grab_banner", return_value=banner_info):
            result = await check.run({"services": [svc]})

        noauth_observations = [
            f for f in result.observations if "without authentication" in f.title.lower()
        ]
        assert len(noauth_observations) == 1
        assert noauth_observations[0].severity == "high"

    @pytest.mark.asyncio
    async def test_multiple_non_http_services(self):
        """Multiple non-HTTP services should each be probed."""
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
            url="http://db.example.com:5432",
            host="db.example.com",
            port=5432,
            scheme="http",
            service_type="unknown",
        )

        async def mock_grab(host, port):
            if port == 6379:
                return {
                    "service": "Redis",
                    "banner": "+PONG",
                    "version": "7.0",
                    "auth_required": True,
                    "raw_bytes": None,
                }
            elif port == 5432:
                return {
                    "service": "PostgreSQL",
                    "banner": "PG 15",
                    "version": "15",
                    "auth_required": None,
                    "raw_bytes": None,
                }
            return None

        with patch.object(check, "_grab_banner", side_effect=mock_grab):
            result = await check.run({"services": [svc1, svc2]})

        assert result.targets_checked == 2
        assert "redis.example.com:6379" in result.outputs["banner_data"]
        assert "db.example.com:5432" in result.outputs["banner_data"]


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
