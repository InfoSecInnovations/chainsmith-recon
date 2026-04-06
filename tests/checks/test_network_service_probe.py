"""Tests for ServiceProbeCheck: HTTP/HTTPS probing, service classification, and header analysis."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.network.service_probe import ServiceProbeCheck
from app.lib.http import HttpResponse


class TestServiceProbeCheckInit:
    """Tests for ServiceProbeCheck initialization."""

    def test_default_initialization(self):
        """Check initializes with defaults."""
        check = ServiceProbeCheck()

        assert check.name == "service_probe"
        assert len(check.conditions) == 1  # Requires services
        assert "services" in check.produces

    def test_metadata(self):
        """Check has educational metadata."""
        check = ServiceProbeCheck()

        assert len(check.references) > 0
        assert len(check.techniques) > 0
        assert "fingerprinting" in " ".join(check.techniques).lower()


class TestServiceProbeCheckService:
    """Tests for ServiceProbeCheck.check_service."""

    @pytest.fixture
    def check(self):
        """ServiceProbeCheck instance."""
        return ServiceProbeCheck()

    @pytest.fixture
    def sample_service(self):
        """Sample service to probe."""
        return Service(
            url="http://example.com:8080",
            host="example.com",
            port=8080,
            scheme="http",
            service_type="unknown",
        )

    def _make_response(
        self,
        status_code: int = 200,
        headers: dict = None,
        body: str = "",
    ) -> HttpResponse:
        """Create a mock HTTP response."""
        return HttpResponse(
            url="http://example.com:8080",
            status_code=status_code,
            headers=headers or {},
            body=body,
            elapsed_ms=50.0,
        )

    async def test_check_service_classifies_html(self, check, sample_service):
        """HTML content type is classified correctly."""
        response = self._make_response(
            headers={"content-type": "text/html; charset=utf-8"},
            body="<html><body>Test</body></html>",
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        assert result.success is True
        assert len(result.services) == 1
        assert result.services[0].service_type == "html"

    async def test_check_service_classifies_api(self, check, sample_service):
        """JSON content type is classified as API."""
        response = self._make_response(
            headers={"content-type": "application/json"},
            body='{"status": "ok"}',
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "api"

    async def test_check_service_classifies_ai_by_header(self, check, sample_service):
        """AI headers trigger AI classification."""
        response = self._make_response(
            headers={
                "content-type": "application/json",
                "x-model-version": "gpt-4",
            },
            body='{"response": "hello"}',
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "ai"

    async def test_check_service_classifies_ai_by_powered_by(self, check, sample_service):
        """X-Powered-By with AI tech triggers AI classification."""
        response = self._make_response(
            headers={
                "content-type": "application/json",
                "x-powered-by": "vLLM/0.4.1",
            },
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "ai"

    async def test_check_service_classifies_ai_by_body(self, check, sample_service):
        """AI indicators in body trigger AI classification."""
        response = self._make_response(
            headers={"content-type": "text/html"},
            body="<html>Welcome to our chatbot powered by LLM</html>",
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "ai"

    async def test_check_service_prefers_https(self, check, sample_service):
        """HTTPS is tried first."""
        response = self._make_response(
            headers={"content-type": "text/html"},
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            await check.check_service(sample_service, {})

        # First call should be HTTPS
        calls = mock_client.get.call_args_list
        assert "https://" in calls[0][0][0]

    async def test_check_service_falls_back_to_http(self, check, sample_service):
        """Falls back to HTTP if HTTPS fails."""
        http_response = self._make_response(
            headers={"content-type": "text/html"},
        )

        call_count = 0

        async def mock_get(url):
            nonlocal call_count
            call_count += 1
            if "https://" in url:
                raise Exception("SSL error")
            return http_response

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = mock_get
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        assert result.success is True
        assert result.services[0].scheme == "http"

    async def test_check_service_tcp_fallback(self, check, sample_service):
        """Falls back to TCP type if all HTTP fails."""

        async def mock_get(url):
            raise Exception("Connection refused")

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = mock_get
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "tcp"


class TestServiceProbeCheckFindings:
    """Tests for ServiceProbeCheck finding generation."""

    @pytest.fixture
    def check(self):
        return ServiceProbeCheck()

    @pytest.fixture
    def sample_service(self):
        return Service(
            url="http://example.com:8080",
            host="example.com",
            port=8080,
        )

    def _make_response(self, headers: dict, body: str = "") -> HttpResponse:
        return HttpResponse(
            url="http://example.com:8080",
            status_code=200,
            headers=headers,
            body=body,
            elapsed_ms=50.0,
        )

    async def test_finding_server_version_disclosure(self, check, sample_service):
        """Server header with version creates finding."""
        response = self._make_response(
            headers={"Server": "nginx/1.21.0", "content-type": "text/html"},
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        server_findings = [f for f in result.findings if "Server" in f.title]
        assert len(server_findings) == 1
        assert server_findings[0].severity == "low"

    async def test_finding_powered_by_disclosure(self, check, sample_service):
        """X-Powered-By creates finding."""
        response = self._make_response(
            headers={"X-Powered-By": "Express", "content-type": "text/html"},
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        tech_findings = [f for f in result.findings if "Technology" in f.title]
        assert len(tech_findings) == 1

    async def test_finding_ai_powered_by_higher_severity(self, check, sample_service):
        """AI tech in X-Powered-By gets higher severity."""
        response = self._make_response(
            headers={"X-Powered-By": "vLLM/0.4.1", "content-type": "text/html"},
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        tech_findings = [f for f in result.findings if "Technology" in f.title]
        assert len(tech_findings) == 1
        assert tech_findings[0].severity == "medium"

    async def test_finding_custom_header(self, check, sample_service):
        """Custom X- headers create findings."""
        response = self._make_response(
            headers={
                "X-Custom-Debug": "true",
                "content-type": "text/html",
            },
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        custom_findings = [f for f in result.findings if "Custom header" in f.title]
        assert len(custom_findings) == 1

    async def test_finding_sensitive_custom_header_higher_severity(self, check, sample_service):
        """Custom headers with sensitive names get higher severity."""
        response = self._make_response(
            headers={
                "X-Internal-Token": "abc123",
                "content-type": "text/html",
            },
        )

        with patch("app.checks.network.service_probe.AsyncHttpClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_client.get = AsyncMock(return_value=response)
            mock_client_cls.return_value = mock_client

            result = await check.check_service(sample_service, {})

        custom_findings = [f for f in result.findings if "Custom header" in f.title]
        assert len(custom_findings) == 1
        assert custom_findings[0].severity == "medium"


class TestServiceProbeClassifyService:
    """Tests for _classify_service method."""

    @pytest.fixture
    def check(self):
        return ServiceProbeCheck()

    def test_classify_html(self, check):
        """HTML content type classified as html."""
        result = check._classify_service(
            headers={},
            content_type="text/html",
            body="<html></html>",
        )
        assert result == "html"

    def test_classify_json_api(self, check):
        """JSON content type classified as api."""
        result = check._classify_service(
            headers={},
            content_type="application/json",
            body='{"key": "value"}',
        )
        assert result == "api"

    def test_classify_ai_header(self, check):
        """AI header classified as ai."""
        result = check._classify_service(
            headers={"X-LLM-Model": "gpt-4"},
            content_type="application/json",
            body="",
        )
        assert result == "ai"

    def test_classify_ai_powered_by(self, check):
        """AI in X-Powered-By classified as ai."""
        result = check._classify_service(
            headers={"X-Powered-By": "ollama"},
            content_type="application/json",
            body="",
        )
        assert result == "ai"

    def test_classify_ai_body_indicator(self, check):
        """AI indicators in body classified as ai."""
        result = check._classify_service(
            headers={},
            content_type="text/html",
            body="<html>Visit /v1/chat/completions for our API</html>",
        )
        assert result == "ai"

    def test_classify_default_http(self, check):
        """Unknown content classified as http."""
        result = check._classify_service(
            headers={},
            content_type="text/plain",
            body="plain text",
        )
        assert result == "http"
