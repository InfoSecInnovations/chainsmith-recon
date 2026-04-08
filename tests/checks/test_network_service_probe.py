"""Tests for ServiceProbeCheck: HTTP/HTTPS probing, service classification, and header analysis."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.network.service_probe import ServiceProbeCheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Helpers & Fixtures
# ═══════════════════════════════════════════════════════════════════════════════


def _make_response(
    status_code: int = 200,
    headers: dict = None,
    body: str = "",
    url: str = "http://example.com:8080",
) -> HttpResponse:
    """Create an HttpResponse for tests."""
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
    )


def _build_mock_client(get_side_effect=None, get_return_value=None):
    """Build an AsyncHttpClient mock usable as an async-context-manager.

    Accepts *either* ``get_side_effect`` (callable / exception) **or**
    ``get_return_value`` (a single HttpResponse).  Returns the mock client.
    """
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock()

    if get_side_effect is not None:
        mock_client.get = (
            get_side_effect
            if callable(get_side_effect) and not isinstance(get_side_effect, type)
            else AsyncMock(side_effect=get_side_effect)
        )
    elif get_return_value is not None:
        mock_client.get = AsyncMock(return_value=get_return_value)
    else:
        mock_client.get = AsyncMock(return_value=_make_response())

    return mock_client


@pytest.fixture
def check():
    """ServiceProbeCheck instance."""
    return ServiceProbeCheck()


@pytest.fixture
def sample_service():
    """Sample service to probe."""
    return Service(
        url="http://example.com:8080",
        host="example.com",
        port=8080,
        scheme="http",
        service_type="unknown",
    )


@pytest.fixture
def patched_client():
    """Yield a factory that builds a mock HTTP client and patches it in.

    Usage inside a test::

        async def test_something(check, sample_service, patched_client):
            response = _make_response(headers={"content-type": "text/html"})
            client = patched_client(get_return_value=response)
            result = await check.check_service(sample_service, {})

    The fixture returns the mock client so callers can inspect ``client.get.call_args_list``.
    The patch is automatically cleaned up when the test ends.
    """
    clients = []
    patchers = []

    def _factory(*, get_side_effect=None, get_return_value=None):
        client = _build_mock_client(
            get_side_effect=get_side_effect,
            get_return_value=get_return_value,
        )
        patcher = patch(
            "app.checks.network.service_probe.AsyncHttpClient",
            return_value=client,
        )
        patcher.start()
        clients.append(client)
        patchers.append(patcher)
        return client

    yield _factory

    for p in patchers:
        p.stop()


# ═══════════════════════════════════════════════════════════════════════════════
# Init
# ═══════════════════════════════════════════════════════════════════════════════


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


# ═══════════════════════════════════════════════════════════════════════════════
# check_service
# ═══════════════════════════════════════════════════════════════════════════════


class TestServiceProbeCheckService:
    """Tests for ServiceProbeCheck.check_service."""

    async def test_check_service_classifies_html(self, check, sample_service, patched_client):
        """HTML content type is classified correctly."""
        response = _make_response(
            headers={"content-type": "text/html; charset=utf-8"},
            body="<html><body>Test</body></html>",
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        assert result.success is True
        assert len(result.services) == 1
        assert result.services[0].service_type == "html"

    async def test_check_service_classifies_api(self, check, sample_service, patched_client):
        """JSON content type is classified as API."""
        response = _make_response(
            headers={"content-type": "application/json"},
            body='{"status": "ok"}',
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "api"

    async def test_check_service_classifies_ai_by_header(
        self, check, sample_service, patched_client
    ):
        """AI headers trigger AI classification."""
        response = _make_response(
            headers={
                "content-type": "application/json",
                "x-model-version": "gpt-4",
            },
            body='{"response": "hello"}',
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "ai"

    async def test_check_service_classifies_ai_by_powered_by(
        self, check, sample_service, patched_client
    ):
        """X-Powered-By with AI tech triggers AI classification."""
        response = _make_response(
            headers={
                "content-type": "application/json",
                "x-powered-by": "vLLM/0.4.1",
            },
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "ai"

    async def test_check_service_classifies_ai_by_body(self, check, sample_service, patched_client):
        """AI indicators in body trigger AI classification."""
        response = _make_response(
            headers={"content-type": "text/html"},
            body="<html>Welcome to our chatbot powered by LLM</html>",
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "ai"

    async def test_check_service_prefers_https(self, check, sample_service, patched_client):
        """HTTPS is tried first."""
        response = _make_response(
            headers={"content-type": "text/html"},
        )
        client = patched_client(get_return_value=response)
        await check.check_service(sample_service, {})

        # First call should be HTTPS
        calls = client.get.call_args_list
        assert "https://" in calls[0][0][0]

    async def test_check_service_falls_back_to_http(self, check, sample_service, patched_client):
        """Falls back to HTTP if HTTPS fails."""
        http_response = _make_response(
            headers={"content-type": "text/html"},
        )

        async def mock_get(url):
            if "https://" in url:
                raise Exception("SSL error")
            return http_response

        patched_client(get_side_effect=mock_get)
        result = await check.check_service(sample_service, {})

        assert result.success is True
        assert result.services[0].scheme == "http"

    async def test_check_service_tcp_fallback(self, check, sample_service, patched_client):
        """Falls back to TCP type if all HTTP fails."""

        async def mock_get(url):
            raise Exception("Connection refused")

        patched_client(get_side_effect=mock_get)
        result = await check.check_service(sample_service, {})

        assert result.services[0].service_type == "tcp"


# ═══════════════════════════════════════════════════════════════════════════════
# Observations
# ═══════════════════════════════════════════════════════════════════════════════


class TestServiceProbeCheckObservations:
    """Tests for ServiceProbeCheck observation generation."""

    async def test_observation_server_version_disclosure(
        self, check, sample_service, patched_client
    ):
        """Server header with version creates observation."""
        response = _make_response(
            headers={"Server": "nginx/1.21.0", "content-type": "text/html"},
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        server_observations = [f for f in result.observations if "Server" in f.title]
        assert len(server_observations) == 1
        assert server_observations[0].severity == "low"

    async def test_observation_powered_by_disclosure(self, check, sample_service, patched_client):
        """X-Powered-By creates observation."""
        response = _make_response(
            headers={"X-Powered-By": "Express", "content-type": "text/html"},
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        tech_observations = [f for f in result.observations if "Technology" in f.title]
        assert len(tech_observations) == 1

    async def test_observation_ai_powered_by_higher_severity(
        self, check, sample_service, patched_client
    ):
        """AI tech in X-Powered-By gets higher severity."""
        response = _make_response(
            headers={"X-Powered-By": "vLLM/0.4.1", "content-type": "text/html"},
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        tech_observations = [f for f in result.observations if "Technology" in f.title]
        assert len(tech_observations) == 1
        assert tech_observations[0].severity == "medium"

    async def test_observation_custom_header(self, check, sample_service, patched_client):
        """Custom X- headers create observations."""
        response = _make_response(
            headers={
                "X-Custom-Debug": "true",
                "content-type": "text/html",
            },
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        custom_observations = [f for f in result.observations if "Custom header" in f.title]
        assert len(custom_observations) == 1

    async def test_observation_sensitive_custom_header_higher_severity(
        self, check, sample_service, patched_client
    ):
        """Custom headers with sensitive names get higher severity."""
        response = _make_response(
            headers={
                "X-Internal-Token": "abc123",
                "content-type": "text/html",
            },
        )
        patched_client(get_return_value=response)
        result = await check.check_service(sample_service, {})

        custom_observations = [f for f in result.observations if "Custom header" in f.title]
        assert len(custom_observations) == 1
        assert custom_observations[0].severity == "medium"


# ═══════════════════════════════════════════════════════════════════════════════
# _classify_service (unit)
# ═══════════════════════════════════════════════════════════════════════════════


class TestServiceProbeClassifyService:
    """Tests for _classify_service method."""

    @pytest.fixture
    def classify_check(self):
        return ServiceProbeCheck()

    def test_classify_html(self, classify_check):
        """HTML content type classified as html."""
        result = classify_check._classify_service(
            headers={},
            content_type="text/html",
            body="<html></html>",
        )
        assert result == "html"

    def test_classify_json_api(self, classify_check):
        """JSON content type classified as api."""
        result = classify_check._classify_service(
            headers={},
            content_type="application/json",
            body='{"key": "value"}',
        )
        assert result == "api"

    def test_classify_ai_header(self, classify_check):
        """AI header classified as ai."""
        result = classify_check._classify_service(
            headers={"X-LLM-Model": "gpt-4"},
            content_type="application/json",
            body="",
        )
        assert result == "ai"

    def test_classify_ai_powered_by(self, classify_check):
        """AI in X-Powered-By classified as ai."""
        result = classify_check._classify_service(
            headers={"X-Powered-By": "ollama"},
            content_type="application/json",
            body="",
        )
        assert result == "ai"

    def test_classify_ai_body_indicator(self, classify_check):
        """AI indicators in body classified as ai."""
        result = classify_check._classify_service(
            headers={},
            content_type="text/html",
            body="<html>Visit /v1/chat/completions for our API</html>",
        )
        assert result == "ai"

    def test_classify_default_http(self, classify_check):
        """Unknown content classified as http."""
        result = classify_check._classify_service(
            headers={},
            content_type="text/plain",
            body="plain text",
        )
        assert result == "http"
