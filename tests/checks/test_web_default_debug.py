"""Tests for directory listing, default credentials, and debug endpoint checks."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.debug_endpoints import DebugEndpointCheck
from app.checks.web.default_creds import DefaultCredsCheck
from app.checks.web.directory_listing import DirectoryListingCheck
from app.lib.http import HttpResponse


@pytest.fixture
def service():
    return Service(
        url="http://target.com:80", host="target.com", port=80, scheme="http", service_type="http"
    )


def resp(status_code=200, body="", headers=None, error=None):
    return HttpResponse(
        url="http://target.com:80",
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


def mock_client_multi(response_map=None, default=None):
    """Mock client that returns different responses based on URL/method.

    response_map: dict mapping (method, url_substring) -> HttpResponse
    default: fallback response
    """
    if default is None:
        default = resp(404)

    mock = AsyncMock()
    mock.__aenter__ = AsyncMock(return_value=mock)
    mock.__aexit__ = AsyncMock()

    def _lookup(method, url):
        if response_map:
            for (m, pattern), response in response_map.items():
                if m == method and pattern in url:
                    return response
        return default

    async def dispatch_get(url, **kwargs):
        return _lookup("GET", url)

    async def dispatch_post(url, **kwargs):
        return _lookup("POST", url)

    async def dispatch_request(method, url, **kwargs):
        return _lookup(method, url)

    mock.get = AsyncMock(side_effect=dispatch_get)
    mock.post = AsyncMock(side_effect=dispatch_post)
    mock.head = AsyncMock(side_effect=lambda url, **kw: _lookup("HEAD", url))
    mock._request = AsyncMock(side_effect=dispatch_request)

    return mock


class TestDirectoryListingCheck:
    def test_init(self):
        check = DirectoryListingCheck()
        assert check.name == "directory_listing"

    @pytest.mark.asyncio
    async def test_detects_apache_listing(self, service):
        check = DirectoryListingCheck()
        listing_body = '<html><head><title>Index of /</title></head><body><h1>Index of /</h1><a href="app.py">app.py</a></body></html>'
        responses = {
            ("GET", "target.com:80/"): resp(200, body=listing_body),
        }

        with patch(
            "app.checks.web.directory_listing.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        assert len(result.observations) >= 1
        root_observation = [f for f in result.observations if "root" in f.title.lower()]
        assert len(root_observation) >= 1
        assert root_observation[0].severity == "high"

    @pytest.mark.asyncio
    async def test_detects_sensitive_files(self, service):
        check = DirectoryListingCheck()
        listing_body = (
            '<h1>Index of /data/</h1><a href=".env">.env</a><a href="model.pt">model.pt</a>'
        )
        responses = {
            ("GET", "/data/"): resp(200, body=listing_body),
        }

        with patch(
            "app.checks.web.directory_listing.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        sensitive = [f for f in result.observations if "sensitive" in f.title.lower()]
        assert len(sensitive) >= 1

    @pytest.mark.asyncio
    async def test_no_listing_no_observations(self, service):
        check = DirectoryListingCheck()
        with patch(
            "app.checks.web.directory_listing.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, body="<html>Normal page</html>")),
        ):
            result = await check.check_service(service, {})
        assert len(result.observations) == 0


class TestDefaultCredsCheck:
    def test_init(self):
        check = DefaultCredsCheck()
        assert check.name == "default_creds"

    @pytest.mark.asyncio
    async def test_skips_when_intrusive_disabled(self, service):
        check = DefaultCredsCheck()
        with patch.object(DefaultCredsCheck, "_is_intrusive_allowed", return_value=False):
            result = await check.check_service(service, {})
        assert len(result.observations) == 0
        assert result.outputs.get("default_creds_skipped") is True

    @pytest.mark.asyncio
    async def test_detects_no_auth_admin(self, service):
        check = DefaultCredsCheck()
        admin_body = '<html><h1>Dashboard</h1><p>Welcome to the admin panel</p><a href="/users">Manage Users</a></html>'
        responses = {
            ("GET", "/admin"): resp(200, body=admin_body),
        }
        context = {f"paths_{service.port}": {"accessible": ["/admin"]}}

        with (
            patch.object(DefaultCredsCheck, "_is_intrusive_allowed", return_value=True),
            patch(
                "app.checks.web.default_creds.AsyncHttpClient",
                return_value=mock_client_multi(responses),
            ),
        ):
            result = await check.check_service(service, context)

        no_auth = [f for f in result.observations if "no authentication" in f.title.lower()]
        assert len(no_auth) >= 1
        assert no_auth[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_detects_login_form_creds_rejected(self, service):
        check = DefaultCredsCheck()
        login_body = '<form action="/admin" method="POST"><input type="text" name="username"><input type="password" name="password"></form>'
        fail_body = "<p>Invalid credentials. Please try again.</p>"
        responses = {
            ("GET", "/admin"): resp(200, body=login_body),
            ("POST", "/admin"): resp(200, body=fail_body),
        }
        context = {f"paths_{service.port}": {"accessible": ["/admin"]}}

        with (
            patch.object(DefaultCredsCheck, "_is_intrusive_allowed", return_value=True),
            patch(
                "app.checks.web.default_creds.AsyncHttpClient",
                return_value=mock_client_multi(responses),
            ),
        ):
            result = await check.check_service(service, context)

        login_form = [f for f in result.observations if "Login form" in f.title]
        assert len(login_form) >= 1
        assert login_form[0].severity == "high"

    @pytest.mark.asyncio
    async def test_no_admin_paths_no_observations(self, service):
        check = DefaultCredsCheck()
        context = {f"paths_{service.port}": {"accessible": ["/api", "/health"]}}

        with patch.object(DefaultCredsCheck, "_is_intrusive_allowed", return_value=True):
            result = await check.check_service(service, context)

        assert len(result.observations) == 0


class TestDebugEndpointCheck:
    def test_init(self):
        check = DebugEndpointCheck()
        assert check.name == "debug_endpoints"

    @pytest.mark.asyncio
    async def test_detects_werkzeug_debugger(self, service):
        check = DebugEndpointCheck()
        werkzeug_body = '<div class="debugger">The Werkzeug Debugger caught an exception</div>'
        responses = {
            ("GET", "/__debug__/"): resp(200, body=werkzeug_body),
        }

        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        werkzeug = [f for f in result.observations if "Werkzeug" in f.title or "werkzeug" in f.title]
        assert len(werkzeug) >= 1
        assert werkzeug[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_detects_django_debug(self, service):
        check = DebugEndpointCheck()
        django_body = "You're seeing this error because you have DEBUG = True in your settings."
        responses = {
            ("GET", "/debug"): resp(200, body=django_body),
        }

        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        django = [f for f in result.observations if "Django" in f.title or "django" in f.title.lower()]
        assert len(django) >= 1

    @pytest.mark.asyncio
    async def test_detects_actuator(self, service):
        check = DebugEndpointCheck()
        actuator_root = '{"_links":{"env":{"href":"/actuator/env"}}}'
        responses = {
            ("GET", "/actuator"): resp(200, body=actuator_root),
            ("GET", "/actuator/env"): resp(200, body='{"propertySources":[]}'),
            ("GET", "/actuator/configprops"): resp(200, body="{}"),
            ("GET", "/actuator/mappings"): resp(404),
            ("GET", "/actuator/beans"): resp(404),
            ("GET", "/actuator/info"): resp(404),
            ("GET", "/actuator/metrics"): resp(404),
            ("GET", "/actuator/loggers"): resp(404),
            ("GET", "/actuator/threaddump"): resp(404),
        }

        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        actuator = [
            f for f in result.observations if "Actuator" in f.title or "actuator" in f.title.lower()
        ]
        assert len(actuator) >= 1
        assert actuator[0].severity == "high"

    @pytest.mark.asyncio
    async def test_detects_sensitive_env_vars(self, service):
        check = DebugEndpointCheck()
        env_body = "DATABASE_URL=postgres://user:pass@db:5432/app\nSECRET_KEY=supersecret123"
        responses = {
            ("GET", "/actuator/env"): resp(200, body=env_body),
        }

        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        sensitive = [
            f
            for f in result.observations
            if "sensitive" in f.title.lower() or "leaks" in f.title.lower()
        ]
        assert len(sensitive) >= 1

    @pytest.mark.asyncio
    async def test_no_debug_endpoints_no_observations(self, service):
        check = DebugEndpointCheck()
        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(404)),
        ):
            result = await check.check_service(service, {})
        assert len(result.observations) == 0


class TestCheckRegistration:
    def test_all_checks_registered(self):
        from app.check_resolver import get_real_checks, infer_suite

        checks = get_real_checks()
        web_checks = [c for c in checks if infer_suite(c.name) == "web"]
        web_names = {c.name for c in web_checks}

        expected = {
            "webdav_check",
            "vcs_exposure",
            "config_exposure",
            "directory_listing",
            "default_creds",
            "debug_endpoints",
        }
        assert expected.issubset(web_names), f"Missing: {expected - web_names}"

    def test_all_checks_importable(self):
        from app.checks.web import (
            ConfigExposureCheck,
            DebugEndpointCheck,
            DefaultCredsCheck,
            DirectoryListingCheck,
            VCSExposureCheck,
            WebDAVCheck,
        )

        for cls in [
            WebDAVCheck,
            VCSExposureCheck,
            ConfigExposureCheck,
            DirectoryListingCheck,
            DefaultCredsCheck,
            DebugEndpointCheck,
        ]:
            instance = cls()
            assert instance.name
            assert instance.description
            assert len(instance.service_types) > 0
