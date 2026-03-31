"""
Tests for Phase 6a-1 critical web finding checks.

Covers:
- WebDAVCheck (intrusive, gated)
- VCSExposureCheck
- ConfigExposureCheck
- DirectoryListingCheck
- DefaultCredsCheck (intrusive, gated)
- DebugEndpointCheck

All HTTP calls are mocked to avoid actual network traffic.
"""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.webdav import WebDAVCheck
from app.checks.web.vcs_exposure import VCSExposureCheck
from app.checks.web.config_exposure import ConfigExposureCheck
from app.checks.web.directory_listing import DirectoryListingCheck
from app.checks.web.default_creds import DefaultCredsCheck
from app.checks.web.debug_endpoints import DebugEndpointCheck
from app.lib.http import HttpResponse


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def service():
    return Service(url="http://target.com:80", host="target.com", port=80, scheme="http", service_type="http")


def resp(status_code=200, body="", headers=None, error=None):
    return HttpResponse(url="http://target.com:80", status_code=status_code, headers=headers or {}, body=body, elapsed_ms=50.0, error=error)


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


# ═══════════════════════════════════════════════════════════════════════════════
# WebDAVCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestWebDAVCheck:
    def test_init(self):
        check = WebDAVCheck()
        assert check.name == "webdav_check"
        assert "http" in check.service_types

    @pytest.mark.asyncio
    async def test_skips_when_intrusive_disabled(self, service):
        check = WebDAVCheck()
        with patch.object(WebDAVCheck, '_is_intrusive_allowed', return_value=False):
            result = await check.check_service(service, {})
        assert len(result.findings) == 0
        assert result.outputs.get("webdav_skipped") is True

    @pytest.mark.asyncio
    async def test_detects_propfind(self, service):
        check = WebDAVCheck()
        responses = {
            ("PROPFIND", "target.com"): resp(207, body="<multistatus>"),
            ("PUT", "chainsmith-webdav-test"): resp(403),
            ("MKCOL", "chainsmith-webdav-test"): resp(403),
        }
        with patch.object(WebDAVCheck, '_is_intrusive_allowed', return_value=True), \
             patch("app.checks.web.webdav.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, {})
        assert any("PROPFIND" in f.title for f in result.findings)
        assert any(f.severity == "high" for f in result.findings)

    @pytest.mark.asyncio
    async def test_detects_put_write(self, service):
        check = WebDAVCheck()
        responses = {
            ("PROPFIND", "target.com"): resp(403),
            ("PUT", "chainsmith-webdav-test"): resp(201),
            ("DELETE", "chainsmith-webdav-test"): resp(204),
            ("MKCOL", "chainsmith-webdav-test"): resp(403),
        }
        with patch.object(WebDAVCheck, '_is_intrusive_allowed', return_value=True), \
             patch("app.checks.web.webdav.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, {})
        critical = [f for f in result.findings if f.severity == "critical"]
        assert len(critical) >= 1
        assert any("PUT" in f.title for f in critical)

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, service):
        check = WebDAVCheck()
        responses = {
            ("PROPFIND", "target.com"): resp(401),
            ("PUT", "chainsmith-webdav-test"): resp(401),
            ("MKCOL", "chainsmith-webdav-test"): resp(401),
        }
        with patch.object(WebDAVCheck, '_is_intrusive_allowed', return_value=True), \
             patch("app.checks.web.webdav.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, {})
        medium = [f for f in result.findings if f.severity == "medium"]
        assert len(medium) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# VCSExposureCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestVCSExposureCheck:
    def test_init(self):
        check = VCSExposureCheck()
        assert check.name == "vcs_exposure"

    @pytest.mark.asyncio
    async def test_detects_git_exposure(self, service):
        check = VCSExposureCheck()
        responses = {
            ("GET", ".git/config"): resp(200, body="[core]\n\trepositoryformatversion = 0"),
            ("GET", ".git/COMMIT_EDITMSG"): resp(200, body="Initial commit"),
            ("GET", ".git/refs/heads/main"): resp(200, body="abc123"),
            ("GET", ".git/logs/HEAD"): resp(200, body="log data"),
            ("GET", ".gitignore"): resp(200, body=".env"),
            ("GET", ".svn/entries"): resp(404),
            ("GET", ".hg/store"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.git/config", "/.git/HEAD"]}}

        with patch("app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        assert len(result.findings) >= 1
        git_finding = result.findings[0]
        assert git_finding.severity in ("critical", "high")
        assert "Git" in git_finding.title or "git" in git_finding.title.lower()

    @pytest.mark.asyncio
    async def test_detects_git_credentials(self, service):
        check = VCSExposureCheck()
        responses = {
            ("GET", ".git/config"): resp(200, body='[remote "origin"]\n\turl = https://user:ghp_secret123@github.com/org/repo'),
            ("GET", ".git/COMMIT_EDITMSG"): resp(404),
            ("GET", ".git/refs"): resp(404),
            ("GET", ".git/logs"): resp(404),
            ("GET", ".gitignore"): resp(404),
            ("GET", ".svn"): resp(404),
            ("GET", ".hg"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.git/config"]}}

        with patch("app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        cred_findings = [f for f in result.findings if "credential" in f.title.lower()]
        assert len(cred_findings) >= 1
        assert cred_findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_detects_svn(self, service):
        check = VCSExposureCheck()
        responses = {
            ("GET", ".svn/entries"): resp(200, body="12\ndir\n"),
            ("GET", ".hg/store"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.svn/entries"]}}

        with patch("app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        assert any("SVN" in f.title for f in result.findings)

    @pytest.mark.asyncio
    async def test_no_findings_when_no_vcs(self, service):
        check = VCSExposureCheck()
        responses = {
            ("GET", ".svn"): resp(404),
            ("GET", ".hg"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": []}}

        with patch("app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# ConfigExposureCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfigExposureCheck:
    def test_init(self):
        check = ConfigExposureCheck()
        assert check.name == "config_exposure"

    @pytest.mark.asyncio
    async def test_detects_env_with_secrets(self, service):
        check = ConfigExposureCheck()
        env_content = "DB_HOST=localhost\nOPENAI_API_KEY=sk-1234567890abcdefghij\nDEBUG=true"
        responses = {
            ("GET", ".env"): resp(200, body=env_content),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.env"]}}

        with patch("app.checks.web.config_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        secrets = [f for f in result.findings if "secret" in f.title.lower() or "contains" in f.title.lower()]
        assert len(secrets) >= 1
        assert secrets[0].severity == "critical"
        # Verify actual secret values are NOT in evidence
        assert "sk-1234567890" not in secrets[0].evidence

    @pytest.mark.asyncio
    async def test_config_accessible_no_secrets(self, service):
        check = ConfigExposureCheck()
        responses = {
            ("GET", "config.json"): resp(200, body='{"debug": true, "port": 8080}'),
        }
        context = {f"paths_{service.port}": {"accessible": ["/config.json"]}}

        with patch("app.checks.web.config_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        assert len(result.findings) >= 1
        assert result.findings[0].severity == "high"
        assert "no secrets detected" in result.findings[0].description.lower() or "accessible" in result.findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_no_findings_when_no_config(self, service):
        check = ConfigExposureCheck()
        responses = {
            ("GET", ".env"): resp(404),
            ("GET", "config.json"): resp(404),
            ("GET", "config.yaml"): resp(404),
            ("GET", "settings.json"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": []}}

        with patch("app.checks.web.config_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_detects_aws_credentials(self, service):
        check = ConfigExposureCheck()
        env_content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        responses = {
            ("GET", ".env"): resp(200, body=env_content),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.env"]}}

        with patch("app.checks.web.config_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        assert any(f.severity == "critical" for f in result.findings)


# ═══════════════════════════════════════════════════════════════════════════════
# DirectoryListingCheck
# ═══════════════════════════════════════════════════════════════════════════════


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

        with patch("app.checks.web.directory_listing.AsyncHttpClient", return_value=mock_client_multi(responses, default=resp(404))):
            result = await check.check_service(service, {})

        assert len(result.findings) >= 1
        root_finding = [f for f in result.findings if "root" in f.title.lower()]
        assert len(root_finding) >= 1
        assert root_finding[0].severity == "high"

    @pytest.mark.asyncio
    async def test_detects_sensitive_files(self, service):
        check = DirectoryListingCheck()
        listing_body = '<h1>Index of /data/</h1><a href=".env">.env</a><a href="model.pt">model.pt</a>'
        responses = {
            ("GET", "/data/"): resp(200, body=listing_body),
        }

        with patch("app.checks.web.directory_listing.AsyncHttpClient", return_value=mock_client_multi(responses, default=resp(404))):
            result = await check.check_service(service, {})

        sensitive = [f for f in result.findings if "sensitive" in f.title.lower()]
        assert len(sensitive) >= 1

    @pytest.mark.asyncio
    async def test_no_listing_no_findings(self, service):
        check = DirectoryListingCheck()
        with patch("app.checks.web.directory_listing.AsyncHttpClient", return_value=mock_client_multi(default=resp(200, body="<html>Normal page</html>"))):
            result = await check.check_service(service, {})
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# DefaultCredsCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestDefaultCredsCheck:
    def test_init(self):
        check = DefaultCredsCheck()
        assert check.name == "default_creds"

    @pytest.mark.asyncio
    async def test_skips_when_intrusive_disabled(self, service):
        check = DefaultCredsCheck()
        with patch.object(DefaultCredsCheck, '_is_intrusive_allowed', return_value=False):
            result = await check.check_service(service, {})
        assert len(result.findings) == 0
        assert result.outputs.get("default_creds_skipped") is True

    @pytest.mark.asyncio
    async def test_detects_no_auth_admin(self, service):
        check = DefaultCredsCheck()
        admin_body = '<html><h1>Dashboard</h1><p>Welcome to the admin panel</p><a href="/users">Manage Users</a></html>'
        responses = {
            ("GET", "/admin"): resp(200, body=admin_body),
        }
        context = {f"paths_{service.port}": {"accessible": ["/admin"]}}

        with patch.object(DefaultCredsCheck, '_is_intrusive_allowed', return_value=True), \
             patch("app.checks.web.default_creds.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        no_auth = [f for f in result.findings if "no authentication" in f.title.lower()]
        assert len(no_auth) >= 1
        assert no_auth[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_detects_login_form_creds_rejected(self, service):
        check = DefaultCredsCheck()
        login_body = '<form action="/admin" method="POST"><input type="text" name="username"><input type="password" name="password"></form>'
        fail_body = '<p>Invalid credentials. Please try again.</p>'
        responses = {
            ("GET", "/admin"): resp(200, body=login_body),
            ("POST", "/admin"): resp(200, body=fail_body),
        }
        context = {f"paths_{service.port}": {"accessible": ["/admin"]}}

        with patch.object(DefaultCredsCheck, '_is_intrusive_allowed', return_value=True), \
             patch("app.checks.web.default_creds.AsyncHttpClient", return_value=mock_client_multi(responses)):
            result = await check.check_service(service, context)

        login_form = [f for f in result.findings if "Login form" in f.title]
        assert len(login_form) >= 1
        assert login_form[0].severity == "high"

    @pytest.mark.asyncio
    async def test_no_admin_paths_no_findings(self, service):
        check = DefaultCredsCheck()
        context = {f"paths_{service.port}": {"accessible": ["/api", "/health"]}}

        with patch.object(DefaultCredsCheck, '_is_intrusive_allowed', return_value=True):
            result = await check.check_service(service, context)

        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# DebugEndpointCheck
# ═══════════════════════════════════════════════════════════════════════════════


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

        with patch("app.checks.web.debug_endpoints.AsyncHttpClient", return_value=mock_client_multi(responses, default=resp(404))):
            result = await check.check_service(service, {})

        werkzeug = [f for f in result.findings if "Werkzeug" in f.title or "werkzeug" in f.title]
        assert len(werkzeug) >= 1
        assert werkzeug[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_detects_django_debug(self, service):
        check = DebugEndpointCheck()
        django_body = "You're seeing this error because you have DEBUG = True in your settings."
        responses = {
            ("GET", "/debug"): resp(200, body=django_body),
        }

        with patch("app.checks.web.debug_endpoints.AsyncHttpClient", return_value=mock_client_multi(responses, default=resp(404))):
            result = await check.check_service(service, {})

        django = [f for f in result.findings if "Django" in f.title or "django" in f.title.lower()]
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

        with patch("app.checks.web.debug_endpoints.AsyncHttpClient", return_value=mock_client_multi(responses, default=resp(404))):
            result = await check.check_service(service, {})

        actuator = [f for f in result.findings if "Actuator" in f.title or "actuator" in f.title.lower()]
        assert len(actuator) >= 1
        assert actuator[0].severity == "high"

    @pytest.mark.asyncio
    async def test_detects_sensitive_env_vars(self, service):
        check = DebugEndpointCheck()
        env_body = 'DATABASE_URL=postgres://user:pass@db:5432/app\nSECRET_KEY=supersecret123'
        responses = {
            ("GET", "/actuator/env"): resp(200, body=env_body),
        }

        with patch("app.checks.web.debug_endpoints.AsyncHttpClient", return_value=mock_client_multi(responses, default=resp(404))):
            result = await check.check_service(service, {})

        sensitive = [f for f in result.findings if "sensitive" in f.title.lower() or "leaks" in f.title.lower()]
        assert len(sensitive) >= 1

    @pytest.mark.asyncio
    async def test_no_debug_endpoints_no_findings(self, service):
        check = DebugEndpointCheck()
        with patch("app.checks.web.debug_endpoints.AsyncHttpClient", return_value=mock_client_multi(default=resp(404))):
            result = await check.check_service(service, {})
        assert len(result.findings) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Cross-cutting: Check Registration
# ═══════════════════════════════════════════════════════════════════════════════


class TestCheckRegistration:
    def test_all_checks_registered(self):
        from app.check_resolver import get_real_checks, infer_suite
        checks = get_real_checks()
        web_checks = [c for c in checks if infer_suite(c.name) == "web"]
        web_names = {c.name for c in web_checks}

        expected = {"webdav_check", "vcs_exposure", "config_exposure",
                    "directory_listing", "default_creds", "debug_endpoints"}
        assert expected.issubset(web_names), f"Missing: {expected - web_names}"

    def test_all_checks_importable(self):
        from app.checks.web import (
            WebDAVCheck, VCSExposureCheck, ConfigExposureCheck,
            DirectoryListingCheck, DefaultCredsCheck, DebugEndpointCheck,
        )
        for cls in [WebDAVCheck, VCSExposureCheck, ConfigExposureCheck,
                     DirectoryListingCheck, DefaultCredsCheck, DebugEndpointCheck]:
            instance = cls()
            assert instance.name
            assert instance.description
            assert len(instance.service_types) > 0
