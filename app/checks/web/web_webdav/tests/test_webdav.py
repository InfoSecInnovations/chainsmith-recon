"""Tests for web_webdav."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_webdav import WebDAVCheck
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


async def probe_and_grade(check, service, context=None):
    """Run the probe, then the grading stage, and return the graded result.

    This check is split into probe + grade, so `check_service()`
    now returns candidates rather than observations. Tests assert on what an
    operator sees, which is what the grading stage produces — the same thing
    `CheckLauncher` calls immediately after `execute()`.
    """
    from app.grading import grade_result

    result = await check.check_service(service, context or {})
    return await grade_result(check, result, context or {})


def _mock_preferences(intrusive_web=False):
    """Return a mock get_preferences function with the given intrusive_web setting."""
    prefs = MagicMock()
    prefs.checks.intrusive_web = intrusive_web
    return MagicMock(return_value=prefs)


REALISTIC_GIT_CONFIG = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
\tignorecase = true
\tprecomposeunicode = true
[remote "origin"]
\turl = git@github.com:acme-corp/webapp.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = deploy-bot
\temail = deploy-bot@acme-corp.example
"""
REALISTIC_GIT_CONFIG_WITH_CREDS = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://deploy-bot:ghp_aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3w@github.com/acme-corp/webapp.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[remote "staging"]
\turl = https://gitlab.acme-corp.internal/webapp-staging.git
\tfetch = +refs/heads/*:refs/remotes/staging/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
[user]
\tname = deploy-bot
\temail = deploy@acme-corp.internal
"""


class TestWebDAVCheck:
    def test_init(self):
        check = WebDAVCheck()
        assert check.name == "web_webdav"
        assert "http" in check.service_types

    @pytest.mark.asyncio
    async def test_skips_when_intrusive_disabled(self, service):
        check = WebDAVCheck()
        with patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=False)):
            result = await probe_and_grade(check, service)
        assert len(result.observations) == 0
        assert result.outputs.get("webdav_skipped") is True

    @pytest.mark.asyncio
    async def test_detects_propfind(self, service):
        check = WebDAVCheck()
        responses = {
            ("PROPFIND", "target.com"): resp(207, body="<multistatus>"),
            ("PUT", "chainsmith-webdav-test"): resp(403),
            ("MKCOL", "chainsmith-webdav-test"): resp(403),
        }
        with (
            patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=True)),
            patch(
                "app.checks.web.web_webdav.check.AsyncHttpClient",
                return_value=mock_client_multi(responses),
            ),
        ):
            result = await probe_and_grade(check, service)

        propfind_obs = [f for f in result.observations if "PROPFIND" in f.title]
        assert len(propfind_obs) == 1
        assert propfind_obs[0].title == "WebDAV PROPFIND enabled: target.com"
        assert propfind_obs[0].severity == "high"
        assert "207" in propfind_obs[0].evidence

    @pytest.mark.asyncio
    async def test_detects_put_write(self, service):
        check = WebDAVCheck()
        responses = {
            ("PROPFIND", "target.com"): resp(403),
            ("PUT", "chainsmith-webdav-test"): resp(201),
            ("DELETE", "chainsmith-webdav-test"): resp(204),
            ("MKCOL", "chainsmith-webdav-test"): resp(403),
        }
        with (
            patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=True)),
            patch(
                "app.checks.web.web_webdav.check.AsyncHttpClient",
                return_value=mock_client_multi(responses),
            ),
        ):
            result = await probe_and_grade(check, service)

        critical = [f for f in result.observations if f.severity == "critical"]
        assert len(critical) == 1
        assert "PUT" in critical[0].title
        assert critical[0].title == f"WebDAV write access: PUT accepted at {service.host}"
        assert "201" in critical[0].evidence

    @pytest.mark.asyncio
    async def test_detects_auth_required(self, service):
        check = WebDAVCheck()
        responses = {
            ("PROPFIND", "target.com"): resp(401),
            ("PUT", "chainsmith-webdav-test"): resp(401),
            ("MKCOL", "chainsmith-webdav-test"): resp(401),
        }
        with (
            patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=True)),
            patch(
                "app.checks.web.web_webdav.check.AsyncHttpClient",
                return_value=mock_client_multi(responses),
            ),
        ):
            result = await probe_and_grade(check, service)

        medium = [f for f in result.observations if f.severity == "medium"]
        assert len(medium) == 1
        assert medium[0].title == f"WebDAV methods require auth: {service.host}"
        assert "401" in medium[0].evidence

    @pytest.mark.asyncio
    async def test_no_observations_when_all_forbidden(self, service):
        """All WebDAV methods return 403 -- no observations should be created."""
        check = WebDAVCheck()
        responses = {
            ("PROPFIND", "target.com"): resp(403),
            ("PUT", "chainsmith-webdav-test"): resp(403),
            ("MKCOL", "chainsmith-webdav-test"): resp(403),
        }
        with (
            patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=True)),
            patch(
                "app.checks.web.web_webdav.check.AsyncHttpClient",
                return_value=mock_client_multi(responses),
            ),
        ):
            result = await probe_and_grade(check, service)

        assert len(result.observations) == 0
