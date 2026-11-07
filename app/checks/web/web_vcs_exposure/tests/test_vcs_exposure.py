"""Tests for web_vcs_exposure."""

from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_vcs_exposure import VCSExposureCheck
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
        # The real client stamps the requested URL onto the response, and a
        # migrated check records that URL on the exchange its grader reads.
        if response_map:
            for (m, pattern), response in response_map.items():
                if m == method and pattern in url:
                    return replace(response, url=url)
        return replace(default, url=url)

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


class TestVCSExposureCheck:
    def test_init(self):
        check = VCSExposureCheck()
        assert check.name == "web_vcs_exposure"

    @pytest.mark.asyncio
    async def test_detects_git_exposure(self, service):
        check = VCSExposureCheck()
        responses = {
            ("GET", ".git/config"): resp(200, body=REALISTIC_GIT_CONFIG),
            ("GET", ".git/COMMIT_EDITMSG"): resp(
                200, body="feat: add user auth endpoint\n\nSigned-off-by: deploy-bot"
            ),
            ("GET", ".git/refs/heads/main"): resp(
                200, body="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
            ),
            ("GET", ".git/refs/heads/master"): resp(404),
            ("GET", ".git/logs/HEAD"): resp(200, body="0000000 a1b2c3d initial commit"),
            ("GET", ".gitignore"): resp(200, body=".env\nnode_modules/\n__pycache__/"),
            ("GET", ".svn/entries"): resp(404),
            ("GET", ".hg/store"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.git/config", "/.git/HEAD"]}}

        with patch(
            "app.checks.web.web_vcs_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == f"Git repository exposed: {service.host}"
        assert obs.severity == "critical"
        assert "/.git/config" in obs.evidence

    @pytest.mark.asyncio
    async def test_detects_git_credentials(self, service):
        check = VCSExposureCheck()
        responses = {
            ("GET", ".git/config"): resp(200, body=REALISTIC_GIT_CONFIG_WITH_CREDS),
            ("GET", ".git/COMMIT_EDITMSG"): resp(404),
            ("GET", ".git/refs/heads/main"): resp(404),
            ("GET", ".git/refs/heads/master"): resp(404),
            ("GET", ".git/logs"): resp(404),
            ("GET", ".gitignore"): resp(404),
            ("GET", ".svn"): resp(404),
            ("GET", ".hg"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.git/config"]}}

        with patch(
            "app.checks.web.web_vcs_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

        assert len(result.observations) == 1
        cred_obs = result.observations[0]
        assert cred_obs.title == f"Git config contains credentials: {service.host}"
        assert cred_obs.severity == "critical"
        assert "redacted" in cred_obs.evidence.lower()

    @pytest.mark.asyncio
    async def test_git_config_404_no_observation(self, service):
        """A 404 at /.git/config should not produce a git exposure observation."""
        check = VCSExposureCheck()
        responses = {
            ("GET", ".git/config"): resp(404),
            ("GET", ".git/COMMIT_EDITMSG"): resp(404),
            ("GET", ".git/refs/heads/main"): resp(404),
            ("GET", ".git/refs/heads/master"): resp(404),
            ("GET", ".git/logs/HEAD"): resp(404),
            ("GET", ".gitignore"): resp(404),
            ("GET", ".svn/entries"): resp(404),
            ("GET", ".hg/store"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.git/config"]}}

        with patch(
            "app.checks.web.web_vcs_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

        git_obs = [o for o in result.observations if "git" in o.title.lower() or "Git" in o.title]
        assert len(git_obs) == 0

    @pytest.mark.asyncio
    async def test_git_config_not_git_syntax(self, service):
        """A 200 at /.git/config with non-git content (e.g., an HTML 404 page) should still
        be counted as accessible but won't match credential patterns."""
        check = VCSExposureCheck()
        html_body = "<html><head><title>Not Found</title></head><body><h1>404</h1></body></html>"
        responses = {
            ("GET", ".git/config"): resp(200, body=html_body),
            ("GET", ".git/COMMIT_EDITMSG"): resp(404),
            ("GET", ".git/refs/heads/main"): resp(404),
            ("GET", ".git/refs/heads/master"): resp(404),
            ("GET", ".git/logs/HEAD"): resp(404),
            ("GET", ".gitignore"): resp(404),
            ("GET", ".svn/entries"): resp(404),
            ("GET", ".hg/store"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.git/config"]}}

        with patch(
            "app.checks.web.web_vcs_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

        # Only 1 accessible path so severity should be high (not critical)
        if result.observations:
            obs = result.observations[0]
            assert obs.severity == "high"
            # Should not be flagged as containing credentials
            assert "credential" not in obs.title.lower()

    @pytest.mark.asyncio
    async def test_detects_svn(self, service):
        check = VCSExposureCheck()
        responses = {
            ("GET", ".svn/entries"): resp(
                200, body="12\ndir\n\nhttps://svn.acme-corp.internal/webapp/trunk\n"
            ),
            ("GET", ".hg/store"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.svn/entries"]}}

        with patch(
            "app.checks.web.web_vcs_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == f"SVN metadata exposed: {service.host}"
        assert obs.severity == "high"

    @pytest.mark.asyncio
    async def test_no_observations_when_no_vcs(self, service):
        check = VCSExposureCheck()
        responses = {
            ("GET", ".svn"): resp(404),
            ("GET", ".hg"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": []}}

        with patch(
            "app.checks.web.web_vcs_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

        assert len(result.observations) == 0
