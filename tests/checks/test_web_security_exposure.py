"""Tests for WebDAV, VCS exposure, and config exposure checks."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.config_exposure import ConfigExposureCheck
from app.checks.web.vcs_exposure import VCSExposureCheck
from app.checks.web.webdav import WebDAVCheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


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


def _mock_preferences(intrusive_web=False):
    """Return a mock get_preferences function with the given intrusive_web setting."""
    prefs = MagicMock()
    prefs.checks.intrusive_web = intrusive_web
    return MagicMock(return_value=prefs)


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
        with patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=False)):
            result = await check.check_service(service, {})
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
                "app.checks.web.webdav.AsyncHttpClient", return_value=mock_client_multi(responses)
            ),
        ):
            result = await check.check_service(service, {})

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
                "app.checks.web.webdav.AsyncHttpClient", return_value=mock_client_multi(responses)
            ),
        ):
            result = await check.check_service(service, {})

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
                "app.checks.web.webdav.AsyncHttpClient", return_value=mock_client_multi(responses)
            ),
        ):
            result = await check.check_service(service, {})

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
                "app.checks.web.webdav.AsyncHttpClient", return_value=mock_client_multi(responses)
            ),
        ):
            result = await check.check_service(service, {})

        assert len(result.observations) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# VCSExposureCheck
# ═══════════════════════════════════════════════════════════════════════════════


# Realistic multi-section git config body (not a minimal stub)
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

# Git config with embedded credentials in remote URL (realistic multi-section)
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
        assert check.name == "vcs_exposure"

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
            "app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)
        ):
            result = await check.check_service(service, context)

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
            "app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)
        ):
            result = await check.check_service(service, context)

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
            "app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)
        ):
            result = await check.check_service(service, context)

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
            "app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)
        ):
            result = await check.check_service(service, context)

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
            "app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)
        ):
            result = await check.check_service(service, context)

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
            "app.checks.web.vcs_exposure.AsyncHttpClient", return_value=mock_client_multi(responses)
        ):
            result = await check.check_service(service, context)

        assert len(result.observations) == 0


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
        env_content = (
            "# Application configuration\n"
            "APP_NAME=acme-webapp\n"
            "APP_PORT=8080\n"
            "DEBUG=true\n"
            "LOG_LEVEL=info\n"
            "\n"
            "# Database\n"
            "DB_HOST=localhost\n"
            "DB_PORT=5432\n"
            "DB_NAME=acme_prod\n"
            "\n"
            "# Third-party integrations\n"
            "OPENAI_API_KEY=sk-proj-1a2B3c4D5e6F7g8H9iJkLmNoPqRsTuVwXyZ0123456\n"
            "SENTRY_DSN=https://abc@sentry.io/123\n"
        )
        responses = {
            ("GET", ".env"): resp(200, body=env_content),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.env"]}}

        with patch(
            "app.checks.web.config_exposure.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, context)

        secrets = [f for f in result.observations if "contains secrets" in f.title.lower()]
        assert len(secrets) == 1
        assert secrets[0].severity == "critical"
        assert secrets[0].title == f"Configuration file contains secrets: /.env at {service.host}"
        assert "OPENAI_API_KEY" in secrets[0].evidence
        # Verify actual secret values are NOT in evidence
        assert "sk-proj-1a2B3c" not in secrets[0].evidence

    @pytest.mark.asyncio
    async def test_config_accessible_no_secrets(self, service):
        check = ConfigExposureCheck()
        responses = {
            ("GET", "config.json"): resp(
                200,
                body='{"debug": true, "port": 8080, "log_level": "info", "workers": 4}',
            ),
        }
        context = {f"paths_{service.port}": {"accessible": ["/config.json"]}}

        with patch(
            "app.checks.web.config_exposure.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, context)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == f"Configuration file accessible: /config.json at {service.host}"
        assert obs.severity == "high"
        assert "no secret" in obs.description.lower()

    @pytest.mark.asyncio
    async def test_empty_env_file_no_secrets(self, service):
        """An empty .env file is still accessible but contains no secrets."""
        check = ConfigExposureCheck()
        responses = {
            ("GET", ".env"): resp(200, body=""),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.env"]}}

        with patch(
            "app.checks.web.config_exposure.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, context)

        # Empty body -> check skips (resp.body is falsy)
        secret_obs = [f for f in result.observations if "secret" in f.title.lower()]
        assert len(secret_obs) == 0

    @pytest.mark.asyncio
    async def test_env_file_no_secret_patterns(self, service):
        """An .env file with only non-secret configuration values."""
        check = ConfigExposureCheck()
        env_content = (
            "# Application settings\n"
            "APP_NAME=my-app\n"
            "PORT=3000\n"
            "NODE_ENV=production\n"
            "LOG_FORMAT=json\n"
        )
        responses = {
            ("GET", ".env"): resp(200, body=env_content),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.env"]}}

        with patch(
            "app.checks.web.config_exposure.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, context)

        assert len(result.observations) == 1
        obs = result.observations[0]
        assert obs.title == f"Configuration file accessible: /.env at {service.host}"
        assert obs.severity == "high"
        assert "no secret" in obs.description.lower()

    @pytest.mark.asyncio
    async def test_no_observations_when_no_config(self, service):
        check = ConfigExposureCheck()
        responses = {
            ("GET", ".env"): resp(404),
            ("GET", "config.json"): resp(404),
            ("GET", "config.yaml"): resp(404),
            ("GET", "settings.json"): resp(404),
        }
        context = {f"paths_{service.port}": {"accessible": []}}

        with patch(
            "app.checks.web.config_exposure.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, context)

        assert len(result.observations) == 0

    @pytest.mark.asyncio
    async def test_detects_aws_credentials(self, service):
        check = ConfigExposureCheck()
        env_content = (
            "# Production environment\n"
            "APP_ENV=production\n"
            "REGION=us-east-1\n"
            "\n"
            "# AWS credentials (rotated quarterly)\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "\n"
            "# S3 bucket\n"
            "S3_BUCKET=acme-uploads-prod\n"
        )
        responses = {
            ("GET", ".env"): resp(200, body=env_content),
        }
        context = {f"paths_{service.port}": {"accessible": ["/.env"]}}

        with patch(
            "app.checks.web.config_exposure.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await check.check_service(service, context)

        secret_obs = [f for f in result.observations if "contains secrets" in f.title.lower()]
        assert len(secret_obs) == 1
        assert secret_obs[0].severity == "critical"
        assert (
            "AWS_ACCESS_KEY_ID" in secret_obs[0].evidence
            or "AWS_SECRET_ACCESS_KEY" in secret_obs[0].evidence
        )
