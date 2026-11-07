"""Tests for web_config_exposure."""

from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.web_config_exposure import ConfigExposureCheck
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


class TestConfigExposureCheck:
    def test_init(self):
        check = ConfigExposureCheck()
        assert check.name == "web_config_exposure"

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
            "app.checks.web.web_config_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

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
            "app.checks.web.web_config_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

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
            "app.checks.web.web_config_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

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
            "app.checks.web.web_config_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

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
            "app.checks.web.web_config_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

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
            "app.checks.web.web_config_exposure.check.AsyncHttpClient",
            return_value=mock_client_multi(responses),
        ):
            result = await probe_and_grade(check, service, context)

        secret_obs = [f for f in result.observations if "contains secrets" in f.title.lower()]
        assert len(secret_obs) == 1
        assert secret_obs[0].severity == "critical"
        assert (
            "AWS_ACCESS_KEY_ID" in secret_obs[0].evidence
            or "AWS_SECRET_ACCESS_KEY" in secret_obs[0].evidence
        )
