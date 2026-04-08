"""Tests for directory listing, default credentials, and debug endpoint checks."""

from unittest.mock import AsyncMock, MagicMock, patch

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


def _mock_preferences(intrusive_web=False):
    """Return a mock get_preferences function with the given intrusive_web setting."""
    prefs = MagicMock()
    prefs.checks.intrusive_web = intrusive_web
    return MagicMock(return_value=prefs)


# ---------------------------------------------------------------------------
# Realistic HTML page templates
# ---------------------------------------------------------------------------

APACHE_LISTING_PAGE = """<!DOCTYPE html>
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1>
<pre>
<img src="/icons/blank.gif" alt="Icon"> <a href="?C=N;O=D">Name</a>
<hr>
<img src="/icons/folder.gif" alt="[DIR]"> <a href="css/">css/</a>           2024-11-15 09:22    -
<img src="/icons/text.gif" alt="[TXT]"> <a href="app.py">app.py</a>        2024-11-14 17:45  3.2K
<img src="/icons/text.gif" alt="[TXT]"> <a href="README.md">README.md</a>  2024-11-10 12:00  1.1K
<hr>
</pre>
<address>Apache/2.4.52 (Ubuntu) Server at target.com Port 80</address>
</body>
</html>"""

SENSITIVE_LISTING_PAGE = """<!DOCTYPE html>
<html>
<head><title>Index of /data/</title></head>
<body>
<h1>Index of /data/</h1>
<pre>
<img src="/icons/back.gif" alt="[PARENTDIR]"> <a href="/">Parent Directory</a>
<img src="/icons/unknown.gif" alt="[   ]"> <a href=".env">.env</a>              2024-10-20 14:33  0.5K
<img src="/icons/unknown.gif" alt="[   ]"> <a href="model.pt">model.pt</a>    2024-10-18 09:15  124M
<img src="/icons/text.gif" alt="[TXT]"> <a href="notes.txt">notes.txt</a>     2024-10-15 08:00  0.2K
</pre>
<address>Apache/2.4.52 (Ubuntu) Server at target.com Port 80</address>
</body>
</html>"""

WERKZEUG_DEBUG_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Werkzeug Debugger</title>
  <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css">
</head>
<body>
  <div class="debugger">
    <h1>NameError</h1>
    <div class="detail">
      <p class="errormsg">NameError: name &#39;foobar&#39; is not defined</p>
    </div>
    <h2 class="traceback">Traceback <em>(most recent call last)</em></h2>
    <div class="traceback">
      <p>The Werkzeug Debugger caught an exception in your WSGI application.</p>
      <ul>
        <li><div class="frame"><code>/app/main.py</code> in <code>index</code>, line 42</li>
      </ul>
    </div>
    <div class="plain">
      <p>This is the Copy/Paste friendly version of the traceback.</p>
    </div>
    <div class="footer">
      Brought to you by <strong class="hierarchylist">DON'T PANIC</strong>
    </div>
  </div>
</body>
</html>"""

DJANGO_DEBUG_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>TemplateSyntaxError at /debug</title>
  <style>
    body { font-family: sans-serif; margin: 0; padding: 0; }
    #summary { background: #ffc; padding: 10px; }
  </style>
</head>
<body>
  <div id="summary">
    <h1>TemplateSyntaxError at /debug</h1>
    <pre class="exception_value">Invalid block tag on line 5: 'endfo'</pre>
    <table class="meta">
      <tr><th>Request Method:</th><td>GET</td></tr>
      <tr><th>Request URL:</th><td>http://target.com/debug</td></tr>
      <tr><th>Django Version:</th><td>4.2.7</td></tr>
      <tr><th>Python Version:</th><td>3.11.5</td></tr>
    </table>
  </div>
  <div id="info">
    <p>You're seeing this error because you have DEBUG = True in your
    Django settings file. Change it to False, and Django will display
    a standard 500 page.</p>
  </div>
</body>
</html>"""

ACTUATOR_ROOT_PAGE = """{
  "_links": {
    "self": {"href": "http://target.com/actuator", "templated": false},
    "health": {"href": "http://target.com/actuator/health", "templated": false},
    "env": {"href": "http://target.com/actuator/env", "templated": false},
    "beans": {"href": "http://target.com/actuator/beans", "templated": false},
    "configprops": {"href": "http://target.com/actuator/configprops", "templated": false}
  }
}"""

ACTUATOR_ENV_WITH_SECRETS = """{
  "activeProfiles": ["production"],
  "propertySources": [
    {
      "name": "systemEnvironment",
      "properties": {
        "DATABASE_URL": {"value": "postgres://user:pass@db:5432/app"},
        "SECRET_KEY": {"value": "supersecret123"},
        "HOME": {"value": "/root"},
        "PATH": {"value": "/usr/local/bin:/usr/bin"}
      }
    }
  ]
}"""

ADMIN_DASHBOARD_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Admin Panel - Dashboard</title>
  <link rel="stylesheet" href="/static/css/admin.css">
</head>
<body>
  <nav class="sidebar">
    <ul>
      <li><a href="/admin/dashboard">Dashboard</a></li>
      <li><a href="/admin/users">Manage Users</a></li>
      <li><a href="/admin/settings">Configuration</a></li>
    </ul>
  </nav>
  <main>
    <h1>Dashboard</h1>
    <p>Welcome to the admin panel. System status: operational.</p>
    <div class="stats">
      <div class="stat-card">Active users: 42</div>
      <div class="stat-card">Pending tasks: 7</div>
    </div>
  </main>
</body>
</html>"""

LOGIN_FORM_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Login - Admin Panel</title>
  <link rel="stylesheet" href="/static/css/login.css">
</head>
<body>
  <div class="login-container">
    <h2>Sign In</h2>
    <form action="/admin" method="POST">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required>
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">Log In</button>
    </form>
    <p class="footer-text">Forgot your password? Contact your administrator.</p>
  </div>
</body>
</html>"""

LOGIN_FAILURE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Login - Admin Panel</title>
</head>
<body>
  <div class="login-container">
    <h2>Sign In</h2>
    <div class="alert alert-danger">Invalid credentials. Please try again.</div>
    <form action="/admin" method="POST">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required>
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required>
      </div>
      <button type="submit">Log In</button>
    </form>
  </div>
</body>
</html>"""

GENERIC_PAGE_NO_DEBUG = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Application Status</title>
</head>
<body>
  <h1>Application Status</h1>
  <p>Service is running normally.</p>
  <ul>
    <li>Version: 2.3.1</li>
    <li>Uptime: 14 days</li>
  </ul>
</body>
</html>"""

GENERIC_ADMIN_NO_INDICATORS = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Portal</title>
</head>
<body>
  <h1>Company Portal</h1>
  <p>Please select a section from the navigation menu.</p>
  <nav>
    <a href="/about">About</a>
    <a href="/contact">Contact</a>
  </nav>
</body>
</html>"""


class TestDirectoryListingCheck:
    def test_init(self):
        check = DirectoryListingCheck()
        assert check.name == "directory_listing"

    @pytest.mark.asyncio
    async def test_detects_apache_listing(self, service):
        check = DirectoryListingCheck()
        responses = {
            ("GET", "target.com:80/"): resp(200, body=APACHE_LISTING_PAGE),
        }

        with patch(
            "app.checks.web.directory_listing.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        root_obs = [o for o in result.observations if "root" in o.title.lower()]
        assert len(root_obs) == 1
        assert root_obs[0].severity == "high"
        assert "target.com" in root_obs[0].title

    @pytest.mark.asyncio
    async def test_detects_sensitive_files(self, service):
        check = DirectoryListingCheck()
        responses = {
            ("GET", "/data/"): resp(200, body=SENSITIVE_LISTING_PAGE),
        }

        with patch(
            "app.checks.web.directory_listing.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        sensitive = [o for o in result.observations if "sensitive" in o.title.lower()]
        assert len(sensitive) == 1
        assert sensitive[0].severity == "high"
        assert ".env" in sensitive[0].description or "model.pt" in sensitive[0].description

    @pytest.mark.asyncio
    async def test_no_listing_no_observations(self, service):
        check = DirectoryListingCheck()
        with patch(
            "app.checks.web.directory_listing.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, body=GENERIC_PAGE_NO_DEBUG)),
        ):
            result = await check.check_service(service, {})
        assert result.observations == []

    @pytest.mark.asyncio
    async def test_normal_html_not_flagged_as_listing(self, service):
        """A normal page that mentions 'index' in prose should not trigger listing detection."""
        check = DirectoryListingCheck()
        normal_page = """<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>Welcome</h1><p>See our index page for details.</p></body>
</html>"""
        with patch(
            "app.checks.web.directory_listing.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(200, body=normal_page)),
        ):
            result = await check.check_service(service, {})
        assert result.observations == []


class TestDefaultCredsCheck:
    def test_init(self):
        check = DefaultCredsCheck()
        assert check.name == "default_creds"

    @pytest.mark.asyncio
    async def test_skips_when_intrusive_disabled(self, service):
        check = DefaultCredsCheck()
        with patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=False)):
            result = await check.check_service(service, {})
        assert result.observations == []
        assert result.outputs.get("default_creds_skipped") is True

    @pytest.mark.asyncio
    async def test_detects_no_auth_admin(self, service):
        check = DefaultCredsCheck()
        responses = {
            ("GET", "/admin"): resp(200, body=ADMIN_DASHBOARD_PAGE),
        }
        context = {f"paths_{service.port}": {"accessible": ["/admin"]}}

        with (
            patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=True)),
            patch(
                "app.checks.web.default_creds.AsyncHttpClient",
                return_value=mock_client_multi(responses),
            ),
        ):
            result = await check.check_service(service, context)

        no_auth = [o for o in result.observations if "no authentication" in o.title.lower()]
        assert len(no_auth) == 1
        assert no_auth[0].severity == "critical"
        assert "target.com" in no_auth[0].title
        assert "/admin" in no_auth[0].title

    @pytest.mark.asyncio
    async def test_detects_login_form_creds_rejected(self, service):
        check = DefaultCredsCheck()
        responses = {
            ("GET", "/admin"): resp(200, body=LOGIN_FORM_PAGE),
            ("POST", "/admin"): resp(200, body=LOGIN_FAILURE_PAGE),
        }
        context = {f"paths_{service.port}": {"accessible": ["/admin"]}}

        with (
            patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=True)),
            patch(
                "app.checks.web.default_creds.AsyncHttpClient",
                return_value=mock_client_multi(responses),
            ),
        ):
            result = await check.check_service(service, context)

        login_obs = [o for o in result.observations if "Login form" in o.title]
        assert len(login_obs) == 1
        assert login_obs[0].severity == "high"
        assert "target.com" in login_obs[0].title

    @pytest.mark.asyncio
    async def test_no_admin_paths_no_observations(self, service):
        check = DefaultCredsCheck()
        context = {f"paths_{service.port}": {"accessible": ["/api", "/health"]}}

        with patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=True)):
            result = await check.check_service(service, context)

        assert result.observations == []

    @pytest.mark.asyncio
    async def test_admin_page_without_admin_content_not_flagged(self, service):
        """An admin path returning generic content (no dashboard/manage/users keywords)
        should not produce a no-auth observation."""
        check = DefaultCredsCheck()
        responses = {
            ("GET", "/admin"): resp(200, body=GENERIC_ADMIN_NO_INDICATORS),
        }
        context = {f"paths_{service.port}": {"accessible": ["/admin"]}}

        with (
            patch("app.preferences.get_preferences", _mock_preferences(intrusive_web=True)),
            patch(
                "app.checks.web.default_creds.AsyncHttpClient",
                return_value=mock_client_multi(responses),
            ),
        ):
            result = await check.check_service(service, context)

        no_auth = [o for o in result.observations if "no authentication" in o.title.lower()]
        assert no_auth == [], "Generic page without admin indicators should not be flagged"


class TestDebugEndpointCheck:
    def test_init(self):
        check = DebugEndpointCheck()
        assert check.name == "debug_endpoints"

    @pytest.mark.asyncio
    async def test_detects_werkzeug_debugger(self, service):
        check = DebugEndpointCheck()
        responses = {
            ("GET", "/__debug__/"): resp(200, body=WERKZEUG_DEBUG_PAGE),
        }

        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        werkzeug = [o for o in result.observations if "Werkzeug" in o.title]
        assert len(werkzeug) == 1
        assert werkzeug[0].severity == "critical"
        assert "target.com" in werkzeug[0].title
        assert "/__debug__/" in werkzeug[0].title

    @pytest.mark.asyncio
    async def test_detects_django_debug(self, service):
        check = DebugEndpointCheck()
        responses = {
            ("GET", "/debug"): resp(200, body=DJANGO_DEBUG_PAGE),
        }

        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        django = [o for o in result.observations if "Django" in o.title]
        assert len(django) == 1
        assert django[0].severity == "high"
        assert "target.com" in django[0].title

    @pytest.mark.asyncio
    async def test_detects_actuator(self, service):
        check = DebugEndpointCheck()
        responses = {
            ("GET", "/actuator"): resp(200, body=ACTUATOR_ROOT_PAGE),
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

        actuator = [o for o in result.observations if "Actuator" in o.title]
        assert len(actuator) == 1
        assert actuator[0].severity == "high"
        assert "target.com" in actuator[0].title

    @pytest.mark.asyncio
    async def test_detects_sensitive_env_vars(self, service):
        check = DebugEndpointCheck()
        responses = {
            ("GET", "/actuator/env"): resp(200, body=ACTUATOR_ENV_WITH_SECRETS),
        }

        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        sensitive = [o for o in result.observations if "leaks" in o.title.lower()]
        assert len(sensitive) == 1
        assert sensitive[0].severity in ("critical", "high")

    @pytest.mark.asyncio
    async def test_no_debug_endpoints_no_observations(self, service):
        check = DebugEndpointCheck()
        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(default=resp(404)),
        ):
            result = await check.check_service(service, {})
        assert result.observations == []

    @pytest.mark.asyncio
    async def test_generic_200_page_not_flagged(self, service):
        """A debug path returning a generic status page without framework
        signatures or sensitive data should produce no observations."""
        check = DebugEndpointCheck()
        responses = {
            ("GET", "/debug"): resp(200, body=GENERIC_PAGE_NO_DEBUG),
            ("GET", "/__debug__/"): resp(200, body=GENERIC_PAGE_NO_DEBUG),
        }

        with patch(
            "app.checks.web.debug_endpoints.AsyncHttpClient",
            return_value=mock_client_multi(responses, default=resp(404)),
        ):
            result = await check.check_service(service, {})

        assert result.observations == [], (
            "Generic pages without debug signatures should not produce observations"
        )


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
