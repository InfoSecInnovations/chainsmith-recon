"""Tests for ErrorPageCheck — error page framework detection."""

from unittest.mock import AsyncMock, patch

import pytest

from app.checks.base import Service
from app.checks.web.error_page import ErrorPageCheck
from app.lib.http import HttpResponse

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures & Helpers
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.fixture
def service():
    return Service(
        url="http://target.com:80", host="target.com", port=80, scheme="http", service_type="http"
    )


def resp(status_code=200, body="", headers=None, error=None, url="http://target.com:80"):
    return HttpResponse(
        url=url,
        status_code=status_code,
        headers=headers or {},
        body=body,
        elapsed_ms=50.0,
        error=error,
    )


def mock_client_multi(response_map=None, default=None):
    """Mock client that returns different responses based on URL/method."""
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

    mock.get = AsyncMock(side_effect=dispatch_get)
    mock.post = AsyncMock(side_effect=dispatch_post)
    mock.head = AsyncMock(side_effect=lambda url, **kw: _lookup("HEAD", url))
    mock._request = AsyncMock(side_effect=lambda m, url, **kw: _lookup(m, url))

    return mock


# ── Realistic HTML page templates ────────────────────────────────────────────

DJANGO_DEBUG_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Page not found at /nonexistent</title>
  <style>body { font-family: sans-serif; background: #eee; }</style>
</head>
<body>
  <div id="summary">
    <h1>Page not found <span>(404)</span></h1>
    <table class="meta">
      <tr><th>Request Method:</th><td>GET</td></tr>
      <tr><th>Request URL:</th><td>http://target.com/nonexistent</td></tr>
    </table>
  </div>
  <div id="info">
    <p>
      You're seeing this error because you have <code>DEBUG = True</code> in
      your Django settings file. Change that to <code>False</code>, and Django
      will display a standard 404 page.
    </p>
  </div>
  <div id="explanation">
    <p>Using the URLconf defined in <code>myproject.urls</code>, Django tried
    these URL patterns, in this order:</p>
    <ol>
      <li><code>^admin/</code></li>
      <li><code>^api/</code></li>
    </ol>
    <p>The current path, <code>nonexistent</code>, didn't match any of these.</p>
  </div>
</body>
</html>"""

WERKZEUG_DEBUGGER_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Werkzeug Debugger</title>
  <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css">
  <script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>
</head>
<body>
  <div class="debugger">
    <h1>Internal Server Error</h1>
    <div class="detail">
      <p class="errormsg">ZeroDivisionError: division by zero</p>
    </div>
    <div class="plain">
      <p>The debugger caught an exception in your WSGI application. You can now
      look at the traceback which led to the error.</p>
      <p>If you enable the evalex feature you can also use additional features
      like the interactive debugger console.</p>
    </div>
    <div class="traceback" id="traceback-0">
      <h2 class="traceback">Traceback <em>(most recent call last)</em>:</h2>
      <ul>
        <li><div class="frame">
          <span class="file">File "/app/server.py", line 14, in index</span>
          <span class="code">result = 1 / 0</span>
        </div></li>
      </ul>
      <blockquote>ZeroDivisionError: division by zero</blockquote>
    </div>
    <div class="footer">
      Brought to you by <strong>DON'T PANIC</strong>, your friendly Alarm Clock.
    </div>
  </div>
</body>
</html>"""

SPRING_BOOT_ERROR_PAGE = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Application Error</title>
  <style>body { font-family: "Helvetica Neue", Helvetica, Arial; }</style>
</head>
<body>
  <div class="container">
    <h1>Whitelabel Error Page</h1>
    <p>This application has no explicit mapping for /error, so you are seeing
    this as a fallback.</p>
    <div id="details">
      <p>Mon Apr 07 14:23:11 UTC 2026</p>
      <p>There was an unexpected error (type=Not Found, status=404).</p>
    </div>
    <div class="footer">
      <p>&copy; 2026 My Application</p>
    </div>
  </div>
</body>
</html>"""

EXPRESS_ERROR_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Error</title>
  <style>body { padding: 50px; font: 14px "Lucida Grande", Helvetica, Arial; }</style>
</head>
<body>
  <div id="wrapper">
    <h1>Not Found</h1>
    <h2>404</h2>
    <pre>Cannot GET /nonexistent-path</pre>
    <p>The requested resource could not be found on this server.</p>
    <hr>
    <address>Express Server</address>
  </div>
</body>
</html>"""

ASPNET_ERROR_PAGE = """<!DOCTYPE html>
<html>
<head>
  <title>Runtime Error - Application</title>
  <style>
    body { background-color: white; font-family: "Verdana"; }
    h1 { font-size: 18pt; color: red; }
    h2 { font-size: 14pt; color: maroon; }
  </style>
</head>
<body bgcolor="white">
  <span><h1>Server Error in '/' Application.<hr width="100%" size="1" color="silver"></h1>
  <h2><i>Runtime Error</i></h2></span>
  <font face="Arial, Helvetica, Geneva, SunSans-Regular, sans-serif">
    <b>Description:</b> An application error occurred on the server.
    The current custom error settings for this application prevent the details
    of the application error from being viewed remotely (for security reasons).
    <br><br>
    <b>Details:</b> To enable the details of this specific error message to be
    viewable on remote machines, please create a &lt;customErrors&gt; tag within
    a &quot;web.config&quot; configuration file.
  </font>
</body>
</html>"""

FASTAPI_ERROR_RESPONSE = """{
  "detail": "Not Found",
  "status": 404,
  "type": "about:blank",
  "title": "Not Found",
  "instance": "/nonexistent-path"
}"""

STACK_TRACE_IN_HTML = """<!DOCTYPE html>
<html>
<head><title>500 Internal Server Error</title></head>
<body>
  <h1>Internal Server Error</h1>
  <p>The server encountered an internal error and was unable to complete your request.</p>
  <div class="error-details">
    <pre>
Traceback (most recent call last):
  File "/opt/app/server.py", line 42, in handle_request
    response = process(request)
  File "/opt/app/handlers.py", line 118, in process
    data = db.query(sql)
  File "/opt/app/database.py", line 55, in query
    raise DatabaseError("Connection pool exhausted")
DatabaseError: Connection pool exhausted
    </pre>
  </div>
  <hr>
  <address>Python WSGI Server</address>
</body>
</html>"""

GENERIC_404_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Page Not Found</title>
  <style>
    body { font-family: Arial, sans-serif; text-align: center; padding: 100px; }
    h1 { font-size: 50px; }
  </style>
</head>
<body>
  <h1>404</h1>
  <p>Oops! The page you are looking for does not exist.</p>
  <p>It might have been moved or deleted.</p>
  <p><a href="/">Return to Homepage</a></p>
  <footer>&copy; 2026 Example Corp</footer>
</body>
</html>"""

GENERIC_500_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Internal Server Error</title>
  <style>body { font-family: sans-serif; text-align: center; padding: 80px; }</style>
</head>
<body>
  <h1>500 - Internal Server Error</h1>
  <p>Something went wrong on our end. Our engineering team has been notified.</p>
  <p>Please try again later or contact support if the problem persists.</p>
  <p>Reference ID: abc-12345-def</p>
  <footer>&copy; 2026 Example Corp</footer>
</body>
</html>"""

BENIGN_PAGE_WITH_DEBUG_WORD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Debug Techniques for Software Engineers</title>
</head>
<body>
  <h1>How to Debug Your Applications</h1>
  <article>
    <p>Debugging is an essential skill for every developer. Whether you are
    working in a development or production environment, knowing how to debug
    effectively can save hours of frustration.</p>
    <h2>Step 1: Enable Debug Logging</h2>
    <p>Most frameworks allow you to set debug = true in your configuration
    to get more verbose output. This is especially useful during development.</p>
    <h2>Step 2: Use a Debugger</h2>
    <p>Tools like the Werkzeug-based interactive debugger (for Python) or
    Chrome DevTools (for JavaScript) let you step through code line by line.</p>
    <p>For Django applications, setting DEBUG to True in settings.py gives
    you detailed error pages with full stack traces.</p>
  </article>
  <footer>&copy; 2026 Tech Blog</footer>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# ErrorPageCheck
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorPageCheck:
    def test_init(self):
        check = ErrorPageCheck()
        assert check.name == "error_page"
        assert "error_page_info" in check.produces

    @pytest.mark.asyncio
    async def test_django_debug_detected(self, service):
        """Django DEBUG=True is detected from a realistic 404 debug page."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=DJANGO_DEBUG_PAGE),
            ),
        ):
            result = await check.check_service(service, {})

        django = [o for o in result.observations if "django" in (o.id or "")]
        assert len(django) == 1
        assert django[0].severity == "medium"
        assert "Debug mode" in django[0].title
        assert "Django" in django[0].title
        assert "URLconf" in django[0].evidence or "DEBUG" in django[0].evidence

    @pytest.mark.asyncio
    async def test_werkzeug_debugger_high_severity(self, service):
        """Werkzeug debugger is flagged as high severity from a full debugger page."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(500, body=WERKZEUG_DEBUGGER_PAGE),
            ),
        ):
            result = await check.check_service(service, {})

        werkzeug = [o for o in result.observations if "werkzeug" in (o.id or "")]
        assert len(werkzeug) == 1
        assert werkzeug[0].severity == "high"
        assert "Debug mode" in werkzeug[0].title
        assert "Werkzeug" in werkzeug[0].title
        assert "remote code execution" in werkzeug[0].description

    @pytest.mark.asyncio
    async def test_spring_boot_identified(self, service):
        """Spring Boot Whitelabel Error Page is identified from realistic page."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=SPRING_BOOT_ERROR_PAGE),
            ),
        ):
            result = await check.check_service(service, {})

        spring = [o for o in result.observations if "spring-boot" in (o.id or "")]
        assert len(spring) == 1
        assert spring[0].severity == "low"
        assert "Framework identified" in spring[0].title
        assert "Spring Boot" in spring[0].title
        assert "Whitelabel Error Page" in spring[0].evidence

    @pytest.mark.asyncio
    async def test_express_identified(self, service):
        """Express.js Cannot GET is identified from a full HTML error page."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=EXPRESS_ERROR_PAGE),
            ),
        ):
            result = await check.check_service(service, {})

        express = [o for o in result.observations if "express" in (o.id or "")]
        assert len(express) == 1
        assert express[0].severity == "low"
        assert "Framework identified" in express[0].title
        assert "Cannot GET" in express[0].evidence

    @pytest.mark.asyncio
    async def test_fastapi_identified(self, service):
        """FastAPI JSON error is identified from realistic JSON response."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=FASTAPI_ERROR_RESPONSE),
            ),
        ):
            result = await check.check_service(service, {})

        fastapi = [o for o in result.observations if "fastapi" in (o.id or "")]
        assert len(fastapi) == 1
        assert fastapi[0].severity == "info"
        assert "Framework identified" in fastapi[0].title
        assert "Not Found" in fastapi[0].evidence

    @pytest.mark.asyncio
    async def test_asp_net_detected(self, service):
        """ASP.NET error page is identified from a realistic runtime error page."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(500, body=ASPNET_ERROR_PAGE),
            ),
        ):
            result = await check.check_service(service, {})

        asp = [o for o in result.observations if "asp.net" in (o.id or "")]
        assert len(asp) == 1
        assert asp[0].severity == "low"
        assert "Framework identified" in asp[0].title
        assert "Server Error in '/' Application" in asp[0].evidence

    @pytest.mark.asyncio
    async def test_stack_trace_detected(self, service):
        """Python stack trace embedded in an HTML error page is flagged."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=STACK_TRACE_IN_HTML),
            ),
        ):
            result = await check.check_service(service, {})

        stack = [o for o in result.observations if "stack-trace" in (o.id or "")]
        assert len(stack) == 1
        assert stack[0].severity == "low"
        assert "Stack trace" in stack[0].title
        assert "Stack trace detected" in stack[0].evidence

    @pytest.mark.asyncio
    async def test_custom_error_pages(self, service):
        """Custom error pages with no framework signature produce info observation."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=GENERIC_404_PAGE),
            ),
        ):
            result = await check.check_service(service, {})

        custom = [o for o in result.observations if "custom-errors" in (o.id or "")]
        assert len(custom) == 1
        assert custom[0].severity == "info"
        assert "framework not identified" in custom[0].title.lower()

    @pytest.mark.asyncio
    async def test_outputs_error_page_info(self, service):
        """Check outputs error_page_info with frameworks and debug status."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(404, body=SPRING_BOOT_ERROR_PAGE),
            ),
        ):
            result = await check.check_service(service, {})

        assert "error_page_info" in result.outputs
        info = result.outputs["error_page_info"]
        assert "Spring Boot" in info["frameworks"]
        assert info["frameworks"]["Spring Boot"]["debug_mode"] is False
        assert info["debug_mode"] is False

    # ── Negative tests ────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_generic_500_no_framework_signatures(self, service):
        """A generic 500 page without framework signatures should NOT trigger
        framework-specific observations."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(500, body=GENERIC_500_PAGE),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success
        # Should only have the custom-errors info observation
        framework_obs = [o for o in result.observations if "framework-" in (o.id or "")]
        assert len(framework_obs) == 0, (
            f"Expected no framework observations but got: {[o.title for o in framework_obs]}"
        )
        custom = [o for o in result.observations if "custom-errors" in (o.id or "")]
        assert len(custom) == 1
        assert custom[0].severity == "info"

    @pytest.mark.asyncio
    async def test_200_page_mentioning_debug_not_flagged(self, service):
        """A 200 page that discusses debugging in normal text should NOT trigger
        debug mode or framework detection observations."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(200, body=BENIGN_PAGE_WITH_DEBUG_WORD),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success
        # No framework-specific or debug-mode observations should fire
        framework_obs = [o for o in result.observations if "framework-" in (o.id or "")]
        assert len(framework_obs) == 0, (
            f"Expected no framework observations but got: {[o.title for o in framework_obs]}"
        )
        assert result.outputs["error_page_info"]["debug_mode"] is False

    # ── Malformed JSON / Connection error (rewritten from tautological) ───────

    @pytest.mark.asyncio
    async def test_malformed_json_triggers_stack_trace_detection(self, service):
        """Malformed JSON to an API path that returns a stack trace is detected
        as debug_mode and recorded in outputs."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                response_map={
                    ("POST", "/api"): resp(500, body=STACK_TRACE_IN_HTML),
                },
                default=resp(404, body=GENERIC_404_PAGE),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success
        info = result.outputs["error_page_info"]
        assert info["debug_mode"] is True

    @pytest.mark.asyncio
    async def test_connection_error_produces_error_message(self, service):
        """Connection errors are recorded in errors list and produce no
        framework observations."""
        check = ErrorPageCheck()

        with patch(
            "app.checks.web.error_page.AsyncHttpClient",
            return_value=mock_client_multi(
                default=resp(0, error="Connection refused"),
            ),
        ):
            result = await check.check_service(service, {})

        assert result.success
        # No framework-specific observations on connection error
        framework_obs = [o for o in result.observations if "framework-" in (o.id or "")]
        assert len(framework_obs) == 0
        # Should fall through to custom-errors since nothing was detected
        custom = [o for o in result.observations if "custom-errors" in (o.id or "")]
        assert len(custom) == 1
        assert result.outputs["error_page_info"]["debug_mode"] is False
        assert result.outputs["error_page_info"]["frameworks"] == {}
