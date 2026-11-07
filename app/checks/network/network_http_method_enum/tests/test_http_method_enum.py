"""Tests for network_http_method_enum."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.checks.base import Service
from app.checks.network.network_http_method_enum.check import _accepted


def _make_mock_client(
    options_allow: str | None = None,
    options_status: int = 200,
    method_responses: dict[str, int] | None = None,
    default_status: int = 405,
):
    """
    Return a factory that, when called as ``httpx.AsyncClient(...)``, produces
    an async-context-manager mock whose ``.options()`` and ``.request()``
    behave according to *options_allow* and *method_responses*.

    Parameters
    ----------
    options_allow : str | None
        Value of the ``Allow`` header returned by OPTIONS.  ``None`` means
        no Allow header at all.
    options_status : int
        Status code for the OPTIONS response.
    method_responses : dict[str, int]
        Maps HTTP method name (e.g. ``"TRACE"``) to the status code that a
        ``.request(method, ...)`` call should return.  Methods not listed
        get *default_status*.
    default_status : int
        Status code for methods not in *method_responses* (default 405,
        i.e. rejected).
    """
    method_responses = method_responses or {}

    def _factory(**kwargs):
        client = AsyncMock()

        # ---- OPTIONS response ------------------------------------------------
        options_resp = MagicMock()
        options_resp.status_code = options_status
        options_resp.headers = {}
        if options_allow is not None:
            options_resp.headers["allow"] = options_allow
        client.options = AsyncMock(return_value=options_resp)

        # ---- Generic .request(method, url) -----------------------------------
        # 57.4 wave 2: the probe sends OPTIONS through `.request` too, so that
        # every method is recorded the same way and `grade()` reads one uniform
        # set of exchanges.
        def _request(method, url, **kw):
            if method.upper() == "OPTIONS":
                return options_resp
            status = method_responses.get(method.upper(), default_status)
            resp = MagicMock()
            resp.status_code = status
            resp.headers = {}
            return resp

        client.request = AsyncMock(side_effect=_request)

        # ---- async context manager -------------------------------------------
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        return client

    return _factory


async def probe_and_grade(check, context):
    """Run the probe, then the grading stage, and return the graded result.

    This check is split into probe + grade, so `run()` now
    returns candidates rather than observations. Tests assert on what an
    operator sees, which is what the grading stage produces — the same thing
    `CheckLauncher` calls immediately after `execute()`.
    """
    from app.grading import grade_result

    result = await check.run(context)
    return await grade_result(check, result, context)


class TestHttpMethodEnumCheckInit:
    """Test HttpMethodEnumCheck metadata and initialization."""

    def test_check_metadata(self):
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        assert check.name == "network_http_method_enum"
        assert "method" in check.description.lower()

    def test_conditions(self):
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        assert len(check.conditions) == 1
        assert check.conditions[0].output_name == "services"
        assert check.conditions[0].operator == "truthy"

    def test_produces(self):
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        assert "http_methods" in check.produces

    def test_references(self):
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        assert len(check.references) > 0
        assert any("OWASP" in r or "CWE" in r for r in check.references)

    def test_conservative_rate_limit(self):
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        # Should be conservative to avoid WAF blocks
        assert check.requests_per_second <= 10.0

    def test_dangerous_methods_defined(self):
        from app.checks.network.network_http_method_enum.check import DANGEROUS_METHODS

        assert "TRACE" in DANGEROUS_METHODS
        assert "PUT" in DANGEROUS_METHODS
        assert "DELETE" in DANGEROUS_METHODS
        assert "PATCH" in DANGEROUS_METHODS
        # TRACE should be medium severity
        assert DANGEROUS_METHODS["TRACE"]["severity"] == "medium"


class TestHttpMethodEnumCheckRun:
    """Test HttpMethodEnumCheck runtime behavior via mocked HTTP transport."""

    @pytest.mark.asyncio
    async def test_no_services_fails(self):
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        result = await check.run({"services": []})
        assert result.success is False
        assert any("services" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_no_http_services_empty_output(self):
        """Non-HTTP services should produce empty output."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="tcp://db.example.com:6379", host="db.example.com", port=6379, scheme="tcp"
        )
        result = await probe_and_grade(check, {"services": [svc]})
        assert result.success is True
        assert result.outputs["http_methods"] == {}

    @pytest.mark.asyncio
    async def test_options_returns_allow_header(self):
        """OPTIONS Allow header populates allowed methods; _probe_service actually runs."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://api.example.com:80", host="api.example.com", port=80, scheme="http"
        )

        # Server allows GET, POST, OPTIONS. All dangerous/webdav probes get 405.
        factory = _make_mock_client(
            options_allow="GET, POST, OPTIONS",
            method_responses={},  # everything else 405
        )

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        assert result.success is True
        assert "api.example.com:80" in result.outputs["http_methods"]
        data = result.outputs["http_methods"]["api.example.com:80"]
        assert "GET" in data["allowed"]
        assert "POST" in data["allowed"]
        assert "OPTIONS" in data["allowed"]
        assert data["dangerous"] == []
        assert data["webdav"] == []
        assert data["options_allow"] == "GET, POST, OPTIONS"
        assert result.targets_checked == 1

    @pytest.mark.asyncio
    async def test_trace_method_observation(self):
        """TRACE enabled should produce a medium-severity observation with correct fields."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://web.example.com:80", host="web.example.com", port=80, scheme="http"
        )

        factory = _make_mock_client(
            options_allow="GET, POST, TRACE",
            method_responses={"TRACE": 200},
        )

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        trace_obs = [o for o in result.observations if "TRACE" in o.title]
        assert len(trace_obs) == 1
        assert trace_obs[0].severity == "medium"
        assert "TRACE method enabled" in trace_obs[0].title
        assert "web.example.com:80" in trace_obs[0].title
        assert "non-405" in trace_obs[0].evidence

        # Also confirm TRACE appears in the output data
        data = result.outputs["http_methods"]["web.example.com:80"]
        assert "TRACE" in data["dangerous"]
        assert "TRACE" in data["allowed"]

    @pytest.mark.asyncio
    async def test_put_method_observation(self):
        """PUT enabled should produce a medium-severity observation."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://api.example.com:8080", host="api.example.com", port=8080, scheme="http"
        )

        factory = _make_mock_client(
            options_allow=None,
            method_responses={"PUT": 201},
        )

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        put_obs = [o for o in result.observations if "PUT" in o.title]
        assert len(put_obs) == 1
        assert put_obs[0].severity == "medium"
        assert "PUT method enabled" in put_obs[0].title
        assert "api.example.com:8080" in put_obs[0].title

    @pytest.mark.asyncio
    async def test_delete_method_observation(self):
        """DELETE enabled should produce a low-severity observation."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://api.example.com:80", host="api.example.com", port=80, scheme="http"
        )

        factory = _make_mock_client(
            options_allow=None,
            method_responses={"DELETE": 204},
        )

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        del_obs = [o for o in result.observations if "DELETE" in o.title]
        assert len(del_obs) == 1
        assert del_obs[0].severity == "low"
        assert "DELETE method enabled" in del_obs[0].title

    @pytest.mark.asyncio
    async def test_multiple_dangerous_methods(self):
        """Multiple dangerous methods should each produce separate observations."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://app.example.com:80", host="app.example.com", port=80, scheme="http"
        )

        factory = _make_mock_client(
            options_allow="GET, POST",
            method_responses={
                "TRACE": 200,
                "PUT": 200,
                "DELETE": 200,
                "PATCH": 200,
            },
        )

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        dangerous_obs = [
            o
            for o in result.observations
            if o.severity in ("medium", "low") and "method" in o.title.lower()
        ]
        # TRACE, PUT = medium; DELETE, PATCH = low
        assert len(dangerous_obs) == 4

        titles = {o.title for o in dangerous_obs}
        assert any("TRACE" in t for t in titles)
        assert any("PUT" in t for t in titles)
        assert any("DELETE" in t for t in titles)
        assert any("PATCH" in t for t in titles)

        data = result.outputs["http_methods"]["app.example.com:80"]
        assert sorted(data["dangerous"]) == ["DELETE", "PATCH", "PUT", "TRACE"]

    @pytest.mark.asyncio
    async def test_webdav_methods_observation(self):
        """WebDAV methods should produce a medium-severity observation."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://files.example.com:80", host="files.example.com", port=80, scheme="http"
        )

        factory = _make_mock_client(
            options_allow="GET",
            method_responses={"PROPFIND": 207, "MKCOL": 201},
        )

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        webdav_obs = [o for o in result.observations if "webdav" in o.title.lower()]
        assert len(webdav_obs) == 1
        assert webdav_obs[0].severity == "medium"
        assert "PROPFIND" in webdav_obs[0].evidence
        assert "MKCOL" in webdav_obs[0].evidence

        data = result.outputs["http_methods"]["files.example.com:80"]
        assert "PROPFIND" in data["webdav"]
        assert "MKCOL" in data["webdav"]

    @pytest.mark.asyncio
    async def test_no_methods_no_observations(self):
        """No allowed methods (OPTIONS fails, all probes 405) -> no observations."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://empty.example.com:80", host="empty.example.com", port=80, scheme="http"
        )

        # OPTIONS returns no Allow header; all method probes return 405
        factory = _make_mock_client(options_allow=None, method_responses={})

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        assert result.success is True
        assert len(result.observations) == 0
        data = result.outputs["http_methods"]["empty.example.com:80"]
        assert data["allowed"] == []
        assert data["dangerous"] == []

    @pytest.mark.asyncio
    async def test_safe_methods_only_no_dangerous_observations(self):
        """A service allowing only GET, HEAD, POST should produce zero dangerous observations.

        This is the realistic 'negative' case: the server advertises safe methods
        via OPTIONS, and all dangerous/WebDAV probes return 405.  The only
        observation should be an info-level summary of allowed methods.
        """
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://safe.example.com:443", host="safe.example.com", port=443, scheme="https"
        )

        factory = _make_mock_client(
            options_allow="GET, HEAD, POST",
            method_responses={},  # all dangerous probes -> 405
        )

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        assert result.success is True

        # No medium/low/high/critical observations (no dangerous methods)
        dangerous_obs = [o for o in result.observations if o.severity != "info"]
        assert dangerous_obs == [], (
            f"Expected zero dangerous observations but got: "
            f"{[(o.title, o.severity) for o in dangerous_obs]}"
        )

        # Should have exactly one info observation listing allowed methods
        info_obs = [o for o in result.observations if o.severity == "info"]
        assert len(info_obs) == 1
        assert "Allowed methods" in info_obs[0].title
        assert "safe.example.com:443" in info_obs[0].title
        assert "GET" in info_obs[0].evidence
        assert "HEAD" in info_obs[0].evidence
        assert "POST" in info_obs[0].evidence

        data = result.outputs["http_methods"]["safe.example.com:443"]
        assert data["dangerous"] == []
        assert data["webdav"] == []
        assert sorted(data["allowed"]) == ["GET", "HEAD", "POST"]

    @pytest.mark.asyncio
    async def test_deduplication_same_host_port(self):
        """Same host:port should only be probed once."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        svc1 = Service(
            url="http://web.example.com:80", host="web.example.com", port=80, scheme="http"
        )
        svc2 = Service(
            url="http://web.example.com:80", host="web.example.com", port=80, scheme="http"
        )

        call_count = 0
        original_probe = check._probe_service

        async def counting_probe(svc):
            nonlocal call_count
            call_count += 1
            return await original_probe(svc)

        factory = _make_mock_client(options_allow="GET", method_responses={})

        with (
            patch("httpx.AsyncClient", side_effect=factory),
            patch.object(check, "_probe_service", side_effect=counting_probe),
        ):
            await check.run({"services": [svc1, svc2]})

        assert call_count == 1

    @pytest.mark.asyncio
    async def test_https_services_included(self):
        """HTTPS services should also be probed."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="https://secure.example.com:443",
            host="secure.example.com",
            port=443,
            scheme="https",
        )

        factory = _make_mock_client(
            options_allow="GET, POST",
            method_responses={},
        )

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        assert result.success is True
        assert "secure.example.com:443" in result.outputs["http_methods"]

    @pytest.mark.asyncio
    async def test_info_observation_includes_all_methods(self):
        """Info observation should list all allowed methods in evidence."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://api.example.com:80", host="api.example.com", port=80, scheme="http"
        )

        factory = _make_mock_client(
            options_allow="GET, POST, OPTIONS, HEAD",
            method_responses={},
        )

        with patch("httpx.AsyncClient", side_effect=factory):
            result = await probe_and_grade(check, {"services": [svc]})

        info_obs = [o for o in result.observations if o.severity == "info"]
        assert len(info_obs) == 1
        assert "Allowed methods" in info_obs[0].title
        # All four methods should appear in the evidence
        for method in ("GET", "HEAD", "OPTIONS", "POST"):
            assert method in info_obs[0].evidence

    @pytest.mark.asyncio
    async def test_options_failure_still_probes_methods(self):
        """If OPTIONS request raises an exception, dangerous method probing still works."""
        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()
        svc = Service(
            url="http://strict.example.com:80",
            host="strict.example.com",
            port=80,
            scheme="http",
        )

        call_index = 0

        def _factory(**kwargs):
            nonlocal call_index
            call_index += 1
            client = AsyncMock()

            if call_index == 1:
                # First client is for OPTIONS -- simulate connection failure
                client.request = AsyncMock(side_effect=Exception("Connection refused"))
            else:
                # Subsequent clients are for _probe_method calls
                resp = MagicMock()
                resp.status_code = 405
                resp.headers = {}
                client.request = AsyncMock(return_value=resp)

            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            return client

        with patch("httpx.AsyncClient", side_effect=_factory):
            result = await probe_and_grade(check, {"services": [svc]})

        assert result.success is True
        data = result.outputs["http_methods"]["strict.example.com:80"]
        # OPTIONS failed so options_allow should be None
        assert data["options_allow"] is None
        # All probes returned 405, so no dangerous methods
        assert data["dangerous"] == []


class TestHttpMethodEnumProbe:
    """Test _probe_method and _probe_service internals."""

    @pytest.mark.asyncio
    async def test_probe_method_405_means_rejected(self):
        """405 Method Not Allowed should mean method is NOT accepted."""

        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        mock_resp = MagicMock()
        mock_resp.status_code = 405
        mock_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            exchange = await check._probe_method("http://example.com", "TRACE", "example.com")

        # 57.4 wave 2: the probe records the response and `_accepted` reads it.
        assert _accepted(exchange) is False

    @pytest.mark.asyncio
    async def test_probe_method_200_means_accepted(self):
        """200 OK should mean method IS accepted."""

        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            exchange = await check._probe_method("http://example.com", "PUT", "example.com")

        assert _accepted(exchange) is True

    @pytest.mark.asyncio
    async def test_probe_method_501_means_rejected(self):
        """501 Not Implemented should mean method is NOT accepted."""

        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        mock_resp = MagicMock()
        mock_resp.status_code = 501
        mock_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            exchange = await check._probe_method("http://example.com", "TRACE", "example.com")

        assert _accepted(exchange) is False

    @pytest.mark.asyncio
    async def test_probe_method_connection_error(self):
        """Connection error should return False (not accepted)."""

        from app.checks.network.network_http_method_enum import HttpMethodEnumCheck

        check = HttpMethodEnumCheck()

        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            exchange = await check._probe_method("http://example.com", "TRACE", "example.com")

        # A probe that never completed is recorded as a failure, and a failure is
        # not an acceptance.
        assert exchange.error is not None
        assert _accepted(exchange) is False
