"""
B-10: `--no-llm` / `--provider` warn when they cannot take effect.
D-5 follow-up: the CLI reads the 429's `Retry-After` and says when to retry.
"""

from types import SimpleNamespace

import httpx
import pytest

from app.cli import _handle_api_error, _warn_if_llm_flags_ignored
from app.cli_client import ChainsmithAPIError, ChainsmithClient
from app.cli_server import ServerManager

pytestmark = pytest.mark.unit


def _ctx(started: bool | None):
    obj = {"server": "127.0.0.1:8000"}
    if started is not None:
        mgr = ServerManager()
        if started:
            mgr._process = object()  # what _start() leaves behind
        obj["server_mgr"] = mgr
    return SimpleNamespace(obj=obj)


def _plain(text, **_):
    return text


class TestLlmFlagWarning:
    def test_warns_when_the_server_was_already_running(self, capsys):
        assert _warn_if_llm_flags_ignored(_ctx(False), no_llm=True, provider=None, style=_plain)
        err = capsys.readouterr().err
        assert "--no-llm has no effect" in err
        assert "prefs set llm.provider" in err

    def test_names_the_provider_flag(self, capsys):
        _warn_if_llm_flags_ignored(_ctx(False), no_llm=False, provider="openai", style=_plain)
        assert "--provider openai has no effect" in capsys.readouterr().err

    def test_silent_when_the_cli_started_the_server(self, capsys):
        assert not _warn_if_llm_flags_ignored(_ctx(True), no_llm=True, provider=None, style=_plain)
        assert capsys.readouterr().err == ""

    def test_silent_without_the_flags(self, capsys):
        assert not _warn_if_llm_flags_ignored(
            _ctx(False), no_llm=False, provider=None, style=_plain
        )
        assert capsys.readouterr().err == ""

    def test_a_fresh_manager_has_not_started_a_server(self):
        assert ServerManager().started_server is False


def _client(status: int, headers: dict | None = None) -> ChainsmithClient:
    def handler(request):
        return httpx.Response(
            status, json={"detail": "Concurrent scan limit reached (1/1)."}, headers=headers
        )

    client = ChainsmithClient("http://test")
    client._client = httpx.Client(base_url="http://test", transport=httpx.MockTransport(handler))
    return client


class TestRetryAfter:
    def test_the_header_reaches_the_error(self):
        with pytest.raises(ChainsmithAPIError) as caught:
            _client(429, {"Retry-After": "30"})._request("POST", "/api/v1/scan")
        assert caught.value.status_code == 429
        assert caught.value.retry_after == 30

    @pytest.mark.parametrize("value", [None, "Wed, 21 Oct 2026 07:28:00 GMT"])
    def test_absent_or_date_form_is_none(self, value):
        headers = {"Retry-After": value} if value else None
        with pytest.raises(ChainsmithAPIError) as caught:
            _client(429, headers)._request("POST", "/api/v1/scan")
        assert caught.value.retry_after is None

    def test_the_cli_prints_the_hint(self, capsys):
        with pytest.raises(SystemExit):
            _handle_api_error(ChainsmithAPIError(429, "limit reached", retry_after=30))
        assert "retry in 30s" in capsys.readouterr().err

    def test_no_hint_for_other_errors(self, capsys):
        with pytest.raises(SystemExit):
            _handle_api_error(ChainsmithAPIError(400, "bad", retry_after=30))
        assert "retry" not in capsys.readouterr().err
