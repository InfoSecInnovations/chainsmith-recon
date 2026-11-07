"""B-1: `chainsmith scan --scope FILE` sends the file's scope with the scan."""

import json

import pytest
from click.testing import CliRunner

from app.cli import cli
from tests.cli.test_cli import _mock_client, _patch_client

pytestmark = pytest.mark.unit


def _run(args):
    client = _mock_client()
    with _patch_client(client):
        result = CliRunner().invoke(cli, ["scan", *args, "--quiet"])
    return result, client


def test_a_yaml_scope_file_is_sent_with_the_scan(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "target: example.com\n"
        "exclude: [admin.example.com]\n"
        "scan_window: {start: '2026-11-07T00:00:00Z', end: '2026-11-08T00:00:00Z'}\n"
        "proof_of_scope: {traffic_logging: true, block_exclusions: true, log_violations: true}\n",
        encoding="utf-8",
    )

    result, client = _run(["example.com", "-e", "vpn.example.com", "--scope", str(scope)])

    assert result.exit_code == 0, result.output
    args, kwargs = client.start_scan.call_args
    assert args[0] == "example.com"
    assert kwargs["exclude"] == ["vpn.example.com", "admin.example.com"]
    assert kwargs["scan_window"]["start"] == "2026-11-07T00:00:00Z"
    assert kwargs["proof_of_scope"]["block_exclusions"] is True
    client.set_scope.assert_not_called()


def test_a_json_scope_file_works_too(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps({"exclude": "admin.example.com"}), encoding="utf-8")

    result, client = _run(["example.com", "--scope", str(scope)])

    assert result.exit_code == 0, result.output
    assert client.start_scan.call_args.kwargs["exclude"] == ["admin.example.com"]


def test_a_target_mismatch_is_refused(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text("target: other.com\n", encoding="utf-8")

    result, client = _run(["example.com", "--scope", str(scope)])

    assert result.exit_code != 0
    assert "does not match TARGET" in result.output
    client.start_scan.assert_not_called()


def test_an_unknown_key_is_refused_not_ignored(tmp_path):
    scope = tmp_path / "scope.yaml"
    scope.write_text("excludes: [typo.example.com]\n", encoding="utf-8")

    result, client = _run(["example.com", "--scope", str(scope)])

    assert result.exit_code != 0
    assert "unknown key(s) excludes" in result.output
    client.start_scan.assert_not_called()
