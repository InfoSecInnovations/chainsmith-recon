"""Phase 45: target_host resolution in BaseCheck.create_observation()."""

import logging

import pytest

from app.checks.base import BaseCheck, CheckResult, Service

pytestmark = pytest.mark.unit


class _Probe(BaseCheck):
    name = "probe"

    async def run(self, context):
        return CheckResult(success=True)


@pytest.fixture
def probe():
    return _Probe()


def test_host_from_service(probe):
    svc = Service(url="http://x:8080", host="x", port=8080)
    obs = probe.create_observation(
        title="t", description="d", severity="info", evidence="e", target=svc
    )
    assert obs.target_host == "x"
    assert obs.target_url == "http://x:8080"


def test_host_from_service_without_url(probe):
    # Port-scan style: Service with host/port but no meaningful URL path
    svc = Service(url="", host="10.0.0.5", port=22, scheme="tcp")
    obs = probe.create_observation(
        title="t", description="d", severity="info", evidence="e", target=svc
    )
    assert obs.target_host == "10.0.0.5"


def test_host_parsed_from_target_url(probe):
    obs = probe.create_observation(
        title="t",
        description="d",
        severity="info",
        evidence="e",
        target_url="https://example.com:8443/admin",
    )
    assert obs.target_host == "example.com"
    assert obs.target_url == "https://example.com:8443/admin"


def test_explicit_host_wins_over_service(probe):
    svc = Service(url="http://wrong:80", host="wrong", port=80)
    obs = probe.create_observation(
        title="t",
        description="d",
        severity="info",
        evidence="e",
        target=svc,
        host="right.internal",
    )
    assert obs.target_host == "right.internal"


def test_explicit_host_wins_over_url(probe):
    obs = probe.create_observation(
        title="t",
        description="d",
        severity="info",
        evidence="e",
        target_url="https://wrong.example.com/",
        host="right.internal",
    )
    assert obs.target_host == "right.internal"


def test_empty_service_host_logs_warning(probe, caplog):
    svc = Service(url="http://fallback.example:80/", host="", port=80)
    with caplog.at_level(logging.WARNING, logger="app.checks.base"):
        obs = probe.create_observation(
            title="t", description="d", severity="info", evidence="e", target=svc
        )
    assert obs.target_host == "fallback.example"
    assert any("empty host" in rec.message for rec in caplog.records)


def test_to_dict_emits_host_alias(probe):
    svc = Service(url="http://x:8080", host="x", port=8080)
    obs = probe.create_observation(
        title="t", description="d", severity="info", evidence="e", target=svc
    )
    d = obs.to_dict()
    assert d["target_host"] == "x"
    assert d["host"] == "x"
