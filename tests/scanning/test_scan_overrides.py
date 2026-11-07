"""
Tests for per-check scan-time overrides — §5.1 layer 6b (Phase 56.17).

`apply_check_overrides` assigns explicit per-check tunables onto resolved instances
AFTER the preset layer (6b > 6a), ephemerally. Plus `ScanStartInput.check_overrides`
parsing + `CheckOverride` validation.
"""

import pytest

from app.api_models import CheckOverride, ScanStartInput
from app.scan_overrides import apply_check_overrides

pytestmark = pytest.mark.unit


class FakeCheck:
    def __init__(self, name, intrusive=False):
        self.name = name
        self.timeout_seconds = 30.0
        self.requests_per_second = 10.0
        self.retry_count = 1
        self.delay_between_targets = 0.1
        self.on_critical = "annotate"
        self.capture = "all"
        self.intrusive = intrusive


def test_override_assigns_knobs_and_on_critical():
    checks = [FakeCheck("web_robots_txt")]
    apply_check_overrides(
        checks,
        {"web_robots_txt": CheckOverride(timeout_seconds=5.0, retry_count=3, on_critical="stop")},
    )
    c = checks[0]
    assert c.timeout_seconds == 5.0
    assert c.retry_count == 3
    assert c.on_critical == "stop"
    assert c.requests_per_second == 10.0  # untouched


def test_only_set_fields_apply():
    checks = [FakeCheck("x")]
    apply_check_overrides(checks, {"x": CheckOverride(requests_per_second=2.0)})
    assert checks[0].requests_per_second == 2.0
    assert checks[0].timeout_seconds == 30.0  # unset → unchanged


def test_override_for_missing_check_is_skipped():
    checks = [FakeCheck("present")]
    # An override naming a check not in the list (deselected/unknown) is a no-op.
    apply_check_overrides(checks, {"ghost": CheckOverride(retry_count=9)})
    assert checks[0].retry_count == 1


def test_inherit_on_critical_ignored_at_scan_time():
    checks = [FakeCheck("x")]
    apply_check_overrides(checks, {"x": {"on_critical": "inherit", "retry_count": 4}})
    assert checks[0].on_critical == "annotate"  # inherit ignored
    assert checks[0].retry_count == 4  # other fields still apply


def test_override_sets_the_capture_policy():
    """Phase 57.2 (D-20): the scalpel reaches `capture:` too, so an operator can
    silence one noisy check for one scan without editing its config.yaml."""
    checks = [FakeCheck("web_path_probe")]
    apply_check_overrides(checks, {"web_path_probe": CheckOverride(capture="none")})
    assert checks[0].capture == "none"


def test_inherit_capture_ignored_at_scan_time():
    checks = [FakeCheck("x")]
    apply_check_overrides(checks, {"x": {"capture": "inherit"}})
    assert checks[0].capture == "all"  # inherit ignored, baseline already resolved


def test_empty_overrides_is_noop_same_list():
    checks = [FakeCheck("x")]
    assert apply_check_overrides(checks, None) is checks
    assert apply_check_overrides(checks, {}) is checks


def test_accepts_plain_dict_overrides():
    checks = [FakeCheck("x")]
    apply_check_overrides(checks, {"x": {"timeout_seconds": 12.0}})
    assert checks[0].timeout_seconds == 12.0


# ── ScanStartInput / CheckOverride validation ────────────────────────


def test_scan_start_input_parses_nested_overrides():
    ssi = ScanStartInput(
        **{
            "preset": "quick",
            "check_overrides": {"web_robots_txt": {"timeout_seconds": 7, "on_critical": "stop"}},
        }
    )
    ov = ssi.check_overrides["web_robots_txt"]
    assert isinstance(ov, CheckOverride)
    assert ov.timeout_seconds == 7.0
    assert ov.on_critical == "stop"


def test_check_override_rejects_bad_on_critical():
    with pytest.raises(ValueError):
        CheckOverride(on_critical="explode")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout_seconds": 0},  # must be > 0
        {"requests_per_second": -1},  # must be > 0
        {"retry_count": -1},  # must be >= 0
        {"delay_between_targets": -0.5},  # must be >= 0
        {"bogus": 1},  # extra forbidden
    ],
)
def test_check_override_rejects_invalid(kwargs):
    with pytest.raises(ValueError):
        CheckOverride(**kwargs)


def test_check_override_allows_zero_retry_and_delay():
    ov = CheckOverride(retry_count=0, delay_between_targets=0)
    assert ov.retry_count == 0
    assert ov.delay_between_targets == 0
