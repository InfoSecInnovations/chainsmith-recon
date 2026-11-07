"""
Tests for `workspace.yaml` — config layer 5 (Phase 57.1b).

Layer 5 was reserved by `config_resolver.py` from the start ("the user-override
file (layer 5) is future"). This fills it with the per-engagement policy layer:
knob defaults that apply across the whole workspace, overriding the component's
own `config.yaml` on purpose.
"""

import pytest

from app import workspace as ws
from app.components.config_models import ComponentConfig, Defaults, SuiteConfig, WorkspaceConfig
from app.components.config_resolver import ConfigResolver

pytestmark = pytest.mark.unit


class FakeCheck:
    timeout_seconds = 30.0
    requests_per_second = 10.0
    retry_count = 1
    delay_between_targets = 0.1


def _resolve(component_config, suite_config=None, env=None, workspace_config=None):
    return ConfigResolver(env=env or {}, workspace_config=workspace_config).resolve(
        "fake_check", FakeCheck, component_config, suite_config
    )


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """An isolated workspace with no workspace.yaml until a test writes one."""
    monkeypatch.delenv(ws.ENV_VAR, raising=False)
    ws.reset_workspace()
    w = ws.set_workspace(ws.Workspace(root=tmp_path / "acme").ensure())
    yield w
    ws.reset_workspace()


# ═══════════════════════════════════════════════════════════════════
# Parsing
# ═══════════════════════════════════════════════════════════════════


class TestLoadWorkspaceConfig:
    def test_absent_file_is_an_empty_config(self, workspace):
        """A workspace without the file is the normal case, not a degraded one."""
        cfg = ws.load_workspace_config(workspace)
        assert cfg.defaults.requests_per_second is None

    def test_empty_file_is_an_empty_config(self, workspace):
        workspace.config_path.write_text("")
        assert ws.load_workspace_config(workspace).defaults.requests_per_second is None

    def test_defaults_parse(self, workspace):
        workspace.config_path.write_text("defaults:\n  requests_per_second: 2.0\n")
        cfg = ws.load_workspace_config(workspace)
        assert cfg.defaults.requests_per_second == 2.0
        assert cfg.defaults.timeout_seconds is None

    def test_invalid_yaml_raises(self, workspace):
        workspace.config_path.write_text("defaults: [unclosed\n")
        with pytest.raises(ws.WorkspaceConfigError, match="not valid YAML"):
            ws.load_workspace_config(workspace)

    def test_non_mapping_raises(self, workspace):
        workspace.config_path.write_text("- a\n- b\n")
        with pytest.raises(ws.WorkspaceConfigError, match="mapping"):
            ws.load_workspace_config(workspace)

    def test_unknown_key_raises(self, workspace):
        workspace.config_path.write_text("nonsense: 1\n")
        with pytest.raises(ws.WorkspaceConfigError):
            ws.load_workspace_config(workspace)

    def test_unknown_knob_raises(self, workspace):
        workspace.config_path.write_text("defaults:\n  not_a_knob: 3\n")
        with pytest.raises(ws.WorkspaceConfigError):
            ws.load_workspace_config(workspace)


class TestUnimplementedKeys:
    """
    Keys an operator would reasonably expect, that nothing consumes yet.

    Accepting them silently is the dangerous option: someone who writes `scope:`
    and believes the engagement boundary is enforced, when it is not, is worse
    off than someone who gets an error naming the gap.
    """

    @pytest.mark.parametrize(
        "key, body",
        [
            ("scope", "scope:\n  in_scope_domains: [acme.test]\n"),
            ("exclusions", "exclusions: [vpn.acme.test]\n"),
            ("scan_window", "scan_window:\n  start: 2026-01-01\n"),
            ("capture", "capture:\n  capture_failures: true\n"),
            ("retention", "retention:\n  days: 30\n"),
            ("report", "report:\n  client_name: Acme\n"),
        ],
    )
    def test_rejected_by_name(self, workspace, key, body):
        workspace.config_path.write_text(body)
        with pytest.raises(ws.WorkspaceConfigError) as exc:
            ws.load_workspace_config(workspace)
        assert key in str(exc.value)
        assert "not consumed yet" in str(exc.value)

    def test_error_names_the_phase_that_will_wire_it(self, workspace):
        workspace.config_path.write_text("capture:\n  capture_failures: true\n")
        with pytest.raises(ws.WorkspaceConfigError, match="57.2"):
            ws.load_workspace_config(workspace)


# ═══════════════════════════════════════════════════════════════════
# Layer 5 in the resolver
# ═══════════════════════════════════════════════════════════════════


class TestLayerFive:
    def test_absent_workspace_config_changes_nothing(self):
        """None must resolve identically to an empty config — the common path."""
        without = _resolve(ComponentConfig(), workspace_config=None)
        empty = _resolve(ComponentConfig(), workspace_config=WorkspaceConfig())
        assert without.requests_per_second == empty.requests_per_second
        assert without.provenance == empty.provenance

    def test_workspace_default_wins_and_is_attributed(self):
        rc = _resolve(
            ComponentConfig(),
            workspace_config=WorkspaceConfig(defaults=Defaults(requests_per_second=2.0)),
        )
        assert rc.requests_per_second == 2.0
        assert rc.provenance["requests_per_second"] == "workspace"

    def test_workspace_beats_component_config(self):
        """Broad beats specific here on purpose: it is a policy ceiling, not a default."""
        rc = _resolve(
            ComponentConfig(defaults=Defaults(requests_per_second=50.0)),
            workspace_config=WorkspaceConfig(defaults=Defaults(requests_per_second=2.0)),
        )
        assert rc.requests_per_second == 2.0
        assert rc.provenance["requests_per_second"] == "workspace"

    def test_workspace_beats_suite(self):
        rc = _resolve(
            ComponentConfig(),
            suite_config=SuiteConfig(name="web", defaults=Defaults(requests_per_second=25.0)),
            workspace_config=WorkspaceConfig(defaults=Defaults(requests_per_second=2.0)),
        )
        assert rc.requests_per_second == 2.0

    def test_workspace_beats_env(self):
        """Layer 5 sits above layer 4; the engagement ceiling outranks the ambient var."""
        rc = _resolve(
            ComponentConfig(),
            env={"CHAINSMITH__FAKE_CHECK__REQUESTS_PER_SECOND": "40"},
            workspace_config=WorkspaceConfig(defaults=Defaults(requests_per_second=2.0)),
        )
        assert rc.requests_per_second == 2.0
        assert rc.provenance["requests_per_second"] == "workspace"

    def test_unset_knobs_fall_through(self):
        """A workspace that sets one knob must not clobber the others."""
        rc = _resolve(
            ComponentConfig(defaults=Defaults(timeout_seconds=5.0, retry_count=3)),
            workspace_config=WorkspaceConfig(defaults=Defaults(requests_per_second=2.0)),
        )
        assert rc.requests_per_second == 2.0
        assert rc.timeout_seconds == 5.0
        assert rc.retry_count == 3
        assert rc.provenance["timeout_seconds"] == "config"
        assert rc.provenance["retry_count"] == "config"

    def test_all_four_knobs_can_be_set(self):
        rc = _resolve(
            ComponentConfig(),
            workspace_config=WorkspaceConfig(
                defaults=Defaults(
                    timeout_seconds=7.0,
                    requests_per_second=2.0,
                    retry_count=5,
                    delay_between_targets=1.5,
                )
            ),
        )
        assert (rc.timeout_seconds, rc.requests_per_second) == (7.0, 2.0)
        assert (rc.retry_count, rc.delay_between_targets) == (5, 1.5)
        # `on_critical` and `capture` are policies about a component, not
        # tunables an operator retunes per engagement, so layer 5 never sets them.
        policies = {"on_critical", "capture"}
        assert all(rc.provenance[k] == "workspace" for k in rc.provenance if k not in policies)

    def test_on_critical_is_not_a_workspace_knob(self):
        """Layer 5 carries the standard knob set only — not the failure policy."""
        rc = _resolve(
            ComponentConfig(on_critical="stop"),
            workspace_config=WorkspaceConfig(defaults=Defaults(requests_per_second=2.0)),
        )
        assert rc.on_critical == "stop"
        assert rc.provenance["on_critical"] != "workspace"


# ═══════════════════════════════════════════════════════════════════
# Two workspaces, two policies
# ═══════════════════════════════════════════════════════════════════


class TestPerEngagementIsolation:
    def test_each_workspace_carries_its_own_policy(self, tmp_path, monkeypatch):
        monkeypatch.delenv(ws.ENV_VAR, raising=False)

        acme = ws.Workspace(root=tmp_path / "acme").ensure()
        acme.config_path.write_text("defaults:\n  requests_per_second: 2.0\n")

        bravo = ws.Workspace(root=tmp_path / "bravo").ensure()
        bravo.config_path.write_text("defaults:\n  requests_per_second: 30.0\n")

        acme_rc = _resolve(ComponentConfig(), workspace_config=ws.load_workspace_config(acme))
        bravo_rc = _resolve(ComponentConfig(), workspace_config=ws.load_workspace_config(bravo))

        assert acme_rc.requests_per_second == 2.0
        assert bravo_rc.requests_per_second == 30.0

        ws.reset_workspace()
