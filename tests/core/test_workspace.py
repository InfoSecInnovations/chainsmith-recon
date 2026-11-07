"""Tests for app/workspace.py — workspace resolution and rooting (Phase 57.1a)."""

import pytest

from app import workspace as ws


@pytest.fixture(autouse=True)
def _isolate_workspace(monkeypatch, tmp_path):
    """Keep every test off the operator's real ~/chainsmith and out of each other's way."""
    monkeypatch.delenv(ws.ENV_VAR, raising=False)
    monkeypatch.delenv("RECON_DB_PATH", raising=False)
    monkeypatch.delenv("CHAINSMITH_DB_PATH", raising=False)
    monkeypatch.delenv("DATA_DIR", raising=False)
    monkeypatch.setattr(ws, "DEFAULT_ROOT", tmp_path / "home" / "chainsmith" / "default")
    monkeypatch.setattr(ws, "LEGACY_DB_PATH", tmp_path / "legacy" / "chainsmith.db")
    ws.reset_workspace()
    yield
    ws.reset_workspace()


# ═══════════════════════════════════════════════════════════════════
# Precedence
# ═══════════════════════════════════════════════════════════════════


class TestResolveRoot:
    def test_explicit_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv(ws.ENV_VAR, str(tmp_path / "from_env"))
        root, source = ws.resolve_root(
            explicit=tmp_path / "from_flag", yaml_value=tmp_path / "from_yaml"
        )
        assert root == (tmp_path / "from_flag").resolve()
        assert source == "--workspace"

    def test_env_beats_yaml(self, tmp_path, monkeypatch):
        monkeypatch.setenv(ws.ENV_VAR, str(tmp_path / "from_env"))
        root, source = ws.resolve_root(yaml_value=tmp_path / "from_yaml")
        assert root == (tmp_path / "from_env").resolve()
        assert source == ws.ENV_VAR

    def test_yaml_beats_default(self, tmp_path):
        root, source = ws.resolve_root(yaml_value=tmp_path / "from_yaml")
        assert root == (tmp_path / "from_yaml").resolve()
        assert source == "chainsmith.yaml"

    def test_default_when_nothing_set(self):
        root, source = ws.resolve_root()
        assert root == ws.DEFAULT_ROOT.resolve()
        assert source == "default"

    def test_source_is_reported_for_the_startup_line(self, tmp_path):
        """The label exists so an operator can see which setting chose the directory."""
        _root, source = ws.resolve_root(explicit=tmp_path / "acme")
        assert source == "--workspace"


# ═══════════════════════════════════════════════════════════════════
# Layout
# ═══════════════════════════════════════════════════════════════════


class TestLayout:
    def test_paths_root_off_the_workspace(self, tmp_path):
        w = ws.Workspace(root=tmp_path / "acme")
        assert w.db_path == tmp_path / "acme" / "chainsmith.db"
        assert w.config_path == tmp_path / "acme" / "workspace.yaml"
        assert w.evidence_dir == tmp_path / "acme" / "evidence"
        assert w.reports_dir == tmp_path / "acme" / "reports"
        assert w.scratch_dir == tmp_path / "acme" / "scratch"
        assert w.logs_dir == tmp_path / "acme" / "logs"
        assert w.customizations_dir == tmp_path / "acme" / "customizations"

    def test_ensure_creates_subdirectories(self, tmp_path):
        w = ws.Workspace(root=tmp_path / "acme").ensure()
        for path in (
            w.root,
            w.evidence_dir,
            w.reports_dir,
            w.scratch_dir,
            w.logs_dir,
            w.customizations_dir,
        ):
            assert path.is_dir()

    def test_ensure_is_idempotent(self, tmp_path):
        w = ws.Workspace(root=tmp_path / "acme")
        w.ensure()
        (w.evidence_dir / "keep.txt").write_text("x")
        w.ensure()
        assert (w.evidence_dir / "keep.txt").read_text() == "x"

    def test_two_workspaces_share_nothing(self, tmp_path):
        """Physical separation is the property the whole design rests on."""
        acme = ws.Workspace(root=tmp_path / "acme").ensure()
        bravo = ws.Workspace(root=tmp_path / "bravo").ensure()

        assert acme.db_path != bravo.db_path
        assert acme.evidence_dir != bravo.evidence_dir
        assert not acme.root.samefile(bravo.root)


# ═══════════════════════════════════════════════════════════════════
# Legacy settings lose to the workspace
# ═══════════════════════════════════════════════════════════════════


class TestLegacyConflicts:
    def test_silent_when_nothing_legacy_is_set(self, tmp_path):
        w = ws.Workspace(root=tmp_path / "acme")
        assert ws.legacy_conflicts(w) == []

    def test_reports_disagreeing_db_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RECON_DB_PATH", "/somewhere/else.db")
        w = ws.Workspace(root=tmp_path / "acme")
        conflicts = ws.legacy_conflicts(w)
        assert len(conflicts) == 1
        assert "RECON_DB_PATH" in conflicts[0]
        assert str(w.db_path) in conflicts[0]

    def test_reports_disagreeing_data_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DATA_DIR", "/var/data")
        w = ws.Workspace(root=tmp_path / "acme")
        conflicts = ws.legacy_conflicts(w)
        assert len(conflicts) == 1
        assert "DATA_DIR" in conflicts[0]

    def test_agreeing_setting_is_not_a_conflict(self, tmp_path, monkeypatch):
        w = ws.Workspace(root=tmp_path / "acme")
        monkeypatch.setenv("DATA_DIR", str(w.logs_dir))
        assert ws.legacy_conflicts(w) == []


class TestLegacyDbNotice:
    def test_none_when_no_legacy_database(self, tmp_path):
        w = ws.Workspace(root=tmp_path / "acme")
        assert ws.legacy_db_notice(w) is None

    def test_points_at_the_old_database(self, tmp_path, monkeypatch):
        legacy = tmp_path / "legacy" / "chainsmith.db"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("pretend database")
        monkeypatch.setattr(ws, "LEGACY_DB_PATH", legacy)

        w = ws.Workspace(root=tmp_path / "acme")
        notice = ws.legacy_db_notice(w)

        assert notice is not None
        assert str(legacy) in notice
        assert "NOT been moved" in notice

    def test_does_not_move_the_old_database(self, tmp_path, monkeypatch):
        """Relocating an operator's database as an upgrade side effect is the wrong default."""
        legacy = tmp_path / "legacy" / "chainsmith.db"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("pretend database")
        monkeypatch.setattr(ws, "LEGACY_DB_PATH", legacy)

        w = ws.Workspace(root=tmp_path / "acme").ensure()
        ws.legacy_db_notice(w)

        assert legacy.exists()
        assert not w.db_path.exists()

    def test_silent_once_the_workspace_has_its_own_database(self, tmp_path, monkeypatch):
        legacy = tmp_path / "legacy" / "chainsmith.db"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("pretend database")
        monkeypatch.setattr(ws, "LEGACY_DB_PATH", legacy)

        w = ws.Workspace(root=tmp_path / "acme").ensure()
        w.db_path.write_text("current database")

        assert ws.legacy_db_notice(w) is None


# ═══════════════════════════════════════════════════════════════════
# Process-wide installation
# ═══════════════════════════════════════════════════════════════════


class TestActiveWorkspace:
    def test_get_resolves_default_when_none_installed(self):
        assert ws.get_workspace().root == ws.DEFAULT_ROOT.resolve()

    def test_set_then_get_round_trips(self, tmp_path):
        installed = ws.set_workspace(ws.Workspace(root=tmp_path / "acme"))
        assert ws.get_workspace() is installed

    def test_reset_clears(self, tmp_path):
        ws.set_workspace(ws.Workspace(root=tmp_path / "acme"))
        ws.reset_workspace()
        assert ws.get_workspace().root == ws.DEFAULT_ROOT.resolve()


# ═══════════════════════════════════════════════════════════════════
# Rooting through the config loader
# ═══════════════════════════════════════════════════════════════════


class TestConfigRooting:
    def test_db_path_comes_from_the_workspace(self, tmp_path, monkeypatch):
        from app.config import load_config

        monkeypatch.setenv(ws.ENV_VAR, str(tmp_path / "acme"))
        cfg = load_config(config_path=tmp_path / "missing.yaml")

        assert cfg.workspace == (tmp_path / "acme").resolve()
        assert cfg.storage.db_path == (tmp_path / "acme").resolve() / "chainsmith.db"

    def test_workspace_beats_explicit_db_path(self, tmp_path, monkeypatch):
        from app.config import load_config

        monkeypatch.setenv(ws.ENV_VAR, str(tmp_path / "acme"))
        monkeypatch.setenv("RECON_DB_PATH", str(tmp_path / "elsewhere.db"))
        cfg = load_config(config_path=tmp_path / "missing.yaml")

        assert cfg.storage.db_path == (tmp_path / "acme").resolve() / "chainsmith.db"

    def test_postgresql_backend_is_left_alone(self, tmp_path, monkeypatch):
        """No file path to root; the workspace still owns evidence and reports."""
        from app.config import load_config

        config_file = tmp_path / "chainsmith.yaml"
        config_file.write_text(
            "storage:\n  backend: postgresql\n  postgresql_url: postgresql://db/x\n"
        )
        monkeypatch.setenv(ws.ENV_VAR, str(tmp_path / "acme"))

        cfg = load_config(config_path=config_file)

        assert cfg.storage.backend == "postgresql"
        assert cfg.storage.postgresql_url == "postgresql://db/x"
        assert cfg.workspace == (tmp_path / "acme").resolve()

    def test_yaml_workspace_key(self, tmp_path):
        from app.config import load_config

        config_file = tmp_path / "chainsmith.yaml"
        config_file.write_text(f"workspace: {tmp_path / 'from_yaml'}\n")

        cfg = load_config(config_path=config_file)

        assert cfg.workspace == (tmp_path / "from_yaml").resolve()

    def test_an_installed_workspace_survives_load_config(self, tmp_path):
        """
        Regression: `chainsmith --workspace X` used to be silently discarded.

        The CLI group installs the workspace, then the first command calls
        get_config(). Before this was fixed, load_config() re-resolved from
        env/default and overwrote the flag — the operator was shown one
        workspace on stderr and scanned into another.
        """
        from app.config import load_config

        chosen = ws.set_workspace(ws.Workspace(root=tmp_path / "acme").ensure())

        cfg = load_config(config_path=tmp_path / "missing.yaml")

        assert ws.get_workspace() is chosen
        assert cfg.workspace == chosen.root
        assert cfg.storage.db_path == chosen.db_path

    def test_installed_workspace_beats_the_env_var(self, tmp_path, monkeypatch):
        """An explicit --workspace outranks CHAINSMITH_WORKSPACE, not the reverse."""
        from app.config import load_config

        monkeypatch.setenv(ws.ENV_VAR, str(tmp_path / "from_env"))
        chosen = ws.set_workspace(ws.Workspace(root=tmp_path / "from_flag").ensure())

        cfg = load_config(config_path=tmp_path / "missing.yaml")

        assert cfg.workspace == chosen.root

    def test_loading_creates_the_workspace(self, tmp_path, monkeypatch):
        from app.config import load_config

        monkeypatch.setenv(ws.ENV_VAR, str(tmp_path / "acme"))
        load_config(config_path=tmp_path / "missing.yaml")

        assert (tmp_path / "acme" / "evidence").is_dir()


# ═══════════════════════════════════════════════════════════════════
# Consumers rooted in 57.1a
# ═══════════════════════════════════════════════════════════════════


class TestRootedConsumers:
    def test_proof_of_scope_logs_land_in_the_workspace(self, tmp_path):
        from app.proof_of_scope import TrafficLogger, ViolationLogger

        w = ws.set_workspace(ws.Workspace(root=tmp_path / "acme").ensure())

        assert TrafficLogger()._log_file == w.logs_dir / "traffic_log.jsonl"
        assert ViolationLogger()._log_file == w.logs_dir / "violations_log.jsonl"

    def test_explicit_data_dir_still_wins_for_a_constructed_logger(self, tmp_path):
        """The constructor argument is a test/embedding seam, not operator config."""
        from app.proof_of_scope import TrafficLogger

        ws.set_workspace(ws.Workspace(root=tmp_path / "acme").ensure())
        logger = TrafficLogger(data_dir=tmp_path / "explicit")

        assert logger._log_file == tmp_path / "explicit" / "traffic_log.jsonl"

    def test_loggers_follow_a_workspace_installed_after_import(self, tmp_path):
        """Module-level singletons resolve lazily, so they cannot freeze a stale path."""
        from app.proof_of_scope import traffic_logger

        w = ws.set_workspace(ws.Workspace(root=tmp_path / "late").ensure())

        assert traffic_logger._log_file == w.logs_dir / "traffic_log.jsonl"

    def test_customizations_land_in_the_workspace(self, tmp_path):
        from app.customizations import _customizations_dir

        w = ws.set_workspace(ws.Workspace(root=tmp_path / "acme").ensure())

        assert _customizations_dir() == w.customizations_dir

    def test_scratch_lands_in_the_workspace(self, tmp_path):
        from app.db.writers import scratch_dir

        w = ws.set_workspace(ws.Workspace(root=tmp_path / "acme").ensure())

        assert scratch_dir() == w.scratch_dir

    def test_severity_overrides_are_per_workspace(self, tmp_path):
        """Contradictory overrides in two workspaces is correct, not a conflict."""
        from app.customizations import _severity_overrides_path

        ws.set_workspace(ws.Workspace(root=tmp_path / "acme").ensure())
        acme_path = _severity_overrides_path()

        ws.set_workspace(ws.Workspace(root=tmp_path / "bravo").ensure())
        bravo_path = _severity_overrides_path()

        assert acme_path != bravo_path
