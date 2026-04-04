"""
Tests for app/config.py

Covers:
- ScopeConfig, LiteLLMConfig, PathsConfig dataclasses
- ChainsmithConfig and validation
- YAML loading and merging
- Environment variable overrides
- Layered config loading (defaults → YAML → env)
- Cached config (get_config)
- Backward-compatible module-level attributes
"""

from pathlib import Path

import pytest

from app.config import (
    ChainsmithConfig,
    LiteLLMConfig,
    PathsConfig,
    ScopeConfig,
    _apply_env,
    _apply_yaml,
    _load_yaml_file,
    get_config,
    load_config,
)

# ═══════════════════════════════════════════════════════════════════════════════
# ScopeConfig Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestScopeConfig:
    """Tests for ScopeConfig dataclass."""

    def test_default_values(self):
        """Defaults are sensible."""
        scope = ScopeConfig()

        assert scope.in_scope_domains == []
        assert scope.out_of_scope_domains == []
        assert scope.in_scope_ports == []  # Empty = no restriction (use profile)
        assert scope.port_profile == "lab"
        assert "port_scan" in scope.allowed_techniques
        assert "dos" in scope.forbidden_techniques

    def test_custom_values(self):
        """Custom values override defaults."""
        scope = ScopeConfig(
            in_scope_domains=["example.com"],
            out_of_scope_domains=["admin.example.com"],
            in_scope_ports=[8080, 8443],
        )

        assert scope.in_scope_domains == ["example.com"]
        assert scope.out_of_scope_domains == ["admin.example.com"]
        assert scope.in_scope_ports == [8080, 8443]


# ═══════════════════════════════════════════════════════════════════════════════
# LiteLLMConfig Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestLiteLLMConfig:
    """Tests for LiteLLMConfig dataclass."""

    def test_default_values(self):
        """Defaults point to local LiteLLM proxy."""
        llm = LiteLLMConfig()

        assert llm.base_url == "http://localhost:4000/v1"
        assert llm.model_scout == "nova-mini"
        assert llm.model_chainsmith == "nova-pro"
        assert llm.model_chainsmith_fallback == "nova-mini"

    def test_custom_values(self):
        """Custom values override defaults."""
        llm = LiteLLMConfig(
            base_url="http://custom:8000/v1",
            model_chainsmith="gpt-4",
        )

        assert llm.base_url == "http://custom:8000/v1"
        assert llm.model_chainsmith == "gpt-4"


# ═══════════════════════════════════════════════════════════════════════════════
# PathsConfig Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestPathsConfig:
    """Tests for PathsConfig dataclass."""

    def test_default_values(self):
        """Defaults point to standard paths."""
        paths = PathsConfig()

        assert paths.db_path == Path("/data/recon.sqlite")
        assert paths.attack_patterns == Path("/app/data/attack_patterns.json")

    def test_custom_values(self):
        """Custom values override defaults."""
        paths = PathsConfig(db_path=Path("/custom/db.sqlite"))

        assert paths.db_path == Path("/custom/db.sqlite")


# ═══════════════════════════════════════════════════════════════════════════════
# ChainsmithConfig Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestChainsmithConfig:
    """Tests for ChainsmithConfig dataclass."""

    def test_default_values(self):
        """Top-level defaults are sensible."""
        cfg = ChainsmithConfig()

        assert cfg.target_domain == ""
        assert cfg.seed_urls == []
        assert isinstance(cfg.scope, ScopeConfig)
        assert isinstance(cfg.litellm, LiteLLMConfig)
        assert isinstance(cfg.paths, PathsConfig)

    def test_is_valid_requires_target_domain(self):
        """Validation fails without target_domain."""
        cfg = ChainsmithConfig()

        valid, errors = cfg.is_valid()

        assert valid is False
        assert "target_domain is required" in errors

    def test_is_valid_passes_with_target(self):
        """Validation passes with target_domain set."""
        cfg = ChainsmithConfig(target_domain="example.com")

        valid, errors = cfg.is_valid()

        assert valid is True
        assert errors == []


# ═══════════════════════════════════════════════════════════════════════════════
# YAML Loading Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestYamlLoading:
    """Tests for YAML file loading."""

    def test_load_yaml_file_valid(self, tmp_path: Path):
        """Valid YAML file is loaded."""
        yaml_file = tmp_path / "config.yaml"
        yaml_file.write_text("target_domain: test.com\n")

        data = _load_yaml_file(yaml_file)

        assert data["target_domain"] == "test.com"

    def test_load_yaml_file_missing(self, tmp_path: Path):
        """Missing file returns empty dict."""
        data = _load_yaml_file(tmp_path / "missing.yaml")

        assert data == {}

    def test_load_yaml_file_invalid(self, tmp_path: Path):
        """Invalid YAML returns empty dict."""
        yaml_file = tmp_path / "bad.yaml"
        yaml_file.write_text("not: valid: yaml: syntax: here")

        data = _load_yaml_file(yaml_file)

        # Should not raise, returns empty
        assert data == {}

    def test_load_yaml_file_non_dict(self, tmp_path: Path):
        """Non-dict YAML returns empty dict."""
        yaml_file = tmp_path / "list.yaml"
        yaml_file.write_text("- item1\n- item2\n")

        data = _load_yaml_file(yaml_file)

        assert data == {}


# ═══════════════════════════════════════════════════════════════════════════════
# YAML Apply Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestApplyYaml:
    """Tests for _apply_yaml merging."""

    def test_apply_target_domain(self):
        """target_domain is applied."""
        cfg = ChainsmithConfig()
        _apply_yaml(cfg, {"target_domain": "example.com"})

        assert cfg.target_domain == "example.com"

    def test_apply_seed_urls(self):
        """seed_urls list is applied."""
        cfg = ChainsmithConfig()
        _apply_yaml(cfg, {"seed_urls": ["http://a.com", "http://b.com"]})

        assert cfg.seed_urls == ["http://a.com", "http://b.com"]

    def test_apply_scope(self):
        """scope section is applied."""
        cfg = ChainsmithConfig()
        _apply_yaml(
            cfg,
            {
                "scope": {
                    "in_scope_domains": ["example.com"],
                    "out_of_scope_domains": ["admin.example.com"],
                    "in_scope_ports": [80, 443],
                    "port_profile": "web",
                }
            },
        )

        assert cfg.scope.in_scope_domains == ["example.com"]
        assert cfg.scope.out_of_scope_domains == ["admin.example.com"]
        assert cfg.scope.in_scope_ports == [80, 443]
        assert cfg.scope.port_profile == "web"

    def test_apply_litellm(self):
        """litellm section is applied."""
        cfg = ChainsmithConfig()
        _apply_yaml(
            cfg,
            {
                "litellm": {
                    "base_url": "http://custom:4000",
                    "model_chainsmith": "gpt-4",
                }
            },
        )

        assert cfg.litellm.base_url == "http://custom:4000"
        assert cfg.litellm.model_chainsmith == "gpt-4"

    def test_apply_paths(self):
        """paths section is applied."""
        cfg = ChainsmithConfig()
        _apply_yaml(
            cfg,
            {
                "paths": {
                    "db_path": "/custom/db.sqlite",
                }
            },
        )

        assert cfg.paths.db_path == Path("/custom/db.sqlite")

    def test_apply_partial_keeps_defaults(self):
        """Partial config keeps other defaults."""
        cfg = ChainsmithConfig()
        _apply_yaml(cfg, {"target_domain": "example.com"})

        # Other defaults should remain
        assert cfg.litellm.base_url == "http://localhost:4000/v1"
        assert cfg.scope.in_scope_domains == []


# ═══════════════════════════════════════════════════════════════════════════════
# Environment Variable Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestApplyEnv:
    """Tests for _apply_env environment overrides."""

    def test_apply_target_domain(self, monkeypatch):
        """CHAINSMITH_TARGET_DOMAIN is applied."""
        monkeypatch.setenv("CHAINSMITH_TARGET_DOMAIN", "env.example.com")

        cfg = ChainsmithConfig()
        _apply_env(cfg)

        assert cfg.target_domain == "env.example.com"

    def test_apply_in_scope_domains(self, monkeypatch):
        """CHAINSMITH_IN_SCOPE_DOMAINS is comma-split."""
        monkeypatch.setenv("CHAINSMITH_IN_SCOPE_DOMAINS", "a.com, b.com, c.com")

        cfg = ChainsmithConfig()
        _apply_env(cfg)

        assert cfg.scope.in_scope_domains == ["a.com", "b.com", "c.com"]

    def test_apply_in_scope_ports(self, monkeypatch):
        """CHAINSMITH_IN_SCOPE_PORTS is comma-split integers."""
        monkeypatch.setenv("CHAINSMITH_IN_SCOPE_PORTS", "80, 443, 8080")

        cfg = ChainsmithConfig()
        _apply_env(cfg)

        assert cfg.scope.in_scope_ports == [80, 443, 8080]

    def test_apply_port_profile(self, monkeypatch):
        """CHAINSMITH_PORT_PROFILE is applied."""
        monkeypatch.setenv("CHAINSMITH_PORT_PROFILE", "ai")

        cfg = ChainsmithConfig()
        _apply_env(cfg)

        assert cfg.scope.port_profile == "ai"

    def test_apply_in_scope_ports_invalid(self, monkeypatch):
        """Invalid port numbers are ignored."""
        monkeypatch.setenv("CHAINSMITH_IN_SCOPE_PORTS", "80, not_a_number, 443")

        cfg = ChainsmithConfig()
        original_ports = cfg.scope.in_scope_ports.copy()
        _apply_env(cfg)

        # Should keep original due to ValueError
        assert cfg.scope.in_scope_ports == original_ports

    def test_apply_litellm_base_url(self, monkeypatch):
        """LITELLM_BASE_URL is applied."""
        monkeypatch.setenv("LITELLM_BASE_URL", "http://env:4000")

        cfg = ChainsmithConfig()
        _apply_env(cfg)

        assert cfg.litellm.base_url == "http://env:4000"

    def test_apply_litellm_chainsmith_prefixed(self, monkeypatch):
        """CHAINSMITH_LITELLM_BASE_URL also works."""
        monkeypatch.setenv("CHAINSMITH_LITELLM_BASE_URL", "http://prefixed:4000")

        cfg = ChainsmithConfig()
        _apply_env(cfg)

        assert cfg.litellm.base_url == "http://prefixed:4000"

    def test_apply_db_path(self, monkeypatch):
        """RECON_DB_PATH is applied."""
        monkeypatch.setenv("RECON_DB_PATH", "/env/db.sqlite")

        cfg = ChainsmithConfig()
        _apply_env(cfg)

        assert cfg.paths.db_path == Path("/env/db.sqlite")

    def test_apply_db_path_chainsmith_prefixed(self, monkeypatch):
        """CHAINSMITH_DB_PATH also works."""
        monkeypatch.setenv("CHAINSMITH_DB_PATH", "/chainsmith/db.sqlite")

        cfg = ChainsmithConfig()
        _apply_env(cfg)

        assert cfg.paths.db_path == Path("/chainsmith/db.sqlite")


# ═══════════════════════════════════════════════════════════════════════════════
# Layered Config Loading Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestLoadConfig:
    """Tests for load_config layered loading."""

    def test_load_defaults_only(self, clean_env, tmp_path: Path, monkeypatch):
        """With no YAML and no env vars, defaults are used."""
        monkeypatch.chdir(tmp_path)  # No chainsmith.yaml here

        cfg = load_config()

        assert cfg.target_domain == ""
        assert cfg.litellm.base_url == "http://localhost:4000/v1"

    def test_load_yaml_overrides_defaults(self, clean_env, tmp_path: Path, monkeypatch):
        """YAML values override defaults."""
        yaml_file = tmp_path / "chainsmith.yaml"
        yaml_file.write_text("target_domain: yaml.example.com\n")
        monkeypatch.chdir(tmp_path)

        cfg = load_config()

        assert cfg.target_domain == "yaml.example.com"

    def test_load_env_overrides_yaml(self, clean_env, tmp_path: Path, monkeypatch):
        """Env vars override YAML."""
        yaml_file = tmp_path / "chainsmith.yaml"
        yaml_file.write_text("target_domain: yaml.example.com\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CHAINSMITH_TARGET_DOMAIN", "env.example.com")

        cfg = load_config()

        assert cfg.target_domain == "env.example.com"

    def test_load_explicit_config_path(self, clean_env, tmp_path: Path):
        """Explicit config path is used."""
        yaml_file = tmp_path / "custom.yaml"
        yaml_file.write_text("target_domain: custom.example.com\n")

        cfg = load_config(config_path=yaml_file)

        assert cfg.target_domain == "custom.example.com"

    def test_load_config_env_path(self, clean_env, tmp_path: Path, monkeypatch):
        """CHAINSMITH_CONFIG env var specifies config path."""
        yaml_file = tmp_path / "env_config.yaml"
        yaml_file.write_text("target_domain: env_path.example.com\n")
        monkeypatch.setenv("CHAINSMITH_CONFIG", str(yaml_file))

        cfg = load_config()

        assert cfg.target_domain == "env_path.example.com"


# ═══════════════════════════════════════════════════════════════════════════════
# Cached Config Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetConfig:
    """Tests for get_config caching."""

    def test_get_config_caches(self, clean_env, tmp_path: Path, monkeypatch):
        """get_config returns cached instance."""
        monkeypatch.chdir(tmp_path)

        # Reset the module-level cache
        import app.config

        app.config._config = None

        cfg1 = get_config()
        cfg2 = get_config()

        assert cfg1 is cfg2

    def test_get_config_reload(self, clean_env, tmp_path: Path, monkeypatch):
        """get_config(reload=True) forces reload."""
        monkeypatch.chdir(tmp_path)

        import app.config

        app.config._config = None

        cfg1 = get_config()
        cfg2 = get_config(reload=True)

        assert cfg1 is not cfg2


# ═══════════════════════════════════════════════════════════════════════════════
# Backward Compatibility Tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestBackwardCompat:
    """Tests for backward-compatible module-level attributes."""

    def test_litellm_base_url_attr(self, clean_env, tmp_path: Path, monkeypatch):
        """LITELLM_BASE_URL module attribute works."""
        monkeypatch.chdir(tmp_path)

        import app.config

        app.config._config = None

        # Access via __getattr__
        url = app.config.LITELLM_BASE_URL

        assert url == "http://localhost:4000/v1"

    def test_recon_db_path_attr(self, clean_env, tmp_path: Path, monkeypatch):
        """RECON_DB_PATH module attribute works."""
        monkeypatch.chdir(tmp_path)

        import app.config

        app.config._config = None

        path = app.config.RECON_DB_PATH

        assert path == Path("/data/recon.sqlite")

    def test_invalid_attr_raises(self, clean_env, tmp_path: Path, monkeypatch):
        """Invalid attribute raises AttributeError."""
        monkeypatch.chdir(tmp_path)

        import app.config

        with pytest.raises(AttributeError, match="INVALID_ATTR"):
            _ = app.config.INVALID_ATTR
