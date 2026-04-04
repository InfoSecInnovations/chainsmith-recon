"""
app/config.py - Chainsmith Recon Configuration

Layered configuration system:
  1. Hardcoded defaults (in ChainsmithConfig dataclass)
  2. YAML config file  (CHAINSMITH_CONFIG env var or ./chainsmith.yaml)
  3. Environment variable overrides (CHAINSMITH_* prefix)

Usage:
    from app.config import get_config
    cfg = get_config()          # loads once, cached
    cfg = get_config(reload=True)  # force reload

Config file (chainsmith.yaml) example:
    target_domain: example.local
    scope:
      in_scope_domains:
        - example.local
        - "*.example.local"
      out_of_scope_domains:
        - vpn.example.local
      in_scope_ports: [80, 443, 8080, 8443]
    litellm:
      base_url: http://localhost:4000/v1
      model_scout: nova-mini
      model_verifier: nova-mini
      model_chainsmith: nova-pro
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from pathlib import Path

# Optional YAML support - graceful degradation if pyyaml not installed
try:
    import yaml as _yaml

    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


# ── Sub-configs ───────────────────────────────────────────────────


@dataclass
class ScopeConfig:
    in_scope_domains: list[str] = field(default_factory=list)
    out_of_scope_domains: list[str] = field(default_factory=list)
    in_scope_ports: list[int] = field(default_factory=list)  # Empty = no restriction (use profile)
    port_profile: str = "lab"  # "web", "ai", "full", "lab"
    allowed_techniques: list[str] = field(
        default_factory=lambda: [
            "port_scan",
            "header_grab",
            "robots_fetch",
            "directory_enum",
            "chatbot_probe",
            "prompt_extract",
            "error_trigger",
        ]
    )
    forbidden_techniques: list[str] = field(
        default_factory=lambda: [
            "dos",
            "data_exfiltration",
            "credential_stuffing",
            "sql_injection",
        ]
    )


@dataclass
class LiteLLMConfig:
    base_url: str = "http://localhost:4000/v1"
    model_scout: str = "nova-mini"
    model_verifier: str = "nova-mini"
    model_chainsmith: str = "nova-pro"
    model_chainsmith_fallback: str = "nova-mini"


@dataclass
class StorageConfig:
    backend: str = "sqlite"  # sqlite or postgresql
    db_path: Path = Path("./data/chainsmith.db")  # SQLite file path
    postgresql_url: str = ""  # PostgreSQL connection string
    auto_persist: bool = True  # Write scan results to DB automatically
    retention_days: int = 365  # Auto-delete scans older than this (0 = forever)


@dataclass
class ScanAdvisorConfig:
    enabled: bool = False
    mode: str = "post_scan"  # post_scan (phase 1) or between_iterations (phase 2)
    auto_seed_urls: bool = False  # allow advisor to suggest context injection
    require_approval: bool = True  # user must approve each recommendation


@dataclass
class SwarmConfig:
    enabled: bool = False
    default_rate_limit: float = 10.0
    task_timeout_seconds: int = 300
    heartbeat_interval: int = 30
    max_agents: int = 50


@dataclass
class PathsConfig:
    db_path: Path = Path("/data/recon.sqlite")  # Legacy - prefer storage.db_path
    attack_patterns: Path = Path("/app/data/attack_patterns.json")
    hallucinations: Path = Path("/app/data/hallucinations.json")


# ── Main config ───────────────────────────────────────────────────


@dataclass
class ChainsmithConfig:
    """
    Top-level Chainsmith configuration.

    All fields have sensible defaults. Override via YAML file or
    CHAINSMITH_* environment variables.
    """

    target_domain: str = ""
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    litellm: LiteLLMConfig = field(default_factory=LiteLLMConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    swarm: SwarmConfig = field(default_factory=SwarmConfig)
    scan_advisor: ScanAdvisorConfig = field(default_factory=ScanAdvisorConfig)

    # Raw seed URLs (optional - scanner can discover these itself)
    seed_urls: list[str] = field(default_factory=list)

    def is_valid(self) -> tuple[bool, list[str]]:
        """Validate config. Returns (ok, list_of_errors)."""
        errors = []
        if not self.target_domain:
            errors.append("target_domain is required")
        return len(errors) == 0, errors


# ── Loader ────────────────────────────────────────────────────────


def _load_yaml_file(path: Path) -> dict:
    """Load a YAML config file. Returns empty dict on any failure."""
    if not _YAML_AVAILABLE:
        return {}
    if not path.exists():
        return {}
    try:
        with open(path) as fh:
            data = _yaml.safe_load(fh) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _apply_yaml(cfg: ChainsmithConfig, data: dict) -> None:
    """Merge YAML data into config in-place."""
    if "target_domain" in data:
        cfg.target_domain = str(data["target_domain"])

    if "seed_urls" in data and isinstance(data["seed_urls"], list):
        cfg.seed_urls = [str(u) for u in data["seed_urls"]]

    if "scope" in data and isinstance(data["scope"], dict):
        s = data["scope"]
        sc = cfg.scope
        if "in_scope_domains" in s:
            sc.in_scope_domains = [str(d) for d in s["in_scope_domains"]]
        if "out_of_scope_domains" in s:
            sc.out_of_scope_domains = [str(d) for d in s["out_of_scope_domains"]]
        if "in_scope_ports" in s:
            sc.in_scope_ports = [int(p) for p in s["in_scope_ports"]]
        if "port_profile" in s:
            sc.port_profile = str(s["port_profile"])
        if "allowed_techniques" in s:
            sc.allowed_techniques = list(s["allowed_techniques"])
        if "forbidden_techniques" in s:
            sc.forbidden_techniques = list(s["forbidden_techniques"])

    if "litellm" in data and isinstance(data["litellm"], dict):
        ll = data["litellm"]
        llm = cfg.litellm
        if "base_url" in ll:
            llm.base_url = str(ll["base_url"])
        if "model_scout" in ll:
            llm.model_scout = str(ll["model_scout"])
        if "model_verifier" in ll:
            llm.model_verifier = str(ll["model_verifier"])
        if "model_chainsmith" in ll:
            llm.model_chainsmith = str(ll["model_chainsmith"])
        if "model_chainsmith_fallback" in ll:
            llm.model_chainsmith_fallback = str(ll["model_chainsmith_fallback"])

    if "paths" in data and isinstance(data["paths"], dict):
        p = data["paths"]
        pc = cfg.paths
        if "db_path" in p:
            pc.db_path = Path(p["db_path"])
        if "attack_patterns" in p:
            pc.attack_patterns = Path(p["attack_patterns"])
        if "hallucinations" in p:
            pc.hallucinations = Path(p["hallucinations"])

    if "storage" in data and isinstance(data["storage"], dict):
        st = data["storage"]
        sc = cfg.storage
        if "backend" in st:
            sc.backend = str(st["backend"])
        if "db_path" in st or "sqlite" in st:
            # Support both storage.db_path and storage.sqlite.path
            if "db_path" in st:
                sc.db_path = Path(st["db_path"])
            elif isinstance(st["sqlite"], dict) and "path" in st["sqlite"]:
                sc.db_path = Path(st["sqlite"]["path"])
        if "postgresql" in st and isinstance(st["postgresql"], dict):
            if "url" in st["postgresql"]:
                sc.postgresql_url = str(st["postgresql"]["url"])
        if "postgresql_url" in st:
            sc.postgresql_url = str(st["postgresql_url"])
        if "auto_persist" in st:
            sc.auto_persist = bool(st["auto_persist"])
        if "retention_days" in st:
            sc.retention_days = int(st["retention_days"])

    if "swarm" in data and isinstance(data["swarm"], dict):
        sw = data["swarm"]
        swc = cfg.swarm
        if "enabled" in sw:
            swc.enabled = bool(sw["enabled"])
        if "default_rate_limit" in sw:
            swc.default_rate_limit = float(sw["default_rate_limit"])
        if "task_timeout_seconds" in sw:
            swc.task_timeout_seconds = int(sw["task_timeout_seconds"])
        if "heartbeat_interval" in sw:
            swc.heartbeat_interval = int(sw["heartbeat_interval"])
        if "max_agents" in sw:
            swc.max_agents = int(sw["max_agents"])

    if "scan_advisor" in data and isinstance(data["scan_advisor"], dict):
        sa = data["scan_advisor"]
        sac = cfg.scan_advisor
        if "enabled" in sa:
            sac.enabled = bool(sa["enabled"])
        if "mode" in sa:
            sac.mode = str(sa["mode"])
        if "auto_seed_urls" in sa:
            sac.auto_seed_urls = bool(sa["auto_seed_urls"])
        if "require_approval" in sa:
            sac.require_approval = bool(sa["require_approval"])


def _apply_env(cfg: ChainsmithConfig) -> None:
    """Apply CHAINSMITH_* environment variable overrides."""
    env = os.environ

    if v := env.get("CHAINSMITH_TARGET_DOMAIN"):
        cfg.target_domain = v

    # Scope overrides (comma-separated lists)
    if v := env.get("CHAINSMITH_IN_SCOPE_DOMAINS"):
        cfg.scope.in_scope_domains = [d.strip() for d in v.split(",") if d.strip()]
    if v := env.get("CHAINSMITH_OUT_OF_SCOPE_DOMAINS"):
        cfg.scope.out_of_scope_domains = [d.strip() for d in v.split(",") if d.strip()]
    if v := env.get("CHAINSMITH_IN_SCOPE_PORTS"):
        with contextlib.suppress(ValueError):
            cfg.scope.in_scope_ports = [int(p.strip()) for p in v.split(",") if p.strip()]
    if v := env.get("CHAINSMITH_PORT_PROFILE"):
        cfg.scope.port_profile = v

    # Default scenario (used by ScenarioManager auto-load)
    # Not stored on ChainsmithConfig itself — ScenarioManager reads it directly
    # from os.environ["CHAINSMITH_SCENARIO"] at startup.

    # LiteLLM overrides (backward-compatible env names kept)
    if v := env.get("LITELLM_BASE_URL") or env.get("CHAINSMITH_LITELLM_BASE_URL"):
        cfg.litellm.base_url = v
    if v := env.get("LITELLM_MODEL_SCOUT") or env.get("CHAINSMITH_LITELLM_MODEL_SCOUT"):
        cfg.litellm.model_scout = v
    if v := env.get("LITELLM_MODEL_VERIFIER") or env.get("CHAINSMITH_LITELLM_MODEL_VERIFIER"):
        cfg.litellm.model_verifier = v
    if v := env.get("LITELLM_MODEL_CHAINSMITH") or env.get("CHAINSMITH_LITELLM_MODEL_CHAINSMITH"):
        cfg.litellm.model_chainsmith = v
    if v := env.get("LITELLM_MODEL_CHAINSMITH_FALLBACK") or env.get(
        "CHAINSMITH_LITELLM_MODEL_CHAINSMITH_FALLBACK"
    ):
        cfg.litellm.model_chainsmith_fallback = v

    # Paths overrides (backward-compatible names kept)
    if v := env.get("RECON_DB_PATH") or env.get("CHAINSMITH_DB_PATH"):
        cfg.paths.db_path = Path(v)
    if v := env.get("ATTACK_PATTERNS_PATH") or env.get("CHAINSMITH_ATTACK_PATTERNS_PATH"):
        cfg.paths.attack_patterns = Path(v)
    if v := env.get("HALLUCINATIONS_PATH") or env.get("CHAINSMITH_HALLUCINATIONS_PATH"):
        cfg.paths.hallucinations = Path(v)

    # Storage overrides
    if v := env.get("CHAINSMITH_STORAGE_BACKEND"):
        cfg.storage.backend = v
    if v := env.get("CHAINSMITH_SQLITE_PATH"):
        cfg.storage.db_path = Path(v)
    if v := env.get("CHAINSMITH_POSTGRESQL_URL"):
        cfg.storage.postgresql_url = v
    if v := env.get("CHAINSMITH_STORAGE_AUTO_PERSIST"):
        cfg.storage.auto_persist = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_STORAGE_RETENTION_DAYS"):
        with contextlib.suppress(ValueError):
            cfg.storage.retention_days = int(v)

    # Scan advisor overrides
    if v := env.get("CHAINSMITH_SCAN_ADVISOR_ENABLED"):
        cfg.scan_advisor.enabled = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_SCAN_ADVISOR_MODE"):
        cfg.scan_advisor.mode = v
    if v := env.get("CHAINSMITH_SCAN_ADVISOR_AUTO_SEED_URLS"):
        cfg.scan_advisor.auto_seed_urls = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_SCAN_ADVISOR_REQUIRE_APPROVAL"):
        cfg.scan_advisor.require_approval = v.lower() in ("true", "1", "yes")

    # Swarm overrides
    if v := env.get("CHAINSMITH_SWARM_ENABLED"):
        cfg.swarm.enabled = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_SWARM_DEFAULT_RATE_LIMIT"):
        with contextlib.suppress(ValueError):
            cfg.swarm.default_rate_limit = float(v)
    if v := env.get("CHAINSMITH_SWARM_TASK_TIMEOUT"):
        with contextlib.suppress(ValueError):
            cfg.swarm.task_timeout_seconds = int(v)


def load_config(config_path: Path | None = None) -> ChainsmithConfig:
    """
    Build a ChainsmithConfig from the layered sources:
      defaults → YAML file → env vars
    """
    cfg = ChainsmithConfig()

    # Resolve config file path
    if config_path is None:
        env_path = os.environ.get("CHAINSMITH_CONFIG")
        if env_path:
            config_path = Path(env_path)
        else:
            config_path = Path("chainsmith.yaml")

    yaml_data = _load_yaml_file(config_path)
    _apply_yaml(cfg, yaml_data)
    _apply_env(cfg)

    return cfg


# ── Module-level cached instance ─────────────────────────────────

_config: ChainsmithConfig | None = None


def get_config(reload: bool = False) -> ChainsmithConfig:
    """Return the cached config, loading it on first call."""
    global _config
    if _config is None or reload:
        _config = load_config()
    return _config


# ── Backward-compatible module-level constants ────────────────────
# These are derived lazily so they don't break imports in existing code
# that does `from app.config import LITELLM_BASE_URL` etc.


def __getattr__(name: str):
    """Lazy backward-compat shim for old-style module-level access."""
    _compat = {
        "RECON_DB_PATH": lambda c: c.paths.db_path,
        "LITELLM_BASE_URL": lambda c: c.litellm.base_url,
        "LITELLM_MODEL_SCOUT": lambda c: c.litellm.model_scout,
        "LITELLM_MODEL_VERIFIER": lambda c: c.litellm.model_verifier,
        "LITELLM_MODEL_CHAINSMITH": lambda c: c.litellm.model_chainsmith,
        "LITELLM_MODEL_CHAINSMITH_FALLBACK": lambda c: c.litellm.model_chainsmith_fallback,
        "TARGET_DOMAIN": lambda c: c.target_domain,
        "DEFAULT_SCOPE": lambda c: {
            "in_scope_domains": c.scope.in_scope_domains,
            "out_of_scope_domains": c.scope.out_of_scope_domains,
            "in_scope_ports": c.scope.in_scope_ports,
            "allowed_techniques": c.scope.allowed_techniques,
            "forbidden_techniques": c.scope.forbidden_techniques,
        },
        "ATTACK_PATTERNS_PATH": lambda c: c.paths.attack_patterns,
        "HALLUCINATIONS_PATH": lambda c: c.paths.hallucinations,
    }
    if name in _compat:
        return _compat[name](get_config())
    raise AttributeError(f"module 'app.config' has no attribute {name!r}")
