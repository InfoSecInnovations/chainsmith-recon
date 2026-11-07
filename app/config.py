"""
app/config.py - Chainsmith Recon Configuration

Layered configuration system:
  1. Hardcoded defaults (in ChainsmithConfig dataclass)
  2. YAML config file  (CHAINSMITH_CONFIG env var or ./chainsmith.yaml)
  3. Environment variable overrides (CHAINSMITH_* prefix)
  4. Workspace rooting - the workspace directory determines
     storage.db_path and the log/report/scratch/customization roots, and wins
     over any legacy path setting that disagrees. See app/workspace.py.

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
    model_verifier: str = "nova-mini"
    model_chainsmith: str = "nova-pro"
    model_chainsmith_fallback: str = "nova-mini"
    model_adjudicator: str = "nova-pro"
    model_triage: str = "nova-pro"


@dataclass
class StorageConfig:
    backend: str = "sqlite"  # sqlite or postgresql
    db_path: Path = Path("./data/chainsmith.db")  # SQLite file path
    postgresql_url: str = ""  # PostgreSQL connection string
    auto_persist: bool = True  # Write scan results to DB automatically
    retention_days: int = 365  # Auto-delete scans older than this (0 = forever)


@dataclass
class SwarmConfig:
    enabled: bool = False
    default_rate_limit: float = 10.0
    task_timeout_seconds: int = 300
    heartbeat_interval: int = 30
    max_agents: int = 50


# NOTE: The adjudicator / triage / researcher / coach agent configs moved out of
# ChainsmithConfig in Phase 56.10c — each agent's knobs now live in its own
# app/agents/<name>/config.yaml (`enabled` + `parameters`), with legacy
# CHAINSMITH_<AGENT>_* env vars honored by the agent registry's back-compat shim.
# LLM model routing for these agents stays central (LiteLLMConfig above).


@dataclass
class ConcurrencyConfig:
    """
    Concurrent-scan limits.

    `max_concurrent_scans` is enforced in `POST /api/v1/scan`, which answers 429
    at the cap. It defaults to 1 (decision D-1). Scope is still set globally by
    `POST /api/v1/scope` before a scan starts, so a second scan can pick up the
    wrong scope (B-1). Raise the cap only on a single-operator instance, or once
    scope moves inline onto `POST /api/v1/scan` (concurrent-scans.md §2.1).
    """

    max_concurrent_scans: int = 1
    # Seconds sent in the 429's `Retry-After` header when the cap is reached
    # (D-5: reject, do not queue). A hint only: the server cannot know when the
    # running scan will finish.
    retry_after_seconds: int = 30
    completed_scan_ttl_seconds: int = 300
    rate_limit_scope: str = "per_scan"  # "per_scan" | "global"


@dataclass
class ScanStreamConfig:
    """Gates advertisement of the SSE streaming capability."""

    enabled: bool = False


@dataclass
class PathsConfig:
    # NOTE: no `db_path`. It was a second, unread database path that nothing
    # opened a connection from; `storage.db_path` is the live one and is rooted
    # off the workspace. Removed rather than left to drift.
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
    # Workspace root. Populated by load_config(); the paths in
    # `storage` and the log/report/scratch roots are derived from it.
    workspace: Path | None = None
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    litellm: LiteLLMConfig = field(default_factory=LiteLLMConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    swarm: SwarmConfig = field(default_factory=SwarmConfig)
    # scan_analysis_advisor + check_proof_advisor moved to per-advisor
    # app/advisors/<name>/config.yaml (56.11);
    # adjudicator / triage / researcher / coach moved to per-agent config.yaml (56.10c).
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    scan_stream: ScanStreamConfig = field(default_factory=ScanStreamConfig)

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
    except (OSError, _yaml.YAMLError):
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
        if "model_verifier" in ll:
            llm.model_verifier = str(ll["model_verifier"])
        if "model_chainsmith" in ll:
            llm.model_chainsmith = str(ll["model_chainsmith"])
        if "model_chainsmith_fallback" in ll:
            llm.model_chainsmith_fallback = str(ll["model_chainsmith_fallback"])
        if "model_adjudicator" in ll:
            llm.model_adjudicator = str(ll["model_adjudicator"])
        if "model_triage" in ll:
            llm.model_triage = str(ll["model_triage"])

    if "workspace" in data and data["workspace"]:
        cfg.workspace = Path(str(data["workspace"]))

    if "paths" in data and isinstance(data["paths"], dict):
        p = data["paths"]
        pc = cfg.paths
        # `paths.db_path` was removed in 57.1a; route the legacy key to the
        # live setting so an old config file still parses. Workspace rooting
        # below overrides it either way.
        if "db_path" in p:
            cfg.storage.db_path = Path(p["db_path"])
        if "attack_patterns" in p:
            pc.attack_patterns = Path(p["attack_patterns"])
        if "hallucinations" in p:
            pc.hallucinations = Path(p["hallucinations"])

    if "storage" in data and isinstance(data["storage"], dict):
        st = data["storage"]
        stc = cfg.storage
        if "backend" in st:
            stc.backend = str(st["backend"])
        if "db_path" in st or "sqlite" in st:
            # Support both storage.db_path and storage.sqlite.path
            if "db_path" in st:
                stc.db_path = Path(st["db_path"])
            elif isinstance(st["sqlite"], dict) and "path" in st["sqlite"]:
                stc.db_path = Path(st["sqlite"]["path"])
        if "postgresql" in st and isinstance(st["postgresql"], dict):
            if "url" in st["postgresql"]:
                stc.postgresql_url = str(st["postgresql"]["url"])
        if "postgresql_url" in st:
            stc.postgresql_url = str(st["postgresql_url"])
        if "auto_persist" in st:
            stc.auto_persist = bool(st["auto_persist"])
        if "retention_days" in st:
            stc.retention_days = int(st["retention_days"])

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

    # scan_analysis_advisor YAML block removed in 56.11 — the post-scan advisor
    # reads its knobs from app/advisors/scan_analysis/config.yaml now.
    # adjudicator / triage / researcher YAML blocks removed in 56.10c — those
    # agents read their knobs from app/agents/<name>/config.yaml now.

    # check_proof_advisor YAML block removed in 56.11 — reads from
    # app/advisors/check_proof/config.yaml now.

    # coach YAML block removed in 56.10c — read from app/agents/coach/config.yaml.

    if "concurrency" in data and isinstance(data["concurrency"], dict):
        cc = data["concurrency"]
        ccc = cfg.concurrency
        if "max_concurrent_scans" in cc:
            ccc.max_concurrent_scans = int(cc["max_concurrent_scans"])
        if "retry_after_seconds" in cc:
            ccc.retry_after_seconds = int(cc["retry_after_seconds"])
        if "completed_scan_ttl_seconds" in cc:
            ccc.completed_scan_ttl_seconds = int(cc["completed_scan_ttl_seconds"])
        if "rate_limit_scope" in cc:
            ccc.rate_limit_scope = str(cc["rate_limit_scope"])

    if "scan_stream" in data and isinstance(data["scan_stream"], dict):
        ss = data["scan_stream"]
        if "enabled" in ss:
            cfg.scan_stream.enabled = bool(ss["enabled"])


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
    if v := env.get("LITELLM_MODEL_VERIFIER") or env.get("CHAINSMITH_LITELLM_MODEL_VERIFIER"):
        cfg.litellm.model_verifier = v
    if v := env.get("LITELLM_MODEL_CHAINSMITH") or env.get("CHAINSMITH_LITELLM_MODEL_CHAINSMITH"):
        cfg.litellm.model_chainsmith = v
    if v := env.get("LITELLM_MODEL_CHAINSMITH_FALLBACK") or env.get(
        "CHAINSMITH_LITELLM_MODEL_CHAINSMITH_FALLBACK"
    ):
        cfg.litellm.model_chainsmith_fallback = v
    if v := env.get("LITELLM_MODEL_ADJUDICATOR") or env.get("CHAINSMITH_LITELLM_MODEL_ADJUDICATOR"):
        cfg.litellm.model_adjudicator = v
    if v := env.get("LITELLM_MODEL_TRIAGE") or env.get("CHAINSMITH_LITELLM_MODEL_TRIAGE"):
        cfg.litellm.model_triage = v

    # Paths overrides (backward-compatible names kept).
    # RECON_DB_PATH / CHAINSMITH_DB_PATH still parse, but workspace rooting in
    # load_config() overrides them — app.workspace.legacy_conflicts() reports
    # the disagreement rather than letting a database land outside its
    # workspace.
    if v := env.get("RECON_DB_PATH") or env.get("CHAINSMITH_DB_PATH"):
        cfg.storage.db_path = Path(v)
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

    # Scan analysis advisor env overrides removed in 56.11 — knobs live in
    # app/advisors/scan_analysis/config.yaml now (the CHAINSMITH_SCAN_ANALYSIS_ADVISOR_*
    # / CHAINSMITH_SCAN_ADVISOR_* vars are no longer read).

    # Swarm overrides
    if v := env.get("CHAINSMITH_SWARM_ENABLED"):
        cfg.swarm.enabled = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_SWARM_DEFAULT_RATE_LIMIT"):
        with contextlib.suppress(ValueError):
            cfg.swarm.default_rate_limit = float(v)
    if v := env.get("CHAINSMITH_SWARM_TASK_TIMEOUT"):
        with contextlib.suppress(ValueError):
            cfg.swarm.task_timeout_seconds = int(v)

    # Adjudicator / Triage / Researcher env overrides moved to the agent
    # registry's legacy back-compat shim in 56.10c (app/agents/registry.py).
    # CHAINSMITH_ADJUDICATOR_ENABLED / CHAINSMITH_TRIAGE_ENABLED /
    # CHAINSMITH_RESEARCHER_ENABLED / CHAINSMITH_RESEARCHER_OFFLINE still work.

    # CheckProofAdvisor env override removed in 56.11 — knobs live in
    # app/advisors/check_proof/config.yaml now.

    # Scan stream (SSE) overrides
    if v := env.get("CHAINSMITH_SCAN_STREAM_ENABLED"):
        cfg.scan_stream.enabled = v.lower() in ("true", "1", "yes")

    # Coach env overrides moved to the agent registry's legacy back-compat shim
    # in 56.10c. CHAINSMITH_COACH_ENABLED / CHAINSMITH_COACH_MEMORY_CAP still work.


def load_config(config_path: Path | None = None) -> ChainsmithConfig:
    """
    Build a ChainsmithConfig from the layered sources:
      defaults → YAML file → env vars → workspace rooting
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
    _apply_workspace(cfg)

    return cfg


def _apply_workspace(cfg: ChainsmithConfig) -> None:
    """
    Root the storage paths off the workspace.

    Runs last because the workspace wins: a legacy `storage.db_path` or
    `RECON_DB_PATH` that disagrees would put the database outside the workspace
    and defeat the physical separation workspaces exist to provide. The
    disagreement is reported by `app.workspace.legacy_conflicts()` at startup
    rather than silently applied.

    SQLite only — a `postgresql` backend has no file path to root, so its
    workspace still owns evidence, reports, and logs while the database lives
    wherever `postgresql_url` points.
    """
    from app import workspace as ws

    # An entry point that already chose a workspace wins. Without this, the
    # first get_config() after `chainsmith --workspace ~/clients/acme` would
    # re-resolve from env/default and silently discard the flag — the operator
    # would be told one workspace and scanned into another.
    resolved = ws.active()
    if resolved is None:
        resolved, _source = ws.resolve(explicit=cfg.workspace)
        ws.set_workspace(resolved)

    cfg.workspace = resolved.root

    if cfg.storage.backend == "sqlite":
        cfg.storage.db_path = resolved.db_path


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
        "RECON_DB_PATH": lambda c: c.storage.db_path,
        "LITELLM_BASE_URL": lambda c: c.litellm.base_url,
        "LITELLM_MODEL_VERIFIER": lambda c: c.litellm.model_verifier,
        "LITELLM_MODEL_CHAINSMITH": lambda c: c.litellm.model_chainsmith,
        "LITELLM_MODEL_CHAINSMITH_FALLBACK": lambda c: c.litellm.model_chainsmith_fallback,
        "LITELLM_MODEL_ADJUDICATOR": lambda c: c.litellm.model_adjudicator,
        "LITELLM_MODEL_TRIAGE": lambda c: c.litellm.model_triage,
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
