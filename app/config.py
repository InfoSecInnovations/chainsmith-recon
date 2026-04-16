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
class ScanAnalysisAdvisorConfig:
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
class AdjudicatorConfig:
    enabled: bool = True
    context_file: str = "~/.chainsmith/adjudicator_context.yaml"


@dataclass
class TriageConfig:
    enabled: bool = True
    context_file: str = "~/.chainsmith/triage_context.yaml"
    kb_path: str = "app/data/remediation_guidance.json"


@dataclass
class ResearcherConfig:
    enabled: bool = True
    offline_mode: bool = False
    data_sources: list[str] = field(
        default_factory=lambda: ["nvd", "exploitdb", "vendor_advisories"]
    )


@dataclass
class CheckProofAdvisorConfig:
    enabled: bool = True
    trigger: str = "operator_selected"  # operator_selected | auto_verified
    include_commands: bool = True
    include_screenshots: bool = True
    template_dir: str = "app/data/proof_templates/"


@dataclass
class CoachConfig:
    enabled: bool = True
    context_window: str = "summary"  # summary | full
    max_recent_events: int = 50
    memory_cap: int = 10


@dataclass
class ConcurrencyConfig:
    """
    Concurrent-scan limits.

    Introduced in the concurrent-scans overhaul (Phase A). Values are parsed
    and surfaced here but not yet enforced — Phase C flips enforcement on.
    """

    max_concurrent_scans: int = 4
    completed_scan_ttl_seconds: int = 300
    rate_limit_scope: str = "per_scan"  # "per_scan" | "global"


@dataclass
class ScanStreamConfig:
    """Phase 51.4 — gates advertisement of the SSE streaming capability."""

    enabled: bool = False


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
    scan_analysis_advisor: ScanAnalysisAdvisorConfig = field(
        default_factory=ScanAnalysisAdvisorConfig
    )
    adjudicator: AdjudicatorConfig = field(default_factory=AdjudicatorConfig)
    triage: TriageConfig = field(default_factory=TriageConfig)
    researcher: ResearcherConfig = field(default_factory=ResearcherConfig)
    check_proof_advisor: CheckProofAdvisorConfig = field(default_factory=CheckProofAdvisorConfig)
    coach: CoachConfig = field(default_factory=CoachConfig)
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

    # Support both old "scan_advisor" and new "scan_analysis_advisor" YAML keys
    sa_data = data.get("scan_analysis_advisor") or data.get("scan_advisor")
    if sa_data and isinstance(sa_data, dict):
        sa = sa_data
        sac = cfg.scan_analysis_advisor
        if "enabled" in sa:
            sac.enabled = bool(sa["enabled"])
        if "mode" in sa:
            sac.mode = str(sa["mode"])
        if "auto_seed_urls" in sa:
            sac.auto_seed_urls = bool(sa["auto_seed_urls"])
        if "require_approval" in sa:
            sac.require_approval = bool(sa["require_approval"])

    if "adjudicator" in data and isinstance(data["adjudicator"], dict):
        adj = data["adjudicator"]
        adjc = cfg.adjudicator
        if "enabled" in adj:
            adjc.enabled = bool(adj["enabled"])
        if "context_file" in adj:
            adjc.context_file = str(adj["context_file"])

    if "triage" in data and isinstance(data["triage"], dict):
        tr = data["triage"]
        trc = cfg.triage
        if "enabled" in tr:
            trc.enabled = bool(tr["enabled"])
        if "context_file" in tr:
            trc.context_file = str(tr["context_file"])
        if "kb_path" in tr:
            trc.kb_path = str(tr["kb_path"])

    if "researcher" in data and isinstance(data["researcher"], dict):
        res = data["researcher"]
        resc = cfg.researcher
        if "enabled" in res:
            resc.enabled = bool(res["enabled"])
        if "offline_mode" in res:
            resc.offline_mode = bool(res["offline_mode"])
        if "data_sources" in res and isinstance(res["data_sources"], list):
            resc.data_sources = [str(s) for s in res["data_sources"]]

    if "check_proof_advisor" in data and isinstance(data["check_proof_advisor"], dict):
        cpa = data["check_proof_advisor"]
        cpac = cfg.check_proof_advisor
        if "enabled" in cpa:
            cpac.enabled = bool(cpa["enabled"])
        if "trigger" in cpa:
            cpac.trigger = str(cpa["trigger"])
        if "include_commands" in cpa:
            cpac.include_commands = bool(cpa["include_commands"])
        if "include_screenshots" in cpa:
            cpac.include_screenshots = bool(cpa["include_screenshots"])
        if "template_dir" in cpa:
            cpac.template_dir = str(cpa["template_dir"])

    if "coach" in data and isinstance(data["coach"], dict):
        co = data["coach"]
        coc = cfg.coach
        if "enabled" in co:
            coc.enabled = bool(co["enabled"])
        if "context_window" in co:
            coc.context_window = str(co["context_window"])
        if "max_recent_events" in co:
            coc.max_recent_events = int(co["max_recent_events"])
        if "memory_cap" in co:
            coc.memory_cap = int(co["memory_cap"])

    if "concurrency" in data and isinstance(data["concurrency"], dict):
        cc = data["concurrency"]
        ccc = cfg.concurrency
        if "max_concurrent_scans" in cc:
            ccc.max_concurrent_scans = int(cc["max_concurrent_scans"])
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

    # Paths overrides (backward-compatible names kept)
    if v := env.get("RECON_DB_PATH") or env.get("CHAINSMITH_DB_PATH"):
        cfg.paths.db_path = Path(v)
        cfg.storage.db_path = Path(v)  # Ensure init_db uses the same path
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

    # Scan analysis advisor overrides (supports old SCAN_ADVISOR prefix too)
    if v := env.get("CHAINSMITH_SCAN_ANALYSIS_ADVISOR_ENABLED") or env.get(
        "CHAINSMITH_SCAN_ADVISOR_ENABLED"
    ):
        cfg.scan_analysis_advisor.enabled = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_SCAN_ANALYSIS_ADVISOR_MODE") or env.get(
        "CHAINSMITH_SCAN_ADVISOR_MODE"
    ):
        cfg.scan_analysis_advisor.mode = v
    if v := env.get("CHAINSMITH_SCAN_ANALYSIS_ADVISOR_AUTO_SEED_URLS") or env.get(
        "CHAINSMITH_SCAN_ADVISOR_AUTO_SEED_URLS"
    ):
        cfg.scan_analysis_advisor.auto_seed_urls = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_SCAN_ANALYSIS_ADVISOR_REQUIRE_APPROVAL") or env.get(
        "CHAINSMITH_SCAN_ADVISOR_REQUIRE_APPROVAL"
    ):
        cfg.scan_analysis_advisor.require_approval = v.lower() in ("true", "1", "yes")

    # Swarm overrides
    if v := env.get("CHAINSMITH_SWARM_ENABLED"):
        cfg.swarm.enabled = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_SWARM_DEFAULT_RATE_LIMIT"):
        with contextlib.suppress(ValueError):
            cfg.swarm.default_rate_limit = float(v)
    if v := env.get("CHAINSMITH_SWARM_TASK_TIMEOUT"):
        with contextlib.suppress(ValueError):
            cfg.swarm.task_timeout_seconds = int(v)

    # Adjudicator overrides
    if v := env.get("CHAINSMITH_ADJUDICATOR_ENABLED"):
        cfg.adjudicator.enabled = v.lower() in ("true", "1", "yes")

    # Triage overrides
    if v := env.get("CHAINSMITH_TRIAGE_ENABLED"):
        cfg.triage.enabled = v.lower() in ("true", "1", "yes")

    # Researcher overrides
    if v := env.get("CHAINSMITH_RESEARCHER_ENABLED"):
        cfg.researcher.enabled = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_RESEARCHER_OFFLINE"):
        cfg.researcher.offline_mode = v.lower() in ("true", "1", "yes")

    # CheckProofAdvisor overrides
    if v := env.get("CHAINSMITH_CHECK_PROOF_ADVISOR_ENABLED"):
        cfg.check_proof_advisor.enabled = v.lower() in ("true", "1", "yes")

    # Scan stream (SSE) overrides
    if v := env.get("CHAINSMITH_SCAN_STREAM_ENABLED"):
        cfg.scan_stream.enabled = v.lower() in ("true", "1", "yes")

    # Coach overrides
    if v := env.get("CHAINSMITH_COACH_ENABLED"):
        cfg.coach.enabled = v.lower() in ("true", "1", "yes")
    if v := env.get("CHAINSMITH_COACH_MEMORY_CAP"):
        with contextlib.suppress(ValueError):
            cfg.coach.memory_cap = int(v)


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
