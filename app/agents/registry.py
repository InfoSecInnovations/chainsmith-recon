"""
app/agents/registry.py - Agent discovery + factory.

The check loader (`discover_components`) builds no-arg startup singletons and
returns *instances*. Agents can't use that path: they need a runtime
`LLMClient` and a per-session `event_callback`, and are built per
request/session (see `app/agents/base.py`). So discovery here returns *specs*
(contract + resolved config + entry class), and a thin factory constructs
instances on demand:

    AGENTS = discover_agent_specs()                 # registry of specs
    agent = AGENTS.create("adjudicator",            # built per request/session
                          client=get_llm_client(),
                          event_callback=session_cb)

It reuses the shared `verify_contracts()` gate and the loader's path helpers, so
agent folders are held to the same identity/placement invariants as checks.
"""

from __future__ import annotations

import importlib
import logging
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from app.component_loader import (
    ComponentLoadError,
    _module_for,
    parse_entry,
    verify_contracts,
)
from app.components.config_models import ComponentConfig
from app.components.contracts import AgentContract

if TYPE_CHECKING:
    from app.agents.base import BaseAgent

logger = logging.getLogger(__name__)

# The agent type root — this package. Discovery walks it for `contract.yaml`.
AGENTS_ROOT = Path(__file__).resolve().parent


def _coerce_bool(v: str) -> bool:
    return v.lower() in ("true", "1", "yes")


# Legacy `CHAINSMITH_<AGENT>_<KNOB>` env back-compat (pre-56.10c, when these
# knobs lived on ChainsmithConfig). Maps each agent to {env_var: (target,
# caster)}; target "enabled" overrides `ComponentConfig.enabled`, anything else
# is a `parameters` key. Applied at discovery so a disabled agent is skipped
# before it's added to the registry — keeping config.yaml the single source of
# truth while honoring the old env vars (operator decision, 56.10c).
_LEGACY_AGENT_ENV: dict[str, dict[str, tuple[str, Callable[[str], object]]]] = {
    "adjudicator": {"CHAINSMITH_ADJUDICATOR_ENABLED": ("enabled", _coerce_bool)},
    "triage": {"CHAINSMITH_TRIAGE_ENABLED": ("enabled", _coerce_bool)},
    "researcher": {
        "CHAINSMITH_RESEARCHER_ENABLED": ("enabled", _coerce_bool),
        "CHAINSMITH_RESEARCHER_OFFLINE": ("offline_mode", _coerce_bool),
    },
    "coach": {
        "CHAINSMITH_COACH_ENABLED": ("enabled", _coerce_bool),
        "CHAINSMITH_COACH_MEMORY_CAP": ("memory_cap", int),
    },
}


def _apply_legacy_env(
    name: str, config: ComponentConfig, env: Mapping[str, str]
) -> ComponentConfig:
    """Return `config` with legacy env overrides applied (no-op if none set)."""
    overrides = _LEGACY_AGENT_ENV.get(name)
    if not overrides:
        return config

    enabled = config.enabled
    params = dict(config.parameters)
    for var, (target, caster) in overrides.items():
        raw = env.get(var)
        if raw is None:
            continue
        try:
            value = caster(raw)
        except (TypeError, ValueError):
            logger.warning("Ignoring env %s=%r: not coercible", var, raw)
            continue
        if target == "enabled":
            enabled = bool(value)
        else:
            params[target] = value

    if enabled == config.enabled and params == config.parameters:
        return config
    return config.model_copy(update={"enabled": enabled, "parameters": params})


@dataclass(frozen=True)
class AgentSpec:
    """A discovered, validated agent ready to construct on demand.

    Holds everything the factory needs except the runtime deps (client,
    event_callback), which the caller supplies to `create()`.
    """

    contract: AgentContract
    config: ComponentConfig
    entry_cls: type[BaseAgent]

    def create(self, **runtime_deps) -> BaseAgent:
        """Construct an instance, injecting runtime deps via `from_spec()`."""
        return self.entry_cls.from_spec(self.contract, self.config, **runtime_deps)


class AgentRegistry:
    """Name → `AgentSpec` lookup with a per-request construction factory."""

    def __init__(self, specs: dict[str, AgentSpec]):
        self._specs: dict[str, AgentSpec] = dict(specs)

    def __contains__(self, name: str) -> bool:
        return name in self._specs

    def names(self) -> list[str]:
        return sorted(self._specs)

    def spec(self, name: str) -> AgentSpec:
        return self._specs[name]

    def param(self, name: str, key: str, default: object = None) -> object:
        """Read a resolved `config.yaml` parameter for an agent.

        Used by engine glue (e.g. load_operator_context / load_team_context /
        load_remediation_kb) to reach the agent's path knobs without
        constructing the agent. Returns `default` if the agent is absent
        (disabled / unknown) or the key is unset.
        """
        spec = self._specs.get(name)
        if spec is None:
            return default
        return spec.config.parameters.get(key, default)

    def create(self, name: str, **runtime_deps) -> BaseAgent:
        """Build the named agent, injecting the supplied runtime deps."""
        if name not in self._specs:
            raise KeyError(f"no agent component named {name!r}; have {self.names()}")
        return self._specs[name].create(**runtime_deps)


def discover_agent_specs(root: Path = AGENTS_ROOT) -> AgentRegistry:
    """Walk `root` for agent `contract.yaml` folders and return a registry.

    Validates with the shared `verify_contracts()` (raises `ComponentLoadError`
    on any violation), then parses each contract/config and resolves the entry
    class — but does NOT instantiate (agents are built per request via the
    factory). Disabled components (`config.yaml: enabled: false`) are skipped.
    """
    root = Path(root)
    violations = verify_contracts(root, "agent")
    if violations:
        raise ComponentLoadError(violations)

    specs: dict[str, AgentSpec] = {}
    for contract_path in sorted(root.rglob("contract.yaml")):
        comp_dir = contract_path.parent
        contract = AgentContract(**yaml.safe_load(contract_path.read_text(encoding="utf-8")))

        cfg_path = comp_dir / "config.yaml"
        if cfg_path.exists():
            config = ComponentConfig(**(yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}))
        else:
            config = ComponentConfig()
        config = _apply_legacy_env(contract.name, config, os.environ)
        if not config.enabled:
            logger.info("Skipping disabled agent: %s", contract.name)
            continue

        filename, class_name = parse_entry(contract.entry)
        module = importlib.import_module(_module_for(comp_dir, filename))
        entry_cls = getattr(module, class_name)
        specs[contract.name] = AgentSpec(contract, config, entry_cls)

    logger.info("Discovered %d agent component(s)", len(specs))
    return AgentRegistry(specs)


_registry: AgentRegistry | None = None


def get_agent_registry() -> AgentRegistry:
    """Process-wide cached agent registry (discovered once, on first use)."""
    global _registry
    if _registry is None:
        _registry = discover_agent_specs()
    return _registry
