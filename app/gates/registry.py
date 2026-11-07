"""app/gates/registry.py - Gate discovery + config accessor.

Gates are deterministic and caller-constructed (see `app/gates/base.py`), so —
exactly like `app/advisors/registry.py` — this is NOT a factory like
`app/agents/registry.py`: there is no `.create()`. Discovery returns *specs*
(contract + resolved config + entry class) purely so call sites can answer two
questions before they build the gate themselves:

    reg = get_gate_registry()
    cfg = reg.config("guardian")        # resolved config.yaml (enabled + parameters)
    cls = reg.entry_cls("guardian")     # the gate class to construct

It reuses the shared `verify_contracts()` gate and the loader's path helpers, so
gate folders are held to the same identity/placement invariants as checks,
agents, and advisors.

Like the advisor registry (and unlike the agent registry), **disabled gates are
still discovered** (not skipped). `enabled` is data the introspection routes
report and the scan path gates on per-call — not a visibility switch.
"""

from __future__ import annotations

import importlib
import logging
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
from app.components.contracts import GateContract

if TYPE_CHECKING:
    from app.gates.base import BaseGate

logger = logging.getLogger(__name__)

# The gate type root — this package. Discovery walks it for `contract.yaml`.
GATES_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class GateSpec:
    """A discovered, validated gate: identity + resolved config + entry class.

    Holds no runtime deps — gates are constructed by their call site, which
    passes the per-scan scope data directly to the entry class.
    """

    contract: GateContract
    config: ComponentConfig
    entry_cls: type[BaseGate]


class GateRegistry:
    """Name → `GateSpec` lookup. A read-only config/discovery accessor.

    No construction factory: gates are built by their call site (the scan
    route / scanner / launcher) with per-scan scope data. This registry only
    resolves identity and `config.yaml`.
    """

    def __init__(self, specs: dict[str, GateSpec]):
        self._specs: dict[str, GateSpec] = dict(specs)

    def __contains__(self, name: str) -> bool:
        return name in self._specs

    def names(self) -> list[str]:
        return sorted(self._specs)

    def get(self, name: str) -> GateSpec:
        return self._specs[name]

    def config(self, name: str) -> ComponentConfig:
        """Resolved `config.yaml` (enabled + parameters) for a gate."""
        return self._specs[name].config

    def entry_cls(self, name: str) -> type[BaseGate]:
        """The gate class to construct at the call site."""
        return self._specs[name].entry_cls

    def param(self, name: str, key: str, default: object = None) -> object:
        """Read a resolved `config.yaml` parameter; `default` if absent."""
        spec = self._specs.get(name)
        if spec is None:
            return default
        return spec.config.parameters.get(key, default)


def discover_gate_specs(root: Path = GATES_ROOT) -> GateRegistry:
    """Walk `root` for gate `contract.yaml` folders and return a registry.

    Validates with the shared `verify_contracts()` (raises `ComponentLoadError`
    on any violation), parses each contract/config, and resolves the entry class
    — but does NOT instantiate (gates are built by their call site) and does NOT
    skip disabled gates (their config must stay introspectable).
    """
    root = Path(root)
    violations = verify_contracts(root, "gate")
    if violations:
        raise ComponentLoadError(violations)

    specs: dict[str, GateSpec] = {}
    for contract_path in sorted(root.rglob("contract.yaml")):
        comp_dir = contract_path.parent
        contract = GateContract(**yaml.safe_load(contract_path.read_text(encoding="utf-8")))

        cfg_path = comp_dir / "config.yaml"
        if cfg_path.exists():
            config = ComponentConfig(**(yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}))
        else:
            config = ComponentConfig()

        filename, class_name = parse_entry(contract.entry)
        module = importlib.import_module(_module_for(comp_dir, filename))
        entry_cls = getattr(module, class_name)
        specs[contract.name] = GateSpec(contract, config, entry_cls)

    logger.info("Discovered %d gate component(s)", len(specs))
    return GateRegistry(specs)


_registry: GateRegistry | None = None


def get_gate_registry() -> GateRegistry:
    """Process-wide cached gate registry (discovered once, on first use)."""
    global _registry
    if _registry is None:
        _registry = discover_gate_specs()
    return _registry
