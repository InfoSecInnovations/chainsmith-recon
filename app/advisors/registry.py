"""app/advisors/registry.py - Advisor discovery + config accessor.

Advisors are deterministic and caller-constructed (see `app/advisors/base.py`),
so this is NOT a factory like `app/agents/registry.py` — there is no `.create()`.
Discovery returns *specs* (contract + resolved config + entry class) purely so
call sites can answer two questions before they build the advisor themselves:

    reg = get_advisor_registry()
    cfg = reg.config("scan_analysis")        # resolved config.yaml (enabled + parameters)
    cls = reg.entry_cls("scan_analysis")     # the advisor class to construct

It reuses the shared `verify_contracts()` gate and the loader's path helpers, so
advisor folders are held to the same identity/placement invariants as checks and
agents.

Unlike the agent registry, **disabled advisors are still discovered** (not
skipped). `enabled` is data the introspection routes report and the scan path
gates on per-call — not a visibility switch — so e.g. the default-disabled
`scan_analysis` must remain readable via `reg.config("scan_analysis").enabled`.
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
from app.components.contracts import AdvisorContract

if TYPE_CHECKING:
    from app.advisors.base import BaseAdvisor

logger = logging.getLogger(__name__)

# The advisor type root — this package. Discovery walks it for `contract.yaml`.
ADVISORS_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class AdvisorSpec:
    """A discovered, validated advisor: identity + resolved config + entry class.

    Holds no runtime deps — advisors are constructed by their call site, which
    passes the per-call data directly to the entry class.
    """

    contract: AdvisorContract
    config: ComponentConfig
    entry_cls: type[BaseAdvisor]


class AdvisorRegistry:
    """Name → `AdvisorSpec` lookup. A read-only config/discovery accessor.

    No construction factory: advisors are built by their call site (the scan
    path or a route) with per-call data. This registry only resolves identity
    and `config.yaml`.
    """

    def __init__(self, specs: dict[str, AdvisorSpec]):
        self._specs: dict[str, AdvisorSpec] = dict(specs)

    def __contains__(self, name: str) -> bool:
        return name in self._specs

    def names(self) -> list[str]:
        return sorted(self._specs)

    def get(self, name: str) -> AdvisorSpec:
        return self._specs[name]

    def config(self, name: str) -> ComponentConfig:
        """Resolved `config.yaml` (enabled + parameters) for an advisor."""
        return self._specs[name].config

    def entry_cls(self, name: str) -> type[BaseAdvisor]:
        """The advisor class to construct at the call site."""
        return self._specs[name].entry_cls

    def param(self, name: str, key: str, default: object = None) -> object:
        """Read a resolved `config.yaml` parameter; `default` if absent."""
        spec = self._specs.get(name)
        if spec is None:
            return default
        return spec.config.parameters.get(key, default)


def discover_advisor_specs(root: Path = ADVISORS_ROOT) -> AdvisorRegistry:
    """Walk `root` for advisor `contract.yaml` folders and return a registry.

    Validates with the shared `verify_contracts()` (raises `ComponentLoadError`
    on any violation), parses each contract/config, and resolves the entry class
    — but does NOT instantiate (advisors are built by their call site) and does
    NOT skip disabled advisors (their config must stay introspectable).
    """
    root = Path(root)
    violations = verify_contracts(root, "advisor")
    if violations:
        raise ComponentLoadError(violations)

    specs: dict[str, AdvisorSpec] = {}
    for contract_path in sorted(root.rglob("contract.yaml")):
        comp_dir = contract_path.parent
        contract = AdvisorContract(**yaml.safe_load(contract_path.read_text(encoding="utf-8")))

        cfg_path = comp_dir / "config.yaml"
        if cfg_path.exists():
            config = ComponentConfig(**(yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}))
        else:
            config = ComponentConfig()

        filename, class_name = parse_entry(contract.entry)
        module = importlib.import_module(_module_for(comp_dir, filename))
        entry_cls = getattr(module, class_name)
        specs[contract.name] = AdvisorSpec(contract, config, entry_cls)

    logger.info("Discovered %d advisor component(s)", len(specs))
    return AdvisorRegistry(specs)


_registry: AdvisorRegistry | None = None


def get_advisor_registry() -> AdvisorRegistry:
    """Process-wide cached advisor registry (discovered once, on first use)."""
    global _registry
    if _registry is None:
        _registry = discover_advisor_specs()
    return _registry
