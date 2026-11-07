"""
app/components/base.py - Minimal BaseComponent.

`BaseComponent` is the thin common ancestor of all four component types
(check/agent/advisor/gate). It holds only what the loader touches uniformly:
identity (`id`/`name`/`component_type`) and the `from_config()` construction
contract.

It is deliberately minimal. The rich per-type bases
(`BaseCheck`/`BaseAgent`/`BaseAdvisor`/`BaseGate`) attach as their phases land
(56.10-56.12), so the abstraction grows from real implementations rather than
being guessed up front. `BaseCheck` (app/checks/base.py) is its first subclass.

Construction is no-arg: `from_config()` builds the instance via `cls()` — exactly
how `get_real_checks()` instantiates checks today — then applies the resolved
load-time config baseline (§5.1 layers 1-5) by attribute assignment. An
auto-discovered component must therefore be no-arg constructible;
`verify_contracts()` AST-asserts this on every `entry` class (§8.6).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.components.config_models import ResolvedConfig
    from app.components.contracts import BaseModel


class BaseComponent:
    """Thin common ancestor; identity + the `from_config()` contract only."""

    # ─── Identity (set authoritatively from the contract at load) ───
    id: str = ""
    name: str = ""
    component_type: str = ""

    @classmethod
    def from_config(cls, contract: BaseModel, config: ResolvedConfig) -> BaseComponent:
        """Construct a component instance from its parsed contract + resolved config.

        Subclasses implement the type-specific attribute application. The base
        contract: build via no-arg `cls()`, then apply identity from `contract`
        and the load-time config baseline from `config`.
        """
        raise NotImplementedError(
            f"{cls.__name__} must implement from_config() (BaseComponent contract, §6)"
        )
