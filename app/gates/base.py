"""app/gates/base.py - BaseGate.

The per-type base for `gate` components, attaching to the minimal
`BaseComponent` (identity only).

Gates are DETERMINISTIC allow/block authorities: they answer "may this
proceed?" at the scan chokepoint — never calling
an LLM, never recommending (that's an advisor), but *deciding*. In that they
sit alongside checks and advisors, not agents.

Like an advisor, a gate is constructed by neither the loader nor a factory but
by its **call site** — the scan route / scanner / launcher build a `Guardian`
per scan via `from_scope(...)` with the operator's scope, which is per-call
data they already hold. So there is deliberately **no `from_spec()` factory and
no config-injection method here**: `app/gates/registry.py` discovers gate
*specs* for identity + config resolution only, and the call site does the
construction.

`BaseGate` is therefore just a marker: it stamps `component_type` and gives
discovery an `issubclass()` sanity check, keeping gates uniform with
`BaseCheck`/`BaseAgent`/`BaseAdvisor` in the tree without importing the agent DI
machinery.
"""

from __future__ import annotations

from app.components.base import BaseComponent


class BaseGate(BaseComponent):
    """Marker base for gate components — identity/type only, no factory.

    Subclasses keep their existing `__init__(self, ...)` signature and are
    constructed directly by their call site. Identity lives on the discovered
    contract (via the registry), not on the instance, so no `from_spec`/
    `from_config` is provided.
    """

    component_type: str = "gate"
    enabled: bool = True
