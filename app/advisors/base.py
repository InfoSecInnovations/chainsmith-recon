"""app/advisors/base.py - BaseAdvisor.

The per-type base for `advisor` components, attaching to the minimal
`BaseComponent` (identity only).

Advisors are DETERMINISTIC, rule-based, narrowly-scoped analysis components:
they read completed pipeline state and emit recommendations, never blocking and
never calling an LLM. In that they sit alongside checks, not agents.

But they are constructed by neither path. A check is a no-arg startup singleton
built by `discover_components` via `cls()`. An agent is built by a
dependency-injecting factory (`from_spec` injects an `LLMClient`). An advisor is
built by its **call site** — the scan path or a route — which already holds the
per-call data the constructor needs (launcher state, request scope). So there is
deliberately **no `from_spec()` factory and no config-injection method here**:
`app/advisors/registry.py` discovers advisor *specs* for identity + config
resolution only, and the call site does the construction.

`BaseAdvisor` is therefore just a marker: it stamps `component_type` and gives
discovery an `issubclass()` sanity check, keeping advisors uniform with
`BaseCheck`/`BaseAgent` in the tree without importing the agent DI machinery.
"""

from __future__ import annotations

from app.components.base import BaseComponent


class BaseAdvisor(BaseComponent):
    """Marker base for advisor components — identity/type only, no factory.

    Subclasses keep their existing `__init__(self, ...)` signature and are
    constructed directly by their call site. Identity lives on the discovered
    contract (via the registry), not on the instance, so no `from_spec`/
    `from_config` is provided.
    """

    component_type: str = "advisor"
    enabled: bool = True
