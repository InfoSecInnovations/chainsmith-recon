"""
app/agents/base.py - BaseAgent.

The per-type base for `agent` components, attaching to the minimal
`BaseComponent` (identity + construction contract).

Agents diverge from checks in *construction*. A check is a no-arg startup
singleton built by `discover_components` via `cls()` + attribute assignment. An
agent needs a runtime `LLMClient` and an optional **per-session**
`event_callback`, and is built **per request/session** — so a shared startup
singleton would cross-wire callbacks between concurrent sessions.

So agents are discovered as *specs* (`app/agents/registry.py`) and constructed
on demand through `from_spec()`, which injects the runtime deps and applies the
load-time config baseline. The check loader's no-arg `from_config()` is not used
for agents; calling it raises (inherited from `BaseComponent`).
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING

from app.components.base import BaseComponent

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from app.components.config_models import ComponentConfig
    from app.components.contracts import AgentContract
    from app.lib.llm import LLMClient
    from app.models import AgentEvent


class BaseAgent(BaseComponent):
    """Common ancestor for agent components; adds the `from_spec()` factory.

    Subclasses keep their existing `__init__(self, client, event_callback=None,
    ...)` signature — `from_spec()` calls it with the injected runtime deps, then
    stamps identity + the config baseline by attribute assignment (mirroring how
    `BaseCheck.from_config()` applies config to a check).
    """

    component_type: str = "agent"
    role: str = ""
    enabled: bool = True

    @classmethod
    def from_spec(
        cls,
        contract: AgentContract,
        config: ComponentConfig,
        *,
        client: LLMClient,
        event_callback: Callable[[AgentEvent], Awaitable[None]] | None = None,
        **ctor_knobs,
    ) -> BaseAgent:
        """Build an agent instance from its discovered spec + injected runtime deps.

        `client` and `event_callback` are runtime (per request/session) and come
        from the caller; identity and the `enabled` baseline come from the
        contract/config.

        Construction knobs live in `config.yaml`'s `parameters` (56.10c). We
        forward the subset the subclass `__init__` actually accepts — e.g. the
        coach's `memory_cap`, the researcher's `offline_mode` — and skip
        engine-glue params (the adjudicator/triage `context_file`, triage
        `kb_path`) that are read elsewhere via the registry accessor. An explicit
        `**ctor_knobs` from the caller wins over the config value, so a caller
        can still override per-call through `AgentRegistry.create(...)`.
        """
        accepted = set(inspect.signature(cls.__init__).parameters)
        ctor_params = {k: v for k, v in config.parameters.items() if k in accepted}
        ctor_params.update(ctor_knobs)  # explicit caller knobs win over config
        instance = cls(client=client, event_callback=event_callback, **ctor_params)
        instance.id = str(contract.id)
        instance.name = contract.name
        instance.component_type = "agent"
        instance.role = contract.role
        instance.enabled = config.enabled
        return instance
