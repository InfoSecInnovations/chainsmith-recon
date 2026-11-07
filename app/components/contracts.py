"""
app/components/contracts.py - The authoritative `contract.yaml` schema.

The loader parses `contract.yaml` into these Pydantic v2 models
(`CheckContract(**yaml_data)`), so required/optional fields, types, enums, and
UUID format are declared once, here, in code. The illustrative YAML in the
design doc is generated to match this model and cannot silently drift.

Pydantic at the I/O boundary; the runtime domain objects (e.g. the
`CheckCondition` dataclass in `app/checks/base.py`) are converted from these at
load time. Each `Condition` below mirrors that dataclass.

`check` (56.1-56.9), `agent` (56.10), `advisor` (56.11), and `gate` (56.12) are
all concrete now — sibling models discriminated on `type` (§4.1).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import UUID4, BaseModel, ConfigDict, Field

# Operators accepted on a dependency condition — mirrors CheckCondition.evaluate.
ConditionOperator = Literal["exists", "equals", "contains", "truthy", "gte", "lte"]

# Allowed side-effect tags (§4 / §8.2 import-derived).
SideEffect = Literal["network", "filesystem", "db", "none"]

# The five severity levels, weakest first. Mirrors `SEVERITY_ORDER` in
# `app/reports.py` and `SEVERITY_LEVELS` in `app/db/repositories.py`; declared
# here as a Literal so a typo in a `contract.yaml` is a parse error rather than
# a severity nothing renders.
SeverityLevel = Literal["info", "low", "medium", "high", "critical"]

# Weakest-to-strongest, for the range-containment check in `verify_contracts`.
SEVERITY_ORDER: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

# Which kind of severity a check has (§7). `fixed` is categorical — the answer
# is in the response, and no model is ever called. `contextual` is a continuum
# the evidence places; phase 58 grades it, and until then it falls through to
# rule logic carrying its declared `default:`.
SeverityModel = Literal["fixed", "contextual"]


class SeverityBlock(BaseModel):
    """A check's declared severity model.

    Contract, not config: model, range, rubric and signals are the author's
    statement of what compliance means for their payload, not an operator knob
    — and a mutable rubric would make rubric provenance meaningless. So the
    block lives in `contract.yaml`, with `extra="forbid"` like everything here.

    Two shapes. The cross-field rules ("contextual needs a default", "a fixed
    check has no rubric") are enforced by `verify_contracts` rather than here,
    because an accumulated `Violation` names the folder at fault and reads
    better than a pydantic error thrown mid-parse:

        severity:                       severity:
          model: fixed                    model: contextual
          observations:                   default: medium
            missing-hsts: medium          range: [info, critical]
            weak-csp: high                rubric: |
                                            ...
                                          signals: [reproduction_rate]

    `rubric` and `signals` are **inert until phase 58**. They are declared now
    so an author can write them once, beside the payload they describe.
    """

    model_config = ConfigDict(extra="forbid")

    model: SeverityModel

    #: The provisional severity a candidate carries before a grader places one
    #: (§6.1). Required for `contextual`; optional for `fixed`, whose
    #: `observations` map already supplies one per discriminator.
    default: SeverityLevel | None = None

    #: `fixed` only: discriminator -> severity. This is what makes a fixed
    #: check's provisional severity free (§6.1).
    observations: dict[str, SeverityLevel] = Field(default_factory=dict)

    #: `contextual` only: `[weakest, strongest]` a grader may place.
    range: list[SeverityLevel] = Field(default_factory=list)

    #: `contextual` only. Inert until phase 58.
    rubric: str = ""
    signals: list[str] = Field(default_factory=list)


class Condition(BaseModel):
    """A single dependency condition. Mirrors the runtime `CheckCondition` dataclass.

    Converted to `app.checks.base.CheckCondition` at load (DTO-at-boundary →
    domain-object).
    """

    model_config = ConfigDict(extra="forbid")

    output_name: str
    operator: ConditionOperator = "exists"
    value: Any = None


class CheckContract(BaseModel):
    """Identity + I/O contract for a `check` component (§4).

    The folder name is the canonical slug and must equal `name`
    (enforced by the loader / `verify_contracts`, not here, so a mismatch is
    reported as a structural violation rather than a parse error).
    """

    model_config = ConfigDict(extra="forbid")

    # ─── identity ───────────────────────────────────────────────
    id: UUID4  # assigned once at authorship
    name: str  # slug; must match folder name
    type: Literal["check"] = "check"
    description: str
    entry: str  # "check.py:ClassName"

    # ─── execution wiring ───────────────────────────────────────
    suite: str
    depends_on: list[Condition] = Field(default_factory=list)
    produces: list[str] = Field(default_factory=list)
    # NOTE: no authored `phase`. Execution order is a runtime topological sort
    # over depends_on/produces (check_launcher.py); the UI progress phase is
    # derived from `suite`. A static phase int would be a third, unbacked
    # source of truth (§6, C1).

    # ─── safety / applicability / scheduling ────────────────────
    intrusive: bool = False
    service_types: list[str] = Field(default_factory=list)
    parallel_safe: bool = False

    # ─── severity model ────────────────────────
    # Required for every built-in check since the §8 exit condition — enforced by
    # `verify_contracts` (`severity-undeclared`), not here. It stays optional in
    # the schema for one reason: `custom`-suite checks, which the Chainsmith agent
    # scaffolds without a severity block (O-5, parked). A schema-level requirement
    # would make one such folder fail discovery for every check in the tree.
    severity: SeverityBlock | None = None

    # ─── I/O + metadata ─────────────────────────────────────────
    outputs: dict[str, Any] = Field(default_factory=lambda: {"observations": ["Observation"]})
    side_effects: list[SideEffect] = Field(default_factory=lambda: ["none"])
    techniques: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    reason: str = ""


class AgentContract(BaseModel):
    """Identity + interface contract for an `agent` component (§4.1, 56.10).

    Agents diverge from checks: no `suite`/`depends_on`/`produces` execution
    wiring. Instead they declare a `role`, the `triggers` that invoke them, the
    `tools` they may call, and the `prompts` they ship. They are also
    constructed differently — per request/session with an injected `LLMClient`
    and an optional per-session `event_callback` — so they are loaded via
    `app/agents/registry.py` (`discover_agent_specs` → factory), not the no-arg
    `discover_components` path. The folder name must equal `name` (enforced by
    `verify_contracts`).
    """

    model_config = ConfigDict(extra="forbid")

    # ─── identity ───────────────────────────────────────────────
    id: UUID4  # assigned once at authorship
    name: str  # slug; must match folder name
    type: Literal["agent"] = "agent"
    description: str
    entry: str  # "agent.py:ClassName"

    # ─── agent interface ────────────────────────────────────────
    role: str = ""  # adjudicator | coach | triage | researcher
    triggers: list[str] = Field(default_factory=list)  # e.g. ["observation.verified"]
    tools: list[str] = Field(default_factory=list)  # declared tool surface
    prompts: dict[str, str] = Field(default_factory=dict)  # role -> path (system, user)

    # ─── I/O + metadata ─────────────────────────────────────────
    outputs: dict[str, Any] = Field(default_factory=dict)
    side_effects: list[SideEffect] = Field(default_factory=lambda: ["none"])
    references: list[str] = Field(default_factory=list)
    reason: str = ""


class AdvisorContract(BaseModel):
    """Identity + I/O contract for an `advisor` component (§4.1, 56.11).

    Advisors are DETERMINISTIC, rule-based analysis components — they read
    completed pipeline state and emit recommendations, never blocking and never
    calling an LLM. So the contract is deliberately thin: it has neither a
    check's execution wiring (`suite`/`depends_on`/`produces` — advisors aren't
    in the scan DAG) nor an agent's LLM interface (`role`/`triggers`/`tools`/
    `prompts`).

    Advisors are also constructed differently from both: not no-arg by the
    loader (like checks) and not by a dependency-injecting factory (like
    agents), but by their **call site** with per-call data it already holds
    (launcher state, request scope). So they are discovered as *specs*
    (`app/advisors/registry.py`) for identity + config resolution only — there
    is no `.create()` factory — and `verify_contracts` exempts them from the
    no-arg constructibility rule. The folder name must equal `name`.
    """

    model_config = ConfigDict(extra="forbid")

    # ─── identity ───────────────────────────────────────────────
    id: UUID4  # assigned once at authorship
    name: str  # slug; must match folder name
    type: Literal["advisor"] = "advisor"
    description: str
    entry: str  # "advisor.py:ClassName"

    # ─── I/O + metadata ─────────────────────────────────────────
    outputs: dict[str, Any] = Field(default_factory=lambda: {"recommendations": []})
    side_effects: list[SideEffect] = Field(default_factory=lambda: ["none"])
    references: list[str] = Field(default_factory=list)
    reason: str = ""


class GateContract(BaseModel):
    """Identity + I/O contract for a `gate` component (§4.1, 56.12).

    Gates are DETERMINISTIC allow/block authorities — they answer "may this
    proceed?" at the scan chokepoint. Like an
    advisor the contract is thin (no check execution wiring, no agent LLM
    interface), but a gate *decides* rather than *recommends*: its methods
    return a (allowed, reason) decision and it may record violations
    (`side_effects: [filesystem]`).

    `enforces` self-documents the distinct gate concerns the component owns
    (e.g. scope / scan_window / technique for the Guardian) — metadata only,
    not load-bearing.

    Gates are constructed by their **call site** with per-scan scope data it
    already holds (the scan route / scanner / launcher build a `Guardian` per
    scan via `from_scope(...)`), so — exactly like advisors — they are
    discovered as *specs* (`app/gates/registry.py`) for identity + config
    resolution only (no `.create()` factory) and `verify_contracts` exempts
    them from the no-arg constructibility rule. The folder name must equal
    `name`.
    """

    model_config = ConfigDict(extra="forbid")

    # ─── identity ───────────────────────────────────────────────
    id: UUID4  # assigned once at authorship
    name: str  # slug; must match folder name
    type: Literal["gate"] = "gate"
    description: str
    entry: str  # "gate.py:ClassName"

    # ─── gate interface ─────────────────────────────────────────
    enforces: list[str] = Field(default_factory=list)  # e.g. ["scope", "scan_window", "technique"]

    # ─── I/O + metadata ─────────────────────────────────────────
    outputs: dict[str, Any] = Field(default_factory=lambda: {"decision": ["GateDecision"]})
    side_effects: list[SideEffect] = Field(default_factory=lambda: ["none"])
    references: list[str] = Field(default_factory=list)
    reason: str = ""


# Registry of contract models by component type — the discriminated union
# described in §4.1. All four types are concrete as of 56.12.
CONTRACT_MODELS: dict[str, type[BaseModel]] = {
    "check": CheckContract,
    "agent": AgentContract,
    "advisor": AdvisorContract,
    "gate": GateContract,
}


def contract_model_for(component_type: str) -> type[BaseModel]:
    """Return the Pydantic contract model for a component type.

    Raises KeyError for an unknown type so a typo fails loudly rather than
    silently.
    """
    return CONTRACT_MODELS[component_type]
