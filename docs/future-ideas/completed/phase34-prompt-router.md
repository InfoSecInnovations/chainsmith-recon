# Phase 34: Prompt Router — Intent Classification & Agent Dispatch

## Overview

A lightweight, hidden agent that classifies operator intent and routes
conversational input to the correct agent. Operators shouldn't need to
know which agent handles what — they ask a question, and the right agent
answers. The Prompt Router is invisible infrastructure, not a
user-facing feature.

## Motivation

- As the agent roster grows (Verifier, Adjudicator, Chainsmith, Triage,
  Proof Advisor, Steward), operators face a cognitive burden: "Which
  agent do I talk to for this?"
- Less experienced operators may ask the Chainsmith scoping flow about
  risk severity, or ask the Triage Agent to re-run a scan.
- Current architecture routes by endpoint (`/api/v1/scope`,
  `/api/v1/adjudication`, etc.), which works for button-driven UI but
  breaks down as conversational interaction grows.
- Misrouted prompts waste LLM tokens and produce confusing responses.

## Design Principles

### Invisible by default

The operator never sees or interacts with the Prompt Router directly.
It has no UI panel, no status indicator, no name in the interface.
From the operator's perspective, they talk to "Chainsmith" and the
right thing happens.

### Classification, not generation

The Prompt Router does NOT generate responses. It classifies intent
and dispatches to the agent that does. This keeps it cheap and fast.

### Deterministic when possible, LLM when necessary

Many routing decisions are obvious from keywords or UI context:
- Operator is in the scoping flow → Chainsmith
- Operator clicked "Re-adjudicate" → Adjudicator
- Operator is on the triage panel → Triage Agent

The LLM classifier is the fallback for ambiguous free-text input,
not the primary path.

## Architecture

```
Operator input
     │
     ▼
┌─────────────┐
│ Prompt Router│ (hidden)
├─────────────┤
│ 1. Context  │ ← UI state, active panel, current workflow
│ 2. Keyword  │ ← deterministic pattern matching
│ 3. LLM      │ ← fallback classifier (small/fast model)
└──────┬──────┘
       │
       ▼
  Target Agent
```

### Layer 1: Context routing (zero cost)

Use the operator's current UI state to route without any classification:

| UI State | Routes To |
|----------|-----------|
| Scoping panel active | Chainsmith |
| Triage panel active | Triage Agent |
| Adjudication view open | Adjudicator |
| Observation detail view | Verifier (for re-verification requests) |

If the UI context is unambiguous, skip layers 2 and 3 entirely.

### Layer 2: Keyword routing (zero cost)

Pattern-match on the input text for strong intent signals:

| Pattern | Routes To |
|---------|-----------|
| "scope", "target", "exclude", "timeframe" | Chainsmith |
| "severity", "risk", "adjudicate", "score" | Adjudicator |
| "verify", "check if", "is this real" | Verifier |
| "prioritize", "fix first", "remediate", "action plan" | Triage |
| "chain", "attack path", "link" | Chainsmith (chain building) |
| "proof", "reproduce", "evidence" | Proof Advisor |

If a single agent matches with high confidence, route directly.

### Layer 3: LLM classification (fallback)

For ambiguous input that doesn't match layers 1 or 2, use a small/fast
model with a classification prompt:

```
Given the operator's message, classify which agent should handle it.

Available agents:
- chainsmith: Scoping, target definition, attack chain building
- verifier: Fact-checking observations, re-verification requests
- adjudicator: Risk severity scoring, risk acceptance
- triage: Remediation prioritization, action planning, fix ordering
- proof_advisor: Reproduction steps, evidence guidance

Operator message: "{input}"
UI context: {panel, workflow_state}

Respond with ONLY the agent name.
```

This is a single-token classification call — minimal cost and latency.

## Redirect Behavior

When the router determines the operator is talking to the wrong agent
(e.g., asking the Adjudicator about scope), it should:

1. **Not silently redirect.** The operator should know what happened.
2. **Briefly explain the redirect.** One sentence, not a lecture.
3. **Hand off with context.** Pass the original message to the correct
   agent so the operator doesn't have to repeat themselves.

Example:
```
Operator (in Adjudicator view): "Can you add vpn.example.com to the
exclusion list?"

Router response: "That's a scoping change — I've passed this to the
scope manager."

[Chainsmith receives: "add vpn.example.com to the exclusion list"]
```

## Prompt Expansion

Beyond routing, the Prompt Router can expand terse operator input into
well-formed prompts for the target agent. This helps less experienced
operators get better results without knowing the "right" way to phrase
requests.

| Operator types | Router expands to |
|---------------|-------------------|
| "is this bad?" (on observation detail) | "Re-verify observation {id} and assess exploitability" |
| "what should I do?" (on triage panel) | "Generate prioritized action plan for current scan" |
| "explain" (on chain view) | "Explain attack chain {id}: how the links connect and why this path is viable" |

Expansion is transparent — the operator sees the expanded prompt so
they learn the vocabulary over time.

## What This Is NOT

- **Not a chatbot.** It doesn't hold conversations or generate
  substantive responses. It classifies and dispatches.
- **Not a required gateway.** Direct API endpoints still work. The
  router sits in front of the conversational interface only.
- **Not an agent orchestrator.** It doesn't coordinate multi-agent
  workflows. It routes single messages to single agents.

## Implementation

### Agent Class

```python
class PromptRouter:
    """Classifies operator intent and routes to the correct agent."""

    def __init__(self):
        self.client = get_llm_client()  # only used for Layer 3

    async def route(
        self,
        message: str,
        ui_context: dict | None = None,
    ) -> RouteDecision:
        """Classify and route an operator message."""
        # Layer 1: context
        if ui_context and (agent := self._context_route(ui_context)):
            return RouteDecision(target=agent, method="context",
                                expanded_prompt=message)

        # Layer 2: keyword
        if agent := self._keyword_route(message):
            return RouteDecision(target=agent, method="keyword",
                                expanded_prompt=message)

        # Layer 3: LLM fallback
        return await self._llm_route(message, ui_context)
```

### New Models

```python
class RouteDecision(BaseModel):
    """Result of prompt classification."""
    target: AgentType
    method: Literal["context", "keyword", "llm"]
    expanded_prompt: str
    redirect_message: str | None = None  # shown to operator if rerouted
    confidence: float = 1.0              # 1.0 for context/keyword, variable for LLM
```

### No new AgentType entry

The Prompt Router is NOT added to the `AgentType` enum. It's
infrastructure, not a pipeline participant. It doesn't emit
observations, adjudications, or triage actions. It doesn't appear
in scan results or reports.

## Cost Profile

| Layer | Cost | Latency |
|-------|------|---------|
| Context routing | Zero | ~0ms |
| Keyword routing | Zero | ~1ms |
| LLM classification | ~20 tokens | ~200ms (small model) |

Most requests should resolve at layers 1-2. Layer 3 is the exception,
not the rule.

## Dependencies

- All conversational agents must accept a `RouteDecision` alongside
  the operator message, so they know they received a redirect and
  can access the expanded prompt.
- UI must pass panel/workflow state to the router endpoint.

## Open Questions

1. Should the router track routing accuracy over time (log
   classification → operator behavior) to improve keyword patterns?
2. Should prompt expansion be opt-in or on by default? Experienced
   operators may find it patronizing.
3. If the LLM classifier returns low confidence, should the router
   ask the operator to clarify, or pick the best guess and let the
   target agent handle confusion?
