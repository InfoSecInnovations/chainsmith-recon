# Phase 36: Guided Mode — Operator Assist System

## Overview

A preference-level toggle that activates a collection of helper
behaviors across all agents. Guided Mode is designed for operators who
want more context, explanation, and proactive guidance — without
requiring them to know which agent does what or what to ask next.

## Motivation

- Not all operators are seasoned pentesters. Chainsmith should be
  approachable without dumbing down the output for experienced users.
- The agent roster is growing (Verifier, Adjudicator, Chainsmith,
  Triage, Proof Advisor). Even experienced operators may not know what
  each agent can do or when to invoke it.
- Proactive tips, terminology definitions, and next-step suggestions
  reduce the learning curve without cluttering the default experience.
- Guided Mode is a positive opt-in ("I want more guidance"), not a
  skill judgment.

## Design Principles

### All-or-nothing toggle

Guided Mode is a single switch. No sub-toggles for individual
behaviors. This keeps the UX simple — one decision, not seven.

### Framing matters

The label is **"Guided Mode"**, not "beginner mode", "easy mode", or
"training wheels." An experienced operator might enable it on an
unfamiliar target or attack surface. The framing should never imply
a skill deficit.

UI copy example:
```
☐ Guided Mode
  Agents offer proactive tips, explain terminology,
  and suggest next steps as you work.
```

### Additive, never subtractive

Guided Mode adds information. It never hides features, restricts
capabilities, or simplifies the interface. Standard Mode is not
"advanced" — it's just quieter.

## Two Modes

| Mode | Label | Default | Description |
|------|-------|---------|-------------|
| **Standard** | "Standard Mode" | Yes | Agents respond when asked. No proactive messages. Brief rationales. |
| **Guided** | "Guided Mode" | No | Agents proactively assist. Extended explanations. Next-step suggestions. |

## What Guided Mode Enables

### Behavior matrix

| Behavior | Standard | Guided |
|----------|----------|--------|
| Proactive agent messages | Off | On — agents push status updates and suggestions |
| Terminology tooltips | Off | On — hover definitions for severity, adjudication, chains |
| Suggested next actions in chat | Minimal | Expanded — agents suggest what to do next after each step |
| Prompt expansion visibility | Hidden | Shown — operator sees how their terse input was expanded (Phase 34) |
| Post-scan summary | None | Auto — Triage pushes "scan complete, here's what to do first" |
| Scoping guidance | None | Chainsmith proactively suggests exclusions and timeframes |
| Adjudication explanations | Brief rationale | Extended — explains each rubric factor in plain language |
| Chain explanations | Chain ID + severity | Narrative — "This chain works because step 1 gives the attacker X, which enables step 2..." |
| Triage reasoning | Priority list | Annotated — each action explains why it's ranked where it is |

### Proactive message triggers

These messages are pushed to the chat stream (Phase 35) without the
operator asking. Each has a defined trigger condition:

| Trigger | Agent | Message |
|---------|-------|---------|
| `scan_complete` | Triage | "Scan finished. N quick wins found — want the action plan?" |
| `high_severity_found` | Adjudicator | "Critical finding adjudicated on [target]. [Brief rationale]." |
| `chain_identified` | Chainsmith | "New attack chain detected linking N observations." |
| `scope_incomplete` | Chainsmith | "Your scope is missing exclusions — want suggestions based on the target?" |
| `hallucination_caught` | Verifier | "Flagged a hallucinated finding. [Brief explanation of what was wrong]." |
| `triage_plan_ready` | Triage | "Action plan ready. Top priority: [action]. Want details?" |
| `partial_fix_detected` | Triage | "Re-scan shows partial progress on [action]. N observations improved." |

### Proactive message format

```
event: proactive_message
data: {
  "agent": "triage",
  "trigger": "scan_complete",
  "text": "Scan finished. 3 quick wins found — low-effort fixes that
           resolve 8 observations. Want me to show the action plan?",
  "actions": [{"label": "Show action plan", "action": "triage_plan"}],
  "dismissable": true
}
```

All proactive messages are:
- **Dismissable** — operator can close without responding
- **Non-blocking** — they appear in the chat stream, don't interrupt
- **Actionable** — include suggested action buttons when applicable

### Dismiss-to-suppress

If an operator dismisses the same trigger type 3 times in a session,
that trigger is suppressed for the remainder of the session. The
operator doesn't need to turn off Guided Mode entirely just because
one message type is noisy.

```javascript
dismissal_counts[trigger]++;
if (dismissal_counts[trigger] >= 3) {
    suppress_triggers.add(trigger);
}
```

Suppression resets on new session. No persistence across sessions —
each engagement starts fresh.

## Terminology Tooltips

In Guided Mode, domain-specific terms in the UI and chat responses
render with hover tooltips:

| Term | Tooltip |
|------|---------|
| Adjudication | "An agent re-evaluates whether the severity rating is accurate given the target context." |
| Attack chain | "A sequence of findings that, combined, create a more severe attack path than any single finding alone." |
| Observation | "A single finding discovered during reconnaissance — may be verified, rejected, or flagged as a hallucination." |
| Triage | "Prioritization of findings into an ordered remediation plan based on effort, impact, and context." |
| Hallucination | "A finding the AI reported that doesn't hold up under verification — it's not real." |
| Severity multiplier | "A chain's combined severity can exceed its individual parts. The multiplier reflects this compounding risk." |

Tooltips are defined in a static catalog. No LLM cost.

## Profile Integration

Guided Mode is stored as a preference within the existing profile
system:

```python
class PreferencesUpdateInput(BaseModel):
    # ... existing fields ...
    operator_assist: dict | None = None  # {"mode": "guided"}
```

This means:
- A profile can ship with Guided Mode enabled by default
- Operators can override per-session
- Profiles like "training" or "first-engagement" could pre-enable it
- The "default" profile stays Standard Mode

### Suggested bundled profiles

| Profile | Guided Mode | Notes |
|---------|-------------|-------|
| `default` | Off | Experienced operator, knows the tool |
| `training` | On | Learning the tool or onboarding new team members |
| `first-engagement` | On | First time running against a new target type |

## Implementation

### Preference check pattern

Every agent and UI component checks the mode before emitting
proactive content:

```python
async def maybe_emit_proactive(self, trigger: str, event: AgentEvent):
    """Emit proactive message only if Guided Mode is active."""
    if not state.preferences.get("operator_assist", {}).get("mode") == "guided":
        return
    await self.emit(event)
```

### Frontend tooltip system

```javascript
function initGuidedTooltips() {
    if (!isGuidedMode()) return;

    document.querySelectorAll('[data-term]').forEach(el => {
        const term = el.dataset.term;
        const definition = TERMINOLOGY[term];
        if (definition) {
            el.classList.add('has-tooltip');
            el.setAttribute('title', definition);
        }
    });
}
```

Terms are tagged in HTML with `data-term` attributes. The tooltip
system only activates in Guided Mode — in Standard Mode, the
attributes are inert.

### Agent modifications

Each agent gains a small guided-mode extension. This is NOT a
refactor — it's additive code gated behind the mode check:

- **Verifier**: Extended `verification_notes` when hallucination caught
- **Adjudicator**: Per-factor explanations appended to rationale
- **Chainsmith**: Scoping suggestions, chain narratives
- **Triage**: Annotated priority reasoning, proactive plan summaries

## Dependencies

- Phase 35 (Operator Chat) — proactive messages delivered via chat SSE
- Phase 34 (Prompt Router) — prompt expansion visibility
- Existing profile/preferences system — mode storage and activation

## What This Is NOT

- **Not a reduced-functionality mode.** Guided operators have access
  to everything Standard operators do. Plus more.
- **Not per-behavior configurable.** It's one toggle. This is a
  deliberate simplicity choice.
- **Not persistent across sessions by default.** Suppressed triggers
  reset each session. The mode preference persists (via profile), but
  per-session behavior adapts to the operator's interaction.

## Open Questions

1. Should Guided Mode include a brief onboarding walkthrough on first
   enable ("Here's what each agent does and when you'll hear from
   them"), or is the tooltip + proactive message system sufficient?
2. Should the terminology catalog be extensible by operators (e.g.,
   adding org-specific terms)?
