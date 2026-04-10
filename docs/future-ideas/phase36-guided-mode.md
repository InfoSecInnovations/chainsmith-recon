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
  Coach, Triage, Researcher). Even experienced operators may not know
  what each agent can do or when to invoke it.
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
[ ] Guided Mode
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
| Scoping guidance | None | Coach proactively suggests exclusions and timeframes (migrates to ScanPlannerAdvisor in Phase 41) |
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
| `scope_incomplete` | Coach | "Your scope is missing exclusions — want suggestions based on the target?" (migrates to ScanPlannerAdvisor in Phase 41) |
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

### Action button resolution

Action buttons inject a synthetic operator message into the chat
stream, routed through the PromptRouter like any other operator input.
This requires zero new infrastructure — it reuses the existing chat
dispatch path. The operator sees the injected message in their chat
history, making the interaction transparent and followup-friendly.

| Trigger | Action Label | Injected Message | Routed To |
|---------|-------------|-----------------|-----------|
| `scan_complete` | "Show action plan" | "Show me the triage action plan" | Triage |
| `high_severity_found` | "Tell me more" | "Explain the adjudication for [observation title]" | Adjudicator |
| `chain_identified` | "Show chain" | "Explain chain [chain_id]" | Chainsmith |
| `scope_incomplete` | "Suggest exclusions" | "Suggest scope exclusions for this target" | Coach (Phase 41: ScanPlannerAdvisor) |
| `hallucination_caught` | "What was wrong?" | "Explain why [observation title] was flagged as a hallucination" | Verifier |
| `triage_plan_ready` | "Show plan" | "Show the triage plan details" | Triage |
| `partial_fix_detected` | "Show progress" | "Show re-scan progress details" | Triage |

### Dismiss-to-suppress

If an operator dismisses the same trigger type 3 times in a session,
that trigger is suppressed for the remainder of the session. The
operator doesn't need to turn off Guided Mode entirely just because
one message type is noisy.

```python
dismissal_counts[trigger] += 1
if dismissal_counts[trigger] >= 3:
    suppress_triggers.add(trigger)
```

Suppression resets on new session. No persistence across sessions —
each engagement starts fresh.

## Notification UX

### Chat icon notification dot

When a proactive message arrives, the chat icon displays a plain
red dot (no count). This matches the notification pattern familiar
from mobile OSs — unobtrusive, universally understood.

- Plain dot, not a count badge — avoids noise when multiple triggers
  fire close together
- Dot clears when the operator opens the chat panel
- Chat panel does NOT auto-open — the operator engages on their terms

### Active mode indicator

When Guided Mode is active, a small "Guided" pill badge appears in
the upper-right corner of the page header, near the settings gear
icon. Visible on every page.

- Clicking the badge toggles Guided Mode off (with a brief
  confirmation toast: "Guided Mode off")
- Proximity to the gear makes it clear this is a setting
- Badge disappears when mode is off — no "Standard" badge needed

## Discovery and Onboarding

### First-enable welcome message

When the operator enables Guided Mode for the first time in a
session, Coach pushes a welcome message into the chat panel:

```
Coach: Guided Mode is active. Here's what changes:

- Agents will proactively share tips and suggestions in this
  chat panel — look for the red dot on the chat icon.
- Hover over highlighted terms for quick definitions.
- After each scan, you'll get a summary with suggested next steps.

You can turn Guided Mode off anytime by clicking the "Guided"
badge in the upper-right corner.

For a deeper walkthrough, see the Quick Start Guide.
```

The welcome message includes a link to the quick start document.

### Quick start document

A static reference page (accessible from the welcome message and
the settings page) covering:

- What Guided Mode does and doesn't do
- What each agent is and when it speaks up
- How to dismiss proactive messages
- How dismiss-to-suppress works
- How to turn Guided Mode off

This is a reference document, not a tutorial — operators can skim
it or skip it entirely. The Coach welcome message is the primary
onboarding mechanism.

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

Tooltips are defined in a static JavaScript catalog. No LLM cost.

### Tooltip page rollout

Tooltips require `data-term` attribute tagging across HTML pages.
Phased rollout by page priority:

| Pass | Pages | Rationale |
|------|-------|-----------|
| First | Observations, chain visualization | Highest density of domain terms |
| Second | Scan, triage results | Active during scan workflow |
| Third | Reports, trends, engagements | Reference and historical pages |

## Profile Integration

Guided Mode is stored as a preference within the existing profile
system:

```python
class Preferences:
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
const TERMINOLOGY = {
    "adjudication": "An agent re-evaluates whether the severity rating is accurate given the target context.",
    "attack-chain": "A sequence of findings that, combined, create a more severe attack path than any single finding alone.",
    // ... etc
};

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
- **Chainsmith**: Chain narratives explaining step-by-step logic
- **Triage**: Annotated priority reasoning, proactive plan summaries
- **Coach**: Welcome message on first enable, scope suggestions (interim until Phase 41)

### PromptRouter adjustments

Scope-related keywords (`scope`, `target`, `exclude`, `exclusion`,
`timeframe`) currently route to Chainsmith. In Phase 36, these
re-route to Coach for guided scope assistance. Phase 41 will move
them to ScanPlannerAdvisor when that component is implemented.

## Sub-Phases

### Sub-Phase A — Preference Plumbing

- Add `operator_assist` field to `Preferences` dataclass
- Wire through profile resolution and API routes
- Add `guided_mode_enabled` helper property
- Add toggle to settings/profiles UI page
- Add "Guided" pill badge to page header (upper-right, near gear)
- Badge click toggles mode off with confirmation toast

### Sub-Phase B — Proactive Message Infrastructure

- Build `maybe_emit_proactive()` as shared pattern across agents
- Add `proactive_message` SSE event type
- Frontend: render proactive messages in chat panel with dismiss button
- Frontend: action button rendering — click injects synthetic message
- Implement dismiss-to-suppress logic (3-strike, session-scoped)
- Red notification dot on chat icon for incoming proactive messages
- Dot clears on chat panel open

### Sub-Phase C — Agent Extensions

- Each agent gets guided-mode conditional content:
  - **Triage**: post-scan summary auto-push, annotated priority reasoning
  - **Adjudicator**: per-factor extended explanations
  - **Chainsmith**: chain narratives
  - **Verifier**: extended hallucination explanations
  - **Coach**: welcome message on first enable, interim scope suggestions
- Hook `scan_complete` in scanner.py to trigger Triage proactive message
- Hook scoping flow for Coach scope suggestions
- Update PromptRouter: scope keywords route to Coach

### Sub-Phase D — Frontend Tooltips and Polish

- Create static TERMINOLOGY catalog in JavaScript
- Tag `data-term` attributes across HTML pages (phased rollout):
  - First pass: observations page, chain visualization
  - Second pass: scan page, triage results
  - Third pass: reports, trends, engagements
- Tooltip CSS styling (gated on Guided Mode)
- Prompt expansion visibility in chat (show PromptRouter interpretation)
- Quick start reference page
- Coach welcome message includes link to quick start page

### Sub-Phase dependencies

```
A ──> B ──> C
A ──> D
```

B and D are independent of each other once A is done. C depends on
B for the proactive emission pathway.

## Dependencies

- Phase 35 (Operator Chat) — proactive messages delivered via chat SSE [DONE]
- Phase 34 (Prompt Router) — prompt expansion visibility [DONE]
- Existing profile/preferences system — mode storage and activation [DONE]

## Future: Phase 41 Integration

Phase 41 (Scan Advisor Split) introduces ScanPlannerAdvisor for
pre-scan planning and scope guidance. When Phase 41 lands:

- `scope_incomplete` trigger migrates from Coach to ScanPlannerAdvisor
- PromptRouter scope keywords migrate from Coach to ScanPlannerAdvisor
- Coach retains the welcome message and general explanation duties

## What This Is NOT

- **Not a reduced-functionality mode.** Guided operators have access
  to everything Standard operators do. Plus more.
- **Not per-behavior configurable.** It's one toggle. This is a
  deliberate simplicity choice.
- **Not persistent across sessions by default.** Suppressed triggers
  reset each session. The mode preference persists (via profile), but
  per-session behavior adapts to the operator's interaction.

## Open Questions

1. Should the terminology catalog be extensible by operators (e.g.,
   adding org-specific terms)?
2. Should the quick start document be a static HTML page or a modal
   overlay within the app?
