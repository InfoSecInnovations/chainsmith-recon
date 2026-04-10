# Phase 35: Operator Chat — Direct Agent Interaction with Voice

## Overview

A unified chat interface that lets operators converse directly with any
Chainsmith agent. Text and optional voice input (browser mic, opt-in).
The Prompt Router (Phase 34) handles classification and dispatch behind
the scenes — the operator just talks and the right agent responds.

## Motivation

- The current UI is form-driven and page-based. Operators configure scope
  via input fields, trigger scans via buttons, and read results in tables.
  This works but forces operators to know *where* each feature lives.
- The ChainsmithAgent already has a conversational scoping flow
  (`start_scoping()`, `continue_scoping()`) with no UI to expose it.
- As agents multiply (Verifier, Adjudicator, Triage, Proof Advisor),
  operators need a single interaction surface rather than navigating to
  per-agent pages.
- Voice input lowers the barrier for operators who are multitasking
  (running assessments while on a call, doing physical security checks,
  or working from a tablet).

## Design Principles

### Chat augments, does not replace

The existing page-based UI remains. Chat is an overlay/panel that
coexists with every page. Operators who prefer forms and buttons lose
nothing. Chat is additive.

### Agents speak as themselves

Each agent response is attributed. The operator sees who answered:

```
[Chainsmith] Target set to *.fakobanko.local. Exclusions?
[Triage]     3 quick wins identified. Highest leverage: rotate the
             exposed MCP token — resolves 4 observations in one action.
[Adjudicator] Observation obs-abc123 re-scored: critical → high.
              Rationale: internal-only service, no internet exposure.
```

This teaches operators the agent vocabulary and builds trust in who is
responsible for what.

### Voice is opt-in, text is default

Voice requires explicit browser permission. The mic button is visible
but inactive until the operator enables it. Text input always works.
No voice-only workflows — everything voice can do, text can do.

## Architecture

### Transport: Server-Sent Events (SSE)

The current UI polls at 500ms intervals. Chat messages need lower
latency and server-push capability. SSE is the right fit:

- **Unidirectional push** (server → browser) for agent responses, events,
  and status updates
- **Operator messages** sent via POST (same as current REST pattern)
- **No WebSocket complexity** — SSE works over standard HTTP, survives
  proxies, and reconnects automatically
- **Event stream** carries both chat messages and agent events (typed),
  so the UI can render them differently

```
Browser                          Server
  │                                │
  │ POST /api/v1/chat/message      │
  │ {"text": "what should I fix?"} │
  │ ─────────────────────────────► │
  │                                │ → Prompt Router classifies
  │                                │ → Triage Agent processes
  │  SSE: event: chat_response     │
  │  data: {"agent": "triage", ..} │
  │ ◄───────────────────────────── │
  │                                │
  │  SSE: event: agent_event       │
  │  data: {"type": "triage_start"}│
  │ ◄───────────────────────────── │
```

Why not WebSocket:
- Agents don't need to receive real-time browser pushes — operator
  messages are discrete and low-frequency (POST is fine)
- SSE is simpler to implement, debug, and proxy
- Auto-reconnect is built into the EventSource API
- Matches the existing REST-first architecture

### Backend Endpoints

```
POST /api/v1/chat/message       Send operator message (text or transcribed voice)
GET  /api/v1/chat/stream        SSE stream for agent responses and events
GET  /api/v1/chat/history        Chat history for current session
POST /api/v1/chat/voice          Upload audio chunk for server-side transcription (optional)
```

### SSE Event Types

```
event: chat_response
data: {
  "id": "msg-001",
  "agent": "triage",
  "text": "3 quick wins identified...",
  "timestamp": "2026-04-09T14:30:00Z",
  "routed_via": "keyword",           // from Prompt Router
  "references": ["obs-abc123"]       // clickable links to observations
}

event: agent_event
data: {
  "event_type": "triage_start",
  "agent": "triage",
  "message": "Generating action plan..."
}

event: redirect
data: {
  "from_agent": null,
  "to_agent": "chainsmith",
  "reason": "That's a scoping change — passing to scope manager."
}

event: typing
data: {
  "agent": "adjudicator",
  "status": "thinking"              // show typing indicator
}
```

### Agent Event Bridge

The existing `event_callback` mechanism on all agents is the hook point.
A new callback implementation pushes events to the SSE stream:

```python
async def chat_event_bridge(event: AgentEvent):
    """Bridge agent events to the SSE chat stream."""
    await sse_manager.broadcast(
        event_type="agent_event",
        data=event.model_dump()
    )
```

This means every agent gets chat presence for free — no per-agent
modifications needed. The Verifier's `HALLUCINATION_CAUGHT` event
shows up in chat as a message from the Verifier.

## Chat UI

### Layout: Slide-out panel

A collapsible panel anchored to the right side of every page. Available
on all pages (scope, scan, observations, reports, etc.). Does not
interfere with the existing layout.

```
┌─────────────────────────────────────┬──────────────────┐
│                                     │  Chat Panel      │
│  Existing page content              │                  │
│  (scope form, scan progress,        │  [Chainsmith]    │
│   observations table, etc.)         │  Target set.     │
│                                     │                  │
│                                     │  [Triage]        │
│                                     │  3 quick wins... │
│                                     │                  │
│                                     │  ┌────────────┐  │
│                                     │  │ Type here...│  │
│                                     │  │         🎤  │  │
│                                     │  └────────────┘  │
└─────────────────────────────────────┴──────────────────┘
```

### Chat message rendering

Messages are attributed by agent with visual differentiation:

- **Agent badge**: Color-coded pill showing agent name
- **References**: Observation IDs, chain IDs rendered as clickable links
  that navigate to the relevant detail view
- **Events**: Lower-prominence inline status messages (typing, processing)
  shown as muted text, not full chat bubbles
- **Redirects**: Shown as a system message explaining the reroute
- **Operator messages**: Right-aligned, distinct styling

### Persistent within session

Chat history persists for the session. Navigating between pages does not
clear the chat. History is loaded from `/api/v1/chat/history` on page
load. Chat state is tied to the existing `session_id`.

## Voice Input

### Browser Speech API (primary path)

Use the Web Speech API (`SpeechRecognition`) for client-side
transcription. Zero server cost, zero latency for the transcription
step, works offline.

```javascript
const recognition = new webkitSpeechRecognition();
recognition.continuous = false;     // one utterance at a time
recognition.interimResults = true;  // show partial transcription
recognition.lang = 'en-US';

recognition.onresult = (event) => {
    const transcript = event.results[0][0].transcript;
    // Send as regular text message
    sendMessage(transcript);
};
```

### Mic button behavior

```
┌────────────────────────────┐
│ Type here...           🎤  │
└────────────────────────────┘
```

- **Default state**: Mic icon, inactive, grayed out
- **Click**: Browser prompts for mic permission (first time only)
- **Listening**: Mic icon pulses red, partial transcription appears in
  the input field in real-time
- **Done**: Transcribed text appears in input field. Operator can review
  and edit before sending, or auto-send on silence (configurable).
- **Error**: If speech API unavailable (Firefox partial support, older
  browsers), mic button shows tooltip: "Voice input not supported in
  this browser"

### Auto-send vs review mode

Two modes, configurable in settings:

- **Review mode** (default): Voice transcription appears in the text
  field. Operator presses Enter or clicks Send to submit. Allows
  correction of transcription errors.
- **Auto-send mode**: Message sends automatically after 1.5s of silence.
  Faster for experienced operators who trust the transcription.

### Server-side transcription fallback

If the operator's browser doesn't support the Web Speech API, offer
an optional server-side path:

```
POST /api/v1/chat/voice
Content-Type: audio/webm
Body: <audio blob>
Response: {"transcript": "what should I fix first?"}
```

This requires a transcription backend (Whisper, Deepgram, or cloud
STT). It's optional — the feature degrades gracefully to text-only
if neither client nor server transcription is available.

Implementation note: server-side transcription adds a dependency and
cost. This should be gated behind a configuration flag, not enabled
by default.

## Prompt Router Integration

The chat system is the Prompt Router's (Phase 34) primary consumer.
Every message flows through the router before reaching an agent:

```
Operator types/speaks
     │
     ▼
POST /api/v1/chat/message
     │
     ▼
Prompt Router (Phase 34)
├── Context: current page, active panel
├── Keyword: pattern match
└── LLM: fallback classification
     │
     ▼
Target Agent processes
     │
     ▼
SSE stream ← agent response + events
     │
     ▼
Chat panel renders
```

The `ui_context` field that the Prompt Router uses is populated from
the operator's current page and panel state:

```javascript
async function sendMessage(text) {
    await fetch('/api/v1/chat/message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            text: text,
            ui_context: {
                page: getCurrentPage(),      // "scan", "observations", etc.
                active_panel: getActivePanel(), // "adjudication", "chains", etc.
                selected_observation: getSelectedObsId(),
                selected_chain: getSelectedChainId()
            }
        })
    });
}
```

## Agent Response Formatting

Agents return structured responses, not raw text. The chat renderer
handles formatting:

```python
class ChatResponse(BaseModel):
    """Agent response formatted for chat display."""
    id: str
    agent: AgentType
    text: str
    references: list[Reference] = []    # clickable links
    actions: list[SuggestedAction] = [] # buttons the operator can click
    metadata: dict = {}

class Reference(BaseModel):
    type: Literal["observation", "chain", "triage_action", "scan"]
    id: str
    label: str                          # display text

class SuggestedAction(BaseModel):
    """Inline action button in chat response."""
    label: str                          # "Re-adjudicate", "View chain"
    action: str                         # API call or navigation target
    params: dict = {}
```

Suggested actions let agents offer one-click follow-ups:

```
[Triage] Quick win: rotate exposed MCP token. Resolves 4 observations.
         [View affected observations]  [Mark as done]
```

## Accessibility

- **Keyboard navigation**: Tab to chat panel, Enter to send, Escape
  to collapse
- **Screen reader**: Agent messages include ARIA labels identifying the
  speaking agent
- **Voice output**: Not in scope for this phase. Text responses only.
  TTS could be a future enhancement for accessibility.
- **High contrast**: Chat panel respects the existing theme system
  (dark/light mode via CSS custom properties)

## Data Model

### Chat messages table

```sql
CREATE TABLE chat_messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    direction TEXT NOT NULL,         -- 'operator' or 'agent'
    agent_type TEXT,                 -- null for operator messages
    text TEXT NOT NULL,
    route_method TEXT,               -- 'context', 'keyword', 'llm'
    ui_context TEXT,                 -- JSON blob of page/panel state
    references TEXT,                 -- JSON array of Reference objects
    actions TEXT                     -- JSON array of SuggestedAction objects
);
```

### Chat history API

```
GET /api/v1/chat/history?session={session_id}&limit=50&before={msg_id}
```

Returns messages in reverse chronological order with cursor-based
pagination. The chat panel loads the most recent 50 messages on open
and lazy-loads older messages on scroll-up.

## Implementation Phases

### 35a — Text chat with SSE (MVP)

- SSE endpoint for server-push
- Chat panel UI (slide-out, collapsible)
- POST endpoint for operator messages
- Prompt Router integration (Phase 34)
- Agent event bridge (existing callbacks → SSE)
- Chat history persistence
- Agent attribution on messages

### 35b — Voice input

- Web Speech API integration (client-side)
- Mic button with permission flow
- Review mode (default) and auto-send mode
- Partial transcription display
- Browser compatibility detection and graceful degradation

### 35c — Server-side transcription fallback (optional)

- Audio upload endpoint
- Whisper/Deepgram/cloud STT integration
- Configuration flag to enable/disable
- Cost tracking for server-side transcription calls

### 35d — Rich responses

- Clickable reference links (observation, chain, triage action)
- Suggested action buttons in chat messages
- Inline data previews (severity badges, risk scores)

## Dependencies

- Phase 34 (Prompt Router) — required for intent classification
- All existing agents — no modifications needed, event bridge handles
  integration automatically

## What This Is NOT

- **Not a replacement for the page-based UI.** Forms, tables, and
  visualizations stay. Chat is an additional interaction mode.
- **Not a general-purpose chatbot.** The chat routes to specific agents
  with specific capabilities. It doesn't answer arbitrary questions.
- **Not voice-first.** Text is the primary input. Voice is a convenience
  that degrades gracefully when unavailable.

## Design Decisions

### 1. Chat panel state persists across navigation

The panel remembers collapsed/expanded state via `localStorage`. If the
operator opened the chat on the scan page, it stays open when they
navigate to observations. Closing is a deliberate choice that sticks.

```javascript
localStorage.setItem('chat_panel_state', 'expanded'); // or 'collapsed'
```

### 2. Proactive messaging requires Guided Mode (Phase 36)

Agents do NOT proactively message operators by default. Proactive
messages and other helper behaviors are part of the **Operator Assist /
Guided Mode** system defined in Phase 36. The chat system respects the
operator's mode setting — in Standard Mode (default), agents only
respond when asked. In Guided Mode, agents push status updates,
suggestions, and explanations through the chat stream.

See `phase36-guided-mode.md` for full specification.

### 3. Chat history is per-session, with engagement continuity

Default: chat history is **per-session**. A new session starts with a
clean chat. This matches the existing session model (`session_id`
tracks state).

Exception: when an operator is working within an **engagement**
(existing feature — `engagements.html`), chat history persists across
sessions tied to that engagement. Multi-day assessments against the
same target should have conversational continuity.

```sql
CREATE TABLE chat_messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    engagement_id TEXT,              -- nullable, links to engagement
    timestamp TEXT NOT NULL,
    -- ... rest of schema unchanged
);
```

Query logic:
- No engagement → load history for current `session_id` only
- Active engagement → load history for all sessions in that engagement

### 4. Voice rate limiting: 2-second cooldown in auto-send mode

- **Review mode** (default): No rate limiting needed. The operator
  manually hits Send, which is self-throttling.
- **Auto-send mode**: 2-second cooldown after each sent message.
  During cooldown, the mic icon shows a brief "..." state and doesn't
  capture. This prevents background noise or trailing speech from
  triggering rapid duplicate messages.

```javascript
let voiceCooldown = false;
recognition.onresult = (event) => {
    if (voiceCooldown) return;
    const transcript = event.results[0][0].transcript;
    sendMessage(transcript);
    voiceCooldown = true;
    setTimeout(() => { voiceCooldown = false; }, 2000);
};
```

### 5. File attachments deferred to Phase 35e

File/image attachments add meaningful scope: upload handling, storage,
size limits, security scanning, and agent-side multimodal processing.
Deferred to a future sub-phase.

Potential use cases for when it's built:
- Operator uploads a screenshot of an error or unusual response
- Operator attaches a config file for the agent to analyze
- Operator shares a network diagram for scoping context

## Resolved Questions

### SSE reconnection strategy

On reconnect, the client re-fetches from `/api/v1/chat/history` to
backfill any messages missed during the disconnect. No `Last-Event-ID`
tracking — history endpoint is the single source of truth.

### SSE stream scoping

The SSE stream is **per-user**. Each authenticated user gets their own
stream regardless of session or tab count. Multiple tabs from the same
user share the same logical stream.

### Agent concurrency on duplicate dispatch

If the Prompt Router dispatches to an agent that is already processing
a prior request, the second message **queues**. Agents process one
message at a time. The `typing` event reflects this — an agent shows
"thinking" until its current task completes, then picks up the next
queued message. Queued messages show a "queued" status in the chat UI.

### Long agent responses

Agents **summarize** long output directly in the chat response. If the
operator wants the full analysis, the agent offers to write a detailed
report to the reports directory. This keeps the chat stream scannable
and pushes detailed artifacts to where they belong.

```
[Triage] 12 quick wins identified across 3 target hosts. Top 3:
         1. Rotate exposed MCP token (resolves 4 observations)
         2. Disable TLS 1.0 on *.internal (resolves 3 observations)
         3. Patch OpenSSH on jump host (resolves 2 observations)
         [Write full analysis to reports]
```

### Error surfacing

When the Prompt Router cannot classify a message, or a target agent
errors during processing, the chat displays a plain-English error
message as a system message:

```
[System] Could not determine which agent should handle your message.
         Try rephrasing, or specify the agent: "triage: what should
         I fix first?"

[System] The Adjudicator encountered an error while re-scoring
         observation obs-abc123: timeout waiting for LLM response.
         Try again or check the observation directly.
```

Errors are never swallowed silently. The operator always sees what
went wrong and gets a suggested next step.

### SSE stream lifecycle

The SSE connection opens when the operator sends their **first chat
message**. It does not open on page load or panel expand. Once open,
the connection persists for the duration of the session — it does not
close when the panel is collapsed, allowing background message
accumulation (for unread badges, etc.).

A **Clear Chat** button in the panel header clears the visible chat
history and closes the SSE connection. The next message re-opens it.
Cleared messages remain in the database for audit purposes but are
marked as cleared and excluded from `/chat/history` responses.

```javascript
async function clearChat(sessionId) {
    await fetch(`/api/v1/chat/clear`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId })
    });
    sseConnection.close();
    chatPanel.clearMessages();
}
```

### Engagement chat history export

Engagement-linked chat history is exportable as **JSON**. The export
is triggered from the engagement detail page alongside existing report
exports. Format:

```json
{
    "engagement_id": "eng-001",
    "exported_at": "2026-04-09T18:00:00Z",
    "messages": [
        {
            "id": "msg-001",
            "timestamp": "2026-04-09T14:30:00Z",
            "direction": "operator",
            "text": "what should I fix first?",
            "agent_type": null
        },
        {
            "id": "msg-002",
            "timestamp": "2026-04-09T14:30:02Z",
            "direction": "agent",
            "text": "3 quick wins identified...",
            "agent_type": "triage",
            "references": ["obs-abc123"]
        }
    ]
}
```

## Open Questions

1. Should Guided Mode have sub-toggles (e.g., "proactive messages yes,
   but terminology tooltips no"), or is it all-or-nothing?
2. Should there be a "do not disturb" toggle that temporarily suppresses
   proactive messages without switching to Standard Mode entirely?
