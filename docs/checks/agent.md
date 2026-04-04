# Agent Suite

AI agent discovery, framework fingerprinting, and adversarial testing.
17 checks organized in 5 phases by dependency order.

---

## Phase 1 — Discovery (depends on services)

### agent_discovery

**Detect AI agent orchestration endpoints and identify frameworks.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `agent_endpoints`, `agent_frameworks` |

Probes 25+ common agent endpoint paths (/agent, /run, /invoke, /stream, /batch, /input_schema, /state, /threads, etc.). Detects LangServe, LangGraph, LangChain, AutoGen, and CrewAI via response headers, body patterns, and error signatures. Identifies capabilities: memory, tools, streaming, state, threads.

#### Findings

- **high**: Unauthenticated agent execution endpoint
- **medium**: Unauthenticated schema/discovery endpoint
- **medium**: Authenticated execution endpoint
- **info**: Agent endpoint requiring auth, framework detected

---

## Phase 2 — Reconnaissance (depends on agent_endpoints)

### agent_multi_agent_detection

**Detect multi-agent system architectures and topology.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `multi_agent_topology` |

Probes management endpoints (/crew, /kickoff, /agents/list, /groupchat, /workers, /supervisor, /orchestrator, /graph). Detects delegation patterns and architecture types: crew, debate, supervisor, routing, graph.

#### Findings

- **medium**: Management endpoints found, delegation patterns detected
- **low**: Multiple agent identifiers detected

---

### agent_framework_version

**Fingerprint agent framework versions and check for known vulnerabilities.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `framework_versions` |

Extracts versions from headers, error messages, and OpenAPI metadata. Checks against known vulnerable versions: LangChain <= 0.0.325 (CVE-2023-36188, RCE), LangChain <= 0.0.350 (deserialization), LangServe <= 0.0.21 (input validation bypass), AutoGen <= 0.2.0 (unsandboxed code execution).

#### Findings

- **critical**: Known RCE vulnerability (CVE match)
- **high**: Known vulnerability in framework version
- **medium**: Framework version with known issues
- **info**: Framework version detected (no known vulnerabilities)

---

### agent_memory_extraction

**Probe agent memory endpoints for extractable content.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `memory_contents` |

Probes /agent/memory, /memory, /history, /state, /threads, /context, /conversation. Detects PII, credentials, system prompt fragments, and multi-user/cross-session data. Enumerates threads and extracts history.

#### Findings

- **critical**: Contains credentials, system prompt fragments, or multi-user data
- **high**: Accessible memory endpoint with entries
- **info**: Memory endpoint exists but requires auth

---

## Phase 3 — Active Probing (depends on Phase 2)

### agent_goal_injection

**Test agent endpoints for goal hijacking vulnerabilities.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `goal_injection_results`, `vulnerable_agents` |

Tests 5 payload categories: direct_override, information_extraction, authority_bypass, framework_specific (LangServe config, LangGraph state, AutoGen code execution, CrewAI task injection). Confidence scoring based on payload and hijack indicators. Intrusive check.

#### Findings

- **high**: Goal injection succeeded (confidence > 0.7)
- **medium**: Goal injection succeeded (lower confidence) or partial success
- **low**: Possible injection with weak indicators

---

### agent_tool_abuse

**Test for unintended tool invocation via conversational manipulation.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `tool_abuse_results` |

Tests 6 abuse categories: file_access (critical), command_execution (critical), ssrf/AWS metadata (critical), database_access (high), outbound_action (high), information_disclosure (high). Distinguishes executed vs. refused tool calls. Intrusive check.

#### Findings

- **critical**: Tool executed (file read, command execution, SSRF)
- **high**: Tool executed (database, outbound, info disclosure)
- **medium**: Tool capability confirmed but execution refused (guardrails present)

---

### agent_privilege_escalation

**Test for privilege escalation via conversational claims.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `privilege_escalation_results` |

Tests 5 techniques: admin_claim, sudo_claim, security_override, admin_mode, superuser_role. Compares baseline vs. escalated responses for new indicators, acknowledgment, or role leakage. Intrusive check.

#### Findings

- **critical**: Clear privilege escalation (confidence > 0.7)
- **high**: Privilege escalation or agent acknowledges claim
- **low**: Agent reveals role/permission structure in refusal

---

### agent_loop_detection

**Detect agent runaway and infinite loop vulnerabilities.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `loop_detection_results` |

Sends 4 loop-trigger prompts designed to cause excessive computation. Measures response time against baseline, detects repetitive patterns, monitors for timeout and server errors (502/503/504).

#### Findings

- **high**: Agent runaway (timeout, server error, extreme response time)
- **medium**: Loop indicators or missing execution timeout

---

### agent_callback_injection

**Test for callback/webhook injection and SSRF via agent.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `callback_injection_results` |

Tests parameter injection (callback_url, webhook, notify_url, etc.), conversational probes ("send results to URL"), and config schema analysis for callback fields. Intrusive check.

#### Findings

- **high**: Callback parameter accepted or URL echoed, config schema exposes callback fields
- **medium**: Conversational probe indicates callback capability

---

### agent_streaming_injection

**Test prompt injection on streaming agent endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `streaming_injection_results` |

Sends injection payloads to streaming endpoints (/stream, /agent/stream, /v1/stream). Compares injection success rate vs. non-streaming endpoints to detect bypass where early chunks evade output filters. Intrusive check.

#### Findings

- **high**: Streaming bypass confirmed (injection succeeds in stream but not non-stream)
- **medium**: Streaming endpoint vulnerable to injection

---

## Phase 4 — Framework-Specific (depends on Phase 2-3)

### agent_framework_exploits

**Test framework-specific vulnerabilities and known CVEs.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `framework_exploit_results` |

Tests per-framework exploits: LangChain PythonREPLTool RCE (CVE-2023-36188), LLMMathChain code execution; LangServe batch abuse, config exploit; LangGraph state write, cross-user thread access; AutoGen default code execution, GroupChat injection; CrewAI task/delegation injection. Intrusive check.

#### Findings

- **critical**: Known RCE (PythonREPLTool, LLMMathChain, AutoGen code exec)
- **high**: Batch abuse, config exploit, state write, cross-user access, task injection

---

### agent_memory_poisoning

**Test if agent memory can be poisoned with persistent instructions.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `memory_poisoning_results` |

Tests 3 poisoning payloads: instruction_inject (persistent marker), role_override (admin permission), policy_inject (relaxed security). Sends poisoning message, checks for acknowledgment, then sends verification prompt. Also tests direct state write via PUT /state. Cleanup attempted after testing. Intrusive check.

#### Findings

- **critical**: Memory poisoning confirmed (verification shows persistence), state endpoint writable
- **high**: Partial success (agent acknowledges storage)

---

### agent_context_overflow

**Test agent guardrails after context window overflow.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `context_overflow_results` |

Tests injection on fresh context (baseline), fills context with 8 large messages (~2.4KB each), then re-tests injection. Detects guardrail bypass when injection succeeds post-fill but failed on fresh context. Also tests for role/personality degradation. Intrusive check.

#### Findings

- **high**: Context overflow weakens guardrails (injection succeeds post-fill)
- **medium**: Agent drops system prompt after overflow (role change detected)

---

### agent_reflection_abuse

**Test if agent reflection loops can be manipulated via injection.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `reflection_abuse_results` |

Tests 3 reflection-targeted prompts designed to exploit self-critique steps: reflection_admin, reflection_relax, reflection_override. Compares baseline vs. reflection-targeted response for increased permissiveness. Intrusive check.

#### Findings

- **high**: Reflection successfully exploited (agent becomes more permissive)
- **medium**: Agent reflection is influenced but constraints maintained

---

### agent_state_manipulation

**Test direct agent state manipulation via /state and /threads endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `state_manipulation_results` |

Tests 3 state modifications: inject_context, override_task, modify_permissions. Targets /state and /threads/{tid}/state endpoints. Detects writability with and without schema validation. Intrusive check.

#### Findings

- **critical**: State writable without schema validation
- **high**: Thread state modifiable
- **medium**: State writable with schema validation
- **info**: State endpoint is read-only

---

## Phase 5 — Multi-Agent (depends on multi-agent detection)

### agent_trust_chain

**Exploit trust chain hierarchies in multi-agent systems.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `trust_chain_results` |

Tests 5 false authority claims: security_approval, compliance_override, verification_claim, qa_bypass, classification_claim. Compares baseline vs. assertion-enhanced response for new indicators and increased permissiveness. Severity escalated for multi-agent systems. Intrusive check.

#### Findings

- **critical**: Trust chain exploitation in multi-agent system
- **high**: Trust chain exploitation in single agent
- **high**: Partial acceptance of authority claim

---

### agent_cross_injection

**Test cross-agent injection via output poisoning.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `cross_injection_results` |

Tests 4 cross-injection payloads: system_override, instruction_smuggle, hidden_directive, role_injection. Checks if injection markers are preserved in agent output (delivery vector for downstream agents). Severity escalated for multi-agent systems. Intrusive check.

#### Findings

- **critical**: Full cross-injection in multi-agent system
- **high**: Full cross-injection in single agent, or delivery vector confirmed in multi-agent
- **medium**: Delivery vector confirmed in single agent
