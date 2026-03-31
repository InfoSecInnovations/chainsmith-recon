# Phase 9: MCP Check Enhancements

16 new checks for the MCP suite (`app/checks/mcp/`), expanding from discovery and tool enumeration into authentication testing, active tool probing, prompt injection detection, and cross-suite analysis.

Source: `docs/future-ideas/mcp_check_enhancements.txt`

---

## Current State

- 2 existing checks: MCPDiscoveryCheck, MCPToolEnumerationCheck
- Discovery probes 8 well-known paths, detects SSE/HTTP transport, extracts capabilities and server info
- Tool enumeration calls `tools/list`, classifies each tool by risk level (critical/high/medium/low/info) using pattern matching on name/description/schema
- Neither check invokes tools or sends payloads

---

## Build Waves

### Wave 1 — High-value passive checks (Phase 9a)

| # | Check | Priority | Depends on | HTTP? |
|---|-------|----------|------------|-------|
| 3 | MCP Authentication & Authorization | High | mcp_discovery | Yes |
| 6 | WebSocket Transport Discovery | High | mcp_discovery | Yes |
| 8 | Tool Chain Category Analysis | Medium | mcp_tool_enumeration | No |
| 5 | Shadow Tool Detection | High | mcp_tool_enumeration | No |

### Wave 2 — Complete passive analysis (Phase 9b)

| # | Check | Priority | Depends on | HTTP? |
|---|-------|----------|------------|-------|
| 9 | Tool Schema Information Leakage | Medium | mcp_tool_enumeration | No |
| 10 | MCP Server Fingerprinting | Medium | mcp_discovery | No |
| 11 | Transport Security Analysis | Medium | mcp_discovery | Yes (light) |
| 12 | MCP Notification/Event Injection | Medium | mcp_discovery | Yes |

### Wave 3 — Active probing framework + checks (Phase 9c)

| # | Check | Priority | Depends on | HTTP? |
|---|-------|----------|------------|-------|
| 1 | MCP Tool Invocation Probing | High | mcp_tool_enumeration | Yes (active) |
| 4 | MCP Resource URI Traversal | High | mcp_discovery (resources cap.) | Yes (active) |
| 13 | Resource Template Injection | Medium | mcp_discovery (resources cap.) | Yes (active) |

**Prerequisite**: Safety framework for tool invocation (shared module).

### Wave 4 — Cross-suite capstone (Phase 9d)

| # | Check | Priority | Depends on | HTTP? |
|---|-------|----------|------------|-------|
| 2 | MCP Prompt Injection via Tool Results | High | mcp_tool_enumeration + chat_endpoints | Yes (active) |

### Wave 5 — Lower priority (Phase 9e)

| # | Check | Priority | Depends on | HTTP? |
|---|-------|----------|------------|-------|
| 7 | MCP Sampling Endpoint Abuse | Medium-high | mcp_discovery (sampling cap.) | Yes |
| 14 | MCP Protocol Version Probing | Low-medium | mcp_discovery | Yes |
| 15 | Tool Rate Limiting / Abuse | Low-medium | mcp_tool_enumeration | Yes |
| 16 | Undeclared Capability Probing | Low | mcp_discovery | Yes |

---

## Proposed Runtime Check Chain

```
Phase 1 (from network suite):
  mcp_discovery -> mcp_servers (transport, capabilities, auth)
  websocket_transport_discovery -> additional mcp_servers

Phase 2 (depends on mcp_servers):
  mcp_tool_enumeration -> mcp_tools, high_risk_tools
  mcp_auth -> auth_status per server
  mcp_transport_security -> transport_security per server
  mcp_server_fingerprint -> server_implementation per server
  mcp_undeclared_capabilities -> hidden capabilities
  mcp_protocol_version_probe -> version_support

Phase 3 (depends on Phase 2):
  mcp_shadow_tool_detection (uses tool names from enumeration)
  mcp_tool_schema_leakage (analyzes schemas from enumeration)
  mcp_tool_chain_analysis (uses classified tools)
  mcp_notification_injection (uses server connections)
  mcp_sampling_abuse (if sampling capability detected)
  mcp_tool_rate_limiting (uses low-risk tools for testing)

Phase 4 (depends on Phase 2-3, requires tool invocation):
  mcp_tool_invocation_probing (safe test payloads)
  mcp_resource_uri_traversal (path traversal + SSRF)
  mcp_resource_template_injection (template parameter injection)

Phase 5 (depends on Phase 4 + AI suite chat_endpoints):
  mcp_prompt_injection_via_tools (tool result -> LLM context)
```

---

## Wave 1 Check Designs

### Check #3: MCP Authentication & Authorization

**Name**: `mcp_auth`
**Depends on**: `mcp_discovery` (mcp_servers), optionally `mcp_tool_enumeration` (mcp_tools)
**Produces**: `mcp_auth_status`

Goes beyond the current 401 detection in discovery. Tests actual auth enforcement at multiple levels.

**Tests**:
- No auth: Send `tools/list` and tool invocations with no auth headers
- Default keys: Try common default API keys (`"mcp-key"`, `"default"`, `"test"`, empty string)
- Auth scope: If auth works for discovery, does the same token work for tool invocation? (often different privilege levels)
- Per-tool authorization: Can a low-privilege token invoke high-risk tools?
- Initialize vs operate: Does the initialize handshake require auth but subsequent requests on the same session don't?
- Session fixation: Can a session ID from one client be reused by another?

**Findings**:
- critical: "MCP server requires no authentication: tools accessible without any credentials"
- critical: "High-risk tool accessible without auth: {tool} invokable by unauthenticated client"
- high: "Auth bypass: initialize requires auth but tools/list does not"
- high: "Session reuse: MCP session ID accepted from different client context"
- medium: "Default API key accepted: '{key}' grants MCP access"
- low: "Per-tool authorization not enforced: all tools accessible with same token"
- info: "Authentication enforced at all levels"

**Implementation notes**:
- Test auth states against both JSON-RPC and direct HTTP endpoints
- If `mcp-session-id` header is present, test session handling
- Check if CORS headers allow cross-origin MCP access (browser-based attacks)

---

### Check #6: WebSocket Transport Discovery

**Name**: `mcp_websocket_discovery` (or fold into `mcp_discovery`)
**Depends on**: `mcp_discovery` (supplements existing transport detection)
**Produces**: additional entries in `mcp_servers`

The current discovery only detects SSE and HTTP transports. MCP also supports WebSocket.

**Paths to test**:
- `/ws`, `/mcp/ws`, `/v1/mcp/ws`, `/api/mcp/ws`
- `/socket`, `/mcp/socket`
- Same paths discovered by MCPDiscoveryCheck (try WS upgrade)

**Method**:
- Send HTTP GET with `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Version: 13`, `Sec-WebSocket-Key: <random>`
- Check for 101 Switching Protocols response
- If upgraded: send JSON-RPC initialize over WebSocket
- Check if WebSocket endpoint has different auth than HTTP

**Findings**:
- medium: "MCP WebSocket transport discovered: ws://example.com/mcp/ws"
- high: "WebSocket MCP endpoint requires no authentication (HTTP endpoint requires auth)"
- info: "WebSocket upgrade rejected on all tested paths"

**Implementation notes**:
- Use `websockets` library or raw HTTP upgrade
- WebSocket endpoints may be on different ports than HTTP
- If WS discovered, add to `mcp_servers` output for downstream checks
- Close WebSocket connections cleanly after testing

---

### Check #8: Tool Chain Category Analysis

**Name**: `mcp_tool_chain_analysis`
**Depends on**: `mcp_tool_enumeration` (mcp_tools)
**Produces**: `mcp_dangerous_chains`
**HTTP**: None — runs entirely on already-enumerated data

Instead of mapping all possible tool chain permutations, defines a small set of dangerous chain categories and checks if the discovered tool set could form any of them. This is a set intersection problem, not a permutation analysis.

**Dangerous chain categories**:
- **Data Read + Data Exfil**: (read_file OR sql_query OR search) AND (send_email OR http_fetch OR upload)
- **Credential Access + Network**: (get_secret OR env_read OR config_read) AND (http_fetch OR ssh OR ftp)
- **File Access + Code Execution**: (read_file OR write_file) AND (exec_command OR run_code OR eval)
- **Recon + Lateral Movement**: (list_files OR search OR browser) AND (ssh OR http_fetch OR send_message)
- **Write + Persistence**: (write_file OR create_file) AND (exec_command OR schedule OR cron)

**Method**:
- Map each discovered tool to capability tags based on risk classification and schema (e.g., `read_file` -> `[file_read]`, `send_email` -> `[data_exfil, network]`)
- Check if any dangerous category has all required capability tags covered by the tool set
- Report which specific tools form each chain

**Findings**:
- critical: "Dangerous tool chain: data exfiltration possible via read_file + send_email"
- critical: "Dangerous tool chain: RCE + file write = persistence via exec_command + write_file"
- high: "Dangerous tool chain: credential theft possible via env_read + http_fetch"
- info: "No dangerous tool chain categories detected"

**Implementation notes**:
- Capability tagging is derived from existing risk classification patterns — reuse the regex lists from tool_enumeration
- The category definitions are the core intellectual property of this check — maintain them as a versioned pattern file
- Keep the number of categories small (5-10) and well-defined

---

### Check #5: Shadow Tool Detection

**Name**: `mcp_shadow_tool_detection`
**Depends on**: `mcp_tool_enumeration` (mcp_tools)
**Produces**: `mcp_shadow_tool_risks`
**HTTP**: Minimal (notification test only)

Tests whether MCP tool names can be overwritten or collided with, enabling an attacker to shadow legitimate tools with malicious replacements.

**Attack scenario**: In multi-server MCP setups, if server A exposes tool "search" and attacker-controlled server B also registers "search", the client/LLM may invoke the attacker's version. Even in single-server setups, a server that accepts client-side tool registration allows tool replacement.

**Detection tests** (safe, non-destructive):
1. Check for tool namespacing: Do tool names include a server/namespace prefix (e.g., `server_name/tool_name`) or are they flat names? Flat names are vulnerable to collision.
2. Send `tools/list_changed` notification: Test if the server accepts unsolicited `notifications/tools/list_changed` from the client. If accepted, re-enumerate tools and compare.
3. Attempt tool re-registration via initialize: Send a second initialize request with clientInfo that includes tool capabilities.
4. Name collision analysis: Compare discovered tool names against a list of common MCP tool names. Flat names matching common names are collision candidates.

**Common MCP tool names to check for collision risk**:
`read_file`, `write_file`, `search`, `fetch`, `browse`, `execute`, `get_weather`, `send_email`, `query`, `list_files`, `create_file`, `delete_file`, `http_request`, `run_command`, `get_url`

**Findings**:
- high: "MCP server accepts tool re-registration: duplicate tool names not rejected (shadow tool attack possible)"
- high: "Server accepts client notifications/tools/list_changed (client can influence server tool state)"
- medium: "MCP tools use flat naming (no namespace prefix) — vulnerable to shadow tool attacks in multi-server configurations. Collision-risk tools: {list}"
- low: "Server does not validate tool list_changed notifications from client (no error returned)"
- info: "Tools are namespaced: {server_name}/{tool_name} (shadow tool resistant)"
- info: "Server rejects client-side tool re-registration attempts"

**Implementation notes**:
- The namespace check is the simplest and most reliable indicator
- For the notification test: send notification and wait 2 seconds before re-enumerating
- Report which specific tool names are collision candidates
- Especially relevant when combined with agent suite results (agent frameworks connecting to multiple MCP servers are the primary target)

---

## Wave 2-5 Check Designs

Detailed designs for checks #1, #2, #4, #7, #9-16 are in the source document (`docs/future-ideas/mcp_check_enhancements.txt`). Designs will be expanded into this document as each wave is reached.

---

## Open Questions — Wave 1

These need resolution before implementation begins.

### #3 MCP Authentication & Authorization

**Q1: Session fixation — what does "another client" mean?**
The doc says "Can a session ID from one client be reused by another?" Chainsmith is a single process. Options: (a) two separate HTTP client instances with different cookies but the same `mcp-session-id` header, (b) strip all auth headers except the session ID and see if it still works. Which interpretation?

**Q2: Default key list scope**
The current list (`"mcp-key"`, `"default"`, `"test"`, empty string) is short. Should it expand to include `"changeme"`, `"password"`, `"admin"`, bearer tokens with common values? There's a design tension between coverage and staying clearly within recon boundaries (not looking like brute force).

**Q3: Auth scope test crosses into active invocation**
Testing "does discovery token work for tool invocation" requires calling `tools/call`, which is active tool invocation — Wave 3 territory. Should this sub-test be deferred to Wave 3 when the invocation safety framework exists, with Wave 1 only testing auth at the `tools/list` level?

**Q4: Split check across phases or degrade gracefully?**
Some sub-tests (per-tool auth) need `mcp_tool_enumeration` output while basic auth tests only need `mcp_discovery`. Options: (a) split into two check classes at different runtime phases, (b) one check that runs basic tests always and per-tool tests only when tool data is available. Which approach?

### #6 WebSocket Transport Discovery

**Q5: WebSocket library dependency**
The existing `AsyncHttpClient` doesn't support WebSocket upgrades. Options: (a) add `websockets` as a new dependency and establish a real WS connection, (b) raw HTTP upgrade only — send Upgrade headers, check for 101, but don't establish a WS frame connection. Option (b) is lighter but can't confirm MCP protocol over WS.

**Q6: Separate check or fold into mcp_discovery?**
If WebSocket discovery also produces `mcp_servers`, there are two producers of the same output key. Options: (a) WS check appends to existing `mcp_servers` list, (b) produces `mcp_websocket_servers` separately and downstream checks look at both, (c) fold WS detection into `mcp_discovery` itself as a transport probe alongside existing SSE/HTTP probes. Option (c) keeps one producer of `mcp_servers` but modifies an existing check.

**Q7: Port scanning scope**
"WebSocket endpoints may be on different ports than HTTP." How far to go? Just test the same host:port with WS upgrade? Or also probe common WS ports (8080, 8443, 3001)? Port scanning changes the check's character significantly.

### #8 Tool Chain Category Analysis

**Q8: Capability tagging layer**
The current risk classification maps tools to risk levels (critical/high/medium), not capability categories (file_read, data_exfil, network). Chain analysis needs a new mapping layer. Options: (a) add capability tags alongside risk levels in the tool enumeration output, (b) derive capability tags in the chain analysis check from the same regex patterns independently. Option (a) enriches the shared data model but modifies the existing check; (b) keeps changes isolated.

**Q9: Pattern file format**
Chain category definitions are described as a "versioned pattern file." Options: (a) YAML file like simulation configs, (b) Python dict in a constants module, (c) standalone JSON file. This shapes how easy it is to add new chain categories later.

**Q10: Partial chain findings — signal or noise?**
The design shows a `medium` finding for "partial dangerous chain: file read tools present but no exfiltration vector found." Every MCP server with a `read_file` tool would trigger this. Should partial matches be dropped entirely, reported at `info` severity only, or kept at `medium`?

### #5 Shadow Tool Detection

**Q11: Notification test is active probing, not passive**
Sending unsolicited `tools/list_changed` notifications to the server is active probing, not purely observational. Wave 1 is labeled "passive." Options: (a) keep it in Wave 1 since it's non-destructive, (b) move the notification sub-tests to Wave 2 (#12 Notification/Event Injection) and limit Wave 1 to static analysis (namespace check + name collision analysis only).

**Q12: Common tool name list location**
The 15 common tool names need a home. Options: (a) hardcoded in the check class, (b) shared constants file that #8 can also reference for capability tagging, (c) YAML pattern file alongside chain category definitions.

**Q13: Multi-server collision grouping**
Shadow tool detection needs to compare tool names across servers. The current `mcp_tools` output includes `server_url` per tool. Confirming the approach: group tools by `server_url`, then find name intersections across groups?

### Cross-cutting

**Q14: Check naming convention**
Existing checks are `mcp_discovery` and `mcp_tool_enumeration`. Proposed names for Wave 1:
- `mcp_auth`
- `mcp_websocket_discovery` (unless folded into `mcp_discovery` per Q6)
- `mcp_tool_chain_analysis`
- `mcp_shadow_tool_detection`

Confirm or suggest alternatives?

**Q15: Simulation YAML coverage**
Each existing check has 2-3 simulation scenarios. Plan the same for Wave 1? Suggested scenarios:
- `mcp_auth`: no_auth, default_key_accepted, auth_enforced, auth_bypass_initialize_vs_tools
- `mcp_websocket_discovery`: ws_found, ws_rejected, ws_no_auth_http_auth
- `mcp_tool_chain_analysis`: dangerous_chain_found, partial_chain, no_chains
- `mcp_shadow_tool_detection`: flat_names_collision, namespaced_safe, re_registration_accepted

**Q16: Test strategy**
Existing tests mock `AsyncHttpClient`. Same pattern for Wave 1? Checks #8 and #5 (static analysis portions) need no HTTP mocking — just unit tests that feed crafted `mcp_tools`/`mcp_servers` context and verify findings. Confirm?
