# MCP Suite

Model Context Protocol server discovery, tool analysis, and security testing.
18 checks organized in 5 phases by dependency order.

---

## Phase 1 — Discovery (depends on services)

### mcp_discovery

**Discover Model Context Protocol (MCP) server endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `mcp_servers` |

Probes well-known MCP paths (/.well-known/mcp, /mcp, /mcp/sse, /v1/mcp, /sse, /events). Detects MCP servers via response headers (mcp-session-id, mcp-server-version), JSON-RPC patterns, and SSE content types. Identifies transport type and server capabilities.

#### Observations

- **medium**: MCP server discovered with capabilities
- **info**: MCP endpoint found (auth required or minimal info)

---

### mcp_websocket_transport

**Discover MCP servers accessible via WebSocket transport.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_websocket_servers` |

Attempts WebSocket upgrade on common MCP paths (/ws, /mcp/ws, /socket, /mcp/websocket). Compares WebSocket auth with HTTP endpoint auth to detect bypass scenarios.

#### Observations

- **high**: WebSocket accepts connection but HTTP requires auth (auth bypass)
- **medium**: WebSocket transport discovered
- **info**: WebSocket upgrade rejected

---

## Phase 2 — Server Analysis (depends on mcp_servers)

### mcp_tool_enumeration

**Enumerate tools exposed by MCP servers and assess risk levels.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_tools`, `high_risk_tools` |

Calls `tools/list` on discovered servers. Classifies each tool by risk: critical (exec, shell, eval, bash), high (file ops, HTTP, SQL, email, cloud), medium (env, config, secrets, browser), low (read-only), info (benign utilities).

#### Observations

- **critical**: Tool enables command execution or code evaluation
- **high**: Tool accesses files, networks, or databases
- **medium**: Tool accesses environment or secrets
- **low/info**: Benign tool discovered

---

### mcp_auth_check

**Check MCP server authentication and authorization enforcement.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_auth_status` |

Tests: no-auth access to tools/list, common default API keys (mcp-key, default, test, admin, changeme), auth scope mismatch (initialize vs tools/list), session reuse/fixation via Mcp-Session-Id, and CORS preflight with foreign origin.

#### Observations

- **critical**: Tools accessible without any authentication
- **high**: Default API keys accepted, auth scope mismatch, session reusable, CORS allows cross-origin
- **info**: Authentication properly enforced

---

### mcp_transport_security

**Analyze MCP transport layer security (TLS, CORS, SSE auth).**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_transport_security` |

Tests for plain HTTP (no TLS), CORS headers on MCP endpoints, origin header validation, and SSE stream auth.

#### Observations

- **high**: Plain HTTP, CORS issues, no origin validation
- **medium**: SSE without per-connection auth
- **info**: Transport security adequate

---

### mcp_server_fingerprint

**Identify MCP server implementation and version.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_server_implementations` |

Identifies server framework/SDK from serverInfo, error response signatures, and capability heuristics. Detects: official TypeScript SDK, official Python SDK, FastMCP, LangChain MCP Adapter, Claude Desktop MCP, Cursor MCP, Ollama MCP Bridge, and custom implementations.

#### Observations

- **info**: Server implementation and version identified
- **low**: Custom/unknown implementation detected

---

### mcp_undeclared_capabilities

**Probe for MCP capabilities not declared in initialize response.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_undeclared_capabilities` |

Probes standard capabilities (tools/list, resources/list, prompts/list, sampling/createMessage) and non-standard methods (admin/status, debug/info, internal/config, server/info, health, metrics, logging/setLevel).

#### Observations

- **high**: Undeclared standard capability returns data
- **medium**: Non-standard method responds with data
- **info**: Server correctly rejects undeclared capabilities

---

### mcp_protocol_version

**Test MCP server for protocol version downgrade vulnerabilities.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_protocol_versions` |

Sends initialize with different protocol versions (2024-01-01 through 2025-03-26). Compares capabilities across versions to detect downgrade with reduced security features.

#### Observations

- **medium/low**: Server accepts protocol downgrade (severity based on capability loss)
- **info**: Server only accepts current version

---

## Phase 3 — Tool Analysis (depends on mcp_tools)

### mcp_shadow_tool_detection

**Detect MCP shadow tool attack susceptibility.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_tools is truthy` |
| Produces | `mcp_shadow_tool_risk` |

Analyzes tool naming conventions (flat vs namespaced), detects common tool name collisions (read_file, execute, search, etc.), and tests protocol-level attacks: list_changed notification injection and re-initialization.

#### Observations

- **high**: Server accepts list_changed notification from client
- **medium**: Flat tool naming (no namespace, vulnerable to collisions)
- **low**: Collision-risk tool names, server accepts duplicate initialize
- **info**: Tools are namespaced (resistant to shadow attacks)

---

### mcp_schema_leakage

**Analyze MCP tool schemas for sensitive information leakage.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_tools is truthy` |
| Produces | `mcp_schema_leaks` |

Inspects inputSchema parameter names, default values, enum values, and descriptions for infrastructure details. Detects sensitive defaults (internal IPs, hostnames, database URIs, S3 paths), sensitive enums (prod, staging, admin), and descriptions mentioning production infrastructure.

#### Observations

- **medium**: Sensitive default values or enum values
- **low**: Sensitive parameter names or description details
- **info**: No sensitive information in schemas

---

### mcp_tool_chain_analysis

**Analyze MCP tools for dangerous capability combinations.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_tools is truthy` |
| Produces | `mcp_dangerous_chains` |

Tags tools with capabilities (file_read, file_write, command_exec, network_request, data_exfil, database_access, credential_access, remote_access, scheduling, search_recon, browser) and detects 6 dangerous chain categories.

#### Observations

- **critical**: Data Read + Exfiltration, Credential + Network, File + Code Exec, Write + Persistence, Database + Exfiltration
- **high**: Recon + Lateral Movement
- **medium**: Partial chain (data access without exfil vector)

---

### mcp_notification_injection

**Test if MCP server accepts unsolicited client notifications.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_notification_status` |

Sends JSON-RPC notifications to test standard MCP notifications (cancelled, progress, tools/list_changed, resources/list_changed, roots/list_changed) and custom/arbitrary methods.

#### Observations

- **high**: Server accepts tools/list_changed or roots/list_changed from client
- **medium**: Server accepts resources/list_changed or cancelled from client
- **low**: Server accepts arbitrary custom notifications
- **info**: Server properly rejects unsolicited notifications

---

### mcp_sampling_abuse

**Test MCP sampling endpoint for open LLM proxy and filter bypass.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_sampling_status` |

Tests sampling/createMessage endpoint. Checks if sampling is exposed despite not being declared. Tests if client-supplied systemPrompt parameter is accepted. Intrusive check.

#### Observations

- **high**: Sampling endpoint exposed as open LLM proxy
- **high**: Undeclared sampling endpoint accessible
- **medium**: Sampling accepts client-supplied system prompt
- **info**: Sampling not exposed or properly restricted

---

### mcp_tool_rate_limit

**Test if MCP tool invocations are rate limited.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_tools is truthy` AND `mcp_servers is truthy` |
| Produces | `mcp_rate_limit_status` |

Sends 10 rapid tool invocations within a 2-second window. Prefers low-risk tools for testing. Intrusive check.

#### Observations

- **medium**: No per-tool rate limiting (all requests succeeded)
- **info**: Rate limiting detected (429 responses)

---

## Phase 4 — Active Probing (requires tool invocation)

### mcp_tool_invocation

**Probe MCP tools with safe test payloads to validate risk.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_tools is truthy` AND `mcp_servers is truthy` |
| Produces | `mcp_invocation_results` |

Generates safe, non-destructive payloads per tool type (exec: echo hostname, file: safe system files, fetch: httpbin.org, search: read-only queries). Invokes via tools/call and analyzes responses. Intrusive check.

#### Observations

- **critical**: Tool executes commands or reads files (real output)
- **high**: Tool makes HTTP requests (SSRF risk) or queries databases (real data)
- **medium**: Tool executes but requires auth

---

### mcp_resource_traversal

**Test MCP resource URIs for path traversal and SSRF.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_resource_traversal_results` |

Enumerates resources via resources/list. Tests path traversal payloads (relative, absolute, encoded, null byte), SSRF payloads (AWS/Azure/GCP metadata, localhost services), and protocol smuggling (gopher, dict). Intrusive check.

#### Observations

- **critical**: Path traversal returns file contents
- **critical**: SSRF returns internal service data
- **high**: Non-standard protocol accepted
- **medium**: Error message leaks file path

---

### mcp_template_injection

**Test MCP resource template parameters for injection.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_template_injection_results` |

Enumerates resource templates, extracts URI parameters, and injects SQL, path traversal, command, and template nesting payloads. Intrusive check.

#### Observations

- **critical**: Command or path traversal injection successful
- **high**: SQL injection error or unsanitized parameter
- **medium**: Template nesting injection detected

---

## Phase 5 — Cross-Suite (depends on MCP + AI suite)

### mcp_prompt_injection

**Test for prompt injection via MCP tool results flowing into LLM context.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_tools is truthy` AND `mcp_servers is truthy` |
| Produces | `mcp_injection_results` |

Identifies text-returning tools (fetch, browse, search, read). Invokes tool and checks if unfiltered external content reaches the LLM context. Tests if chat endpoint is influenced by tool result content. Intrusive check.

#### Observations

- **critical**: Tool result injection — LLM influenced by tool content
- **high**: Tool returns unfiltered external content
- **info**: No text-returning tools or results appear sanitized
