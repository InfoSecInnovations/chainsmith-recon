# MCP Suite

Model Context Protocol server discovery and tool enumeration.

## mcp_discovery

**Discover MCP server endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `mcp_servers` |

Probes for MCP endpoints at common paths:

- `/.well-known/mcp`
- `/mcp`
- `/mcp/sse`
- `/v1/mcp`
- `/api/mcp`

Detects MCP via headers (`mcp-session-id`, `x-mcp-version`), JSON-RPC 2.0 responses, and SSE content types.

### Findings

- **medium**: MCP server found (no auth)
- **info**: MCP server found (auth required)

---

## mcp_tool_enumeration

**Enumerate tools exposed by MCP servers.**

| Property | Value |
|----------|-------|
| Conditions | `mcp_servers is truthy` |
| Produces | `mcp_tools`, `high_risk_tools` |

Lists available tools and assesses risk based on capabilities:

| Risk Level | Indicators |
|------------|------------|
| **critical** | exec, shell, eval, run_command, system |
| **high** | file_write, http_request, sql_query, send_email |
| **medium** | file_read, env, secrets, credentials |
| **low** | read-only operations |
| **info** | Benign tools |

### Findings

- **critical**: Command execution tool (e.g., `execute_sql`)
- **high**: File write or HTTP request tool
- **medium**: Environment/secrets access
- **info**: Tools enumerated

### Example Output

```yaml
high_risk_tools:
  - name: execute_sql
    risk_level: critical
    reason: Direct SQL execution allows database manipulation
  - name: transfer_funds
    risk_level: high
    reason: Financial transfer capability
```

### References

- [OWASP LLM07: Insecure Plugin Design](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
