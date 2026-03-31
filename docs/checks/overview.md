# Check Reference

Chainsmith includes 25 checks organized into 7 suites.

## Suite Execution Order

Checks run in dependency order:

```
network → web → ai → mcp → agent → rag → cag
```

Within each suite, checks with dependencies wait for their requirements.

## Suite Summary

| Suite | Checks | Entry Point | Purpose |
|-------|--------|-------------|---------|
| [network](network.md) | 2 | Yes | Service discovery |
| [web](web.md) | 5 | No | HTTP analysis |
| [ai](ai.md) | 10 | No | LLM/ML endpoints |
| [mcp](mcp.md) | 2 | No | MCP servers |
| [agent](agent.md) | 2 | No | AI agents |
| [rag](rag.md) | 2 | No | RAG systems |
| [cag](cag.md) | 2 | No | Cache systems |

## Dependency Flow

```
dns_enumeration ──┬──► service_probe ──┬──► header_analysis
                  │                    ├──► robots_txt
                  │                    ├──► llm_endpoint_discovery ──► prompt_leakage
                  │                    ├──► mcp_discovery ──► mcp_tool_enumeration
                  │                    ├──► agent_discovery ──► agent_goal_injection
                  │                    ├──► rag_discovery ──► rag_indirect_injection
                  │                    └──► cag_discovery ──► cag_cache_probe
```

## Check Anatomy

Each check has:

- **name**: Unique identifier
- **description**: What it does
- **conditions**: Requirements to run (e.g., `services is truthy`)
- **produces**: Outputs added to context (e.g., `mcp_servers`)
- **reason**: Why a pentester would run this
- **references**: OWASP, CWE, MITRE links

## Finding Severities

| Severity | Description | Examples |
|----------|-------------|----------|
| **critical** | Immediate exploitation risk | SQL exec tool, prompt leak with creds |
| **high** | Significant security issue | Goal injection, cross-session leak |
| **medium** | Notable finding | Unauthenticated endpoints |
| **low** | Minor issue | Info disclosure |
| **info** | Informational | Service detected |

## Running Specific Checks

```bash
# By name
chainsmith scan example.com -c mcp_discovery -c mcp_tool_enumeration

# By suite
chainsmith scan example.com --suite mcp

# View what's available
chainsmith list-checks --suite mcp --verbose
```
