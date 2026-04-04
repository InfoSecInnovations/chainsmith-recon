# Check Reference

Chainsmith includes 123 checks organized into 7 suites.

## Suite Execution Order

Checks run in dependency order:

```
network → web → ai → mcp → agent → rag → cag
```

Within each suite, checks with dependencies wait for their requirements.

## Suite Summary

| Suite | Checks | Entry Point | Purpose |
|-------|--------|-------------|---------|
| [network](network.md) | 13 | Yes | Service discovery |
| [web](web.md) | 23 | No | HTTP analysis |
| [ai](ai.md) | 28 | No | LLM/ML endpoints |
| [mcp](mcp.md) | 18 | No | MCP servers |
| [agent](agent.md) | 17 | No | AI agents |
| [rag](rag.md) | 17 | No | RAG systems |
| [cag](cag.md) | 17 | No | Cache systems |

## Dependency Flow

```
dns_enumeration ──┬──► service_probe ──┬──► header_analysis ──► ... (23 web checks)
                  │                    │
                  │                    ├──► llm_endpoint_discovery ──┬──► prompt_leakage
                  │                    │                             ├──► jailbreak_testing
                  │                    │                             └──► ... (28 AI checks total)
                  │                    │
                  │                    ├──► mcp_discovery ──► mcp_tool_enumeration
                  │                    │                      ├──► mcp_auth_check
                  │                    │                      ├──► shadow_tool_detection
                  │                    │                      ├──► tool_chain_analysis
                  │                    │                      ├──► mcp_tool_invocation
                  │                    │                      └──► ... (18 MCP checks total)
                  │                    │
                  │                    ├──► agent_discovery ──► agent_multi_agent_detection
                  │                    │                      ├──► agent_framework_version
                  │                    │                      ├──► agent_goal_injection
                  │                    │                      ├──► agent_tool_abuse
                  │                    │                      ├──► agent_trust_chain
                  │                    │                      └──► ... (17 agent checks total)
                  │                    │
                  │                    ├──► rag_discovery ──► rag_vector_store_access
                  │                    │                    ├──► rag_indirect_injection
                  │                    │                    ├──► rag_corpus_poisoning
                  │                    │                    ├──► rag_cross_collection
                  │                    │                    └──► ... (17 RAG checks total)
                  │                    │
                  │                    └──► cag_discovery ──► cag_cache_probe
                  │                                        ├──► cag_cross_user_leakage
                  │                                        ├──► cag_cache_poisoning
                  │                                        ├──► cag_injection_persistence
                  │                                        └──► ... (17 CAG checks total)
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
