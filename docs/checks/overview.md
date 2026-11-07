# Check Reference

Chainsmith includes 133 checks organized into 7 suites.

Every check name carries its suite as a prefix (`network_`, `web_`, `ai_`, `mcp_`, `agent_`, `rag_`, `cag_`). Each check lives in its own folder, `app/checks/<suite>/<check_name>/`, and its `contract.yaml` is the authoritative record of what it depends on, what it produces, and how its observations are graded.

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
network_dns_enumeration ──► network_port_scan ──► network_service_probe ──┬──► web_header_analysis ──► ... (23 web checks)
  (target_hosts)              (services)            (services_probed)       │
                                                                            ├──► ai_llm_endpoint_discovery ──┬──► ai_prompt_leakage
                                                                            │                                ├──► ai_jailbreak_testing
                                                                            │                                └──► ... (28 AI checks total)
                                                                            │
                                                                            ├──► mcp_discovery ──► mcp_tool_enumeration
                                                                            │                    ├──► mcp_auth_check
                                                                            │                    ├──► mcp_shadow_tool_detection
                                                                            │                    ├──► mcp_tool_chain_analysis
                                                                            │                    ├──► mcp_tool_invocation
                                                                            │                    └──► ... (18 MCP checks total)
                                                                            │
                                                                            ├──► agent_discovery ──► agent_multi_agent_detection
                                                                            │                      ├──► agent_framework_version
                                                                            │                      ├──► agent_goal_injection
                                                                            │                      ├──► agent_tool_abuse
                                                                            │                      ├──► agent_trust_chain
                                                                            │                      └──► ... (17 agent checks total)
                                                                            │
                                                                            ├──► rag_discovery ──► rag_vector_store_access
                                                                            │                    ├──► rag_indirect_injection
                                                                            │                    ├──► rag_corpus_poisoning
                                                                            │                    ├──► rag_cross_collection
                                                                            │                    └──► ... (17 RAG checks total)
                                                                            │
                                                                            └──► cag_discovery ──► cag_cache_probe
                                                                                                 ├──► cag_cross_user_leakage
                                                                                                 ├──► cag_cache_poisoning
                                                                                                 ├──► cag_injection_persistence
                                                                                                 └──► ... (17 CAG checks total)
```

`network_dns_records` and `network_wildcard_dns` are also entry points; `network_geoip`, `network_reverse_dns`, `network_whois_lookup`, and `network_traceroute` build on DNS results. Most web checks need only `services`; the AI, MCP, agent, RAG, and CAG discovery checks also wait for `services_probed` so they see classified services.

## Check Anatomy

Each check has:

- **name**: Unique identifier, suite-prefixed (matches the folder name)
- **description**: What it does
- **depends_on** (shown as *Conditions* in these pages): Requirements to run (e.g., `services is truthy`)
- **produces**: Outputs added to context (e.g., `mcp_servers`)
- **intrusive**: Whether it actively probes (injection, writes, auth attempts)
- **severity**: How its observations are graded — a fixed severity per observation type, or a contextual default and range
- **reason**: Why a pentester would run this
- **references**: OWASP, CWE, MITRE links

Every check is split into a **probe**, which sends traffic and records what came back, and a **grade**, which reads that response and decides what it means and how severe it is. Because grading reads the recorded response rather than the network, a scan captured with `--capture` can be re-graded later without re-sending anything.

## Observation Severities

| Severity | Description | Examples |
|----------|-------------|----------|
| **critical** | Immediate exploitation risk | SQL exec tool, prompt leak with creds |
| **high** | Significant security issue | Goal injection, cross-session leak |
| **medium** | Notable observation | Unauthenticated endpoints |
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
