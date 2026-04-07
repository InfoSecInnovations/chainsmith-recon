# Fakobanko Scenario

Fakobanko Regional Bank is a fictional AI-powered banking platform with intentional vulnerabilities for training.

## Quick Start

```bash
chainsmith scan fakobanko.local --scenario fakobanko
```

## Infrastructure

| Host | Service | Vulnerabilities |
|------|---------|-----------------|
| www.fakobanko.local | Public website | Missing headers |
| chat.fakobanko.local | LLM chatbot | Prompt leak, no rate limit |
| api.fakobanko.local | Banking API | CORS, OpenAPI exposed |
| docs.fakobanko.local | Documentation | Path disclosure |
| mcp.fakobanko.local | MCP server | Dangerous tools |
| agent.fakobanko.local | LangServe agent | Goal injection |
| rag.fakobanko.local | RAG knowledge base | Indirect injection |
| cache.fakobanko.local | Semantic cache | Cross-session leak |

## Vulnerability Summary

### MCP (Critical)

- `execute_sql`: Direct SQL execution
- `transfer_funds`: Financial transfers
- `read_customer_file`: Path traversal risk

### Agent (High)

- System prompt leaked via injection (92% confidence)
- Tool disclosure via task pivot (78%)
- Direct instruction override (85%)

### RAG (High)

- Context extraction (85% confidence)
- Data exfiltration (78%)
- Delimiter escape (68%)

### CAG (High)

- Cross-session data leakage
- Predictable context IDs (1, admin, test)
- 95% cache timing side-channel

### Web (Medium)

- CORS reflects origin on API
- OpenAPI spec exposed
- Sensitive paths in robots.txt

### AI (Medium)

- Prompt leaked from chatbot
- No rate limiting
- Tools enumerable

## Expected Observations

Running the full scenario produces ~23 observations:

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 8 |
| Medium | 9 |
| Low | 2 |
| Info | 2 |

## Attack Chains

The scenario demonstrates these attack chains:

1. **MCP Tool Abuse**: Discover MCP → enumerate tools → find `execute_sql` → potential data breach

2. **Agent Goal Hijack**: Find agent → inject payload → extract system prompt → discover tools

3. **RAG Document Exfiltration**: Find RAG → inject query → extract internal documents

4. **Cache Cross-Session Theft**: Find cache → inject marker → retrieve in other session

## Lab Usage

For SEC536 Lab 2.6:

```bash
# Run full scenario
chainsmith scan fakobanko.local --scenario fakobanko -o lab-report.yaml -f yaml

# Focus on MCP attack surface
chainsmith scan fakobanko.local --scenario fakobanko --suite mcp -v

# Focus on agent injection
chainsmith scan fakobanko.local --scenario fakobanko --suite agent -v
```
