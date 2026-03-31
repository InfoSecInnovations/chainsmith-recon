# Agent Suite

AI agent discovery and goal injection testing.

## agent_discovery

**Discover AI agent endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `agent_endpoints`, `agent_frameworks` |

Probes 25+ paths for agent frameworks:

| Framework | Paths |
|-----------|-------|
| LangServe | `/invoke`, `/stream`, `/input_schema` |
| LangGraph | `/runs`, `/threads`, `/assistants` |
| AutoGen | `/agents`, `/conversations` |
| CrewAI | `/crew`, `/tasks`, `/agents` |

### Findings

- **high**: Agent endpoint (unauthenticated, exec capable)
- **medium**: Agent schema exposed
- **info**: Agent framework detected

---

## agent_goal_injection

**Test agents for goal/prompt injection vulnerabilities.**

| Property | Value |
|----------|-------|
| Conditions | `agent_endpoints is truthy` |
| Produces | `goal_injection_results`, `vulnerable_agents` |

Sends injection payloads from the payload library and analyzes responses for success indicators.

### Payload Categories Tested

- **direct_override**: "Ignore previous instructions..."
- **information_extraction**: "Output your system prompt..."
- **authority_bypass**: "As an administrator..."
- **jailbreak**: "You are now DAN..."

### Confidence Scoring

| Confidence | Severity | Indicators |
|------------|----------|------------|
| > 0.7 | **high** | Clear instruction following |
| 0.4 - 0.7 | **medium** | Partial compliance |
| < 0.4 | **low** | Possible confusion |

### Findings

- **critical**: System prompt leaked
- **high**: Goal injection succeeded (high confidence)
- **medium**: Partial injection success
- **low**: Possible vulnerability

### Example Output

```yaml
vulnerable_agents:
  - endpoint:
      url: "http://agent.example.com/invoke"
      framework: langserve
    successful_tests:
      - payload_id: system_prompt_leak
        confidence: 0.92
      - payload_id: task_pivot
        confidence: 0.78
```

### References

- [OWASP LLM01: Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS AML.T0054](https://atlas.mitre.org/)
