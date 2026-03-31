# AI Suite

LLM and ML endpoint discovery and analysis.

## llm_endpoint_discovery

**Discover LLM chat/completion endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `chat_endpoints`, `completion_endpoints` |

Probes for OpenAI-compatible, Anthropic, and custom LLM endpoints.

### Findings

- **medium**: LLM endpoint discovered (no auth)
- **info**: LLM endpoint found (auth required)

---

## embedding_endpoint_discovery

**Discover embedding API endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `embedding_endpoints` |

### Findings

- **low**: Embedding endpoint accessible

---

## model_info_check

**Extract model information from endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `model_info` |

Identifies model names, versions, and capabilities.

### Findings

- **medium**: Model info exposed
- **info**: Model version detected

---

## ai_framework_fingerprint

**Fingerprint AI frameworks.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `ai_framework` |

Detects LangChain, LlamaIndex, Hugging Face, vLLM, Ollama, etc.

### Findings

- **info**: Framework detected

---

## ai_error_leakage

**Test for information leakage in error responses.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `error_leaks` |

### Findings

- **medium**: Stack trace in error
- **low**: Debug info leaked

---

## tool_discovery

**Enumerate tools/functions available to LLM.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `discovered_tools`, `chatbot_capabilities` |

### Findings

- **high**: Dangerous tools available
- **medium**: Tools enumerated

---

## prompt_leakage

**Test for system prompt leakage.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `prompt_leak_findings` |

Uses various techniques to extract system prompts.

### Findings

- **critical**: System prompt leaked (contains secrets)
- **high**: System prompt leaked
- **medium**: Partial prompt leak

---

## rate_limit_check

**Test rate limiting on LLM endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `rate_limit_info` |

### Findings

- **medium**: No rate limiting detected
- **info**: Rate limit headers present

---

## content_filter_check

**Test content filtering and safety guardrails.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `content_filter_info` |

### Findings

- **medium**: Weak content filtering
- **info**: Content filter detected

---

## context_window_check

**Probe context window limits.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `context_info` |

### Findings

- **info**: Context window size detected
