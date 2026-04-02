# AI Suite

LLM and ML endpoint discovery, analysis, and attack surface mapping.
28 checks organized in 4 phases by dependency order.

---

## Phase 1 — Service-level (no chat endpoint dependency)

### llm_endpoint_discovery

**Discover LLM chat/completion endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `chat_endpoints`, `completion_endpoints` |

Probes for OpenAI-compatible, Anthropic, and custom LLM endpoints.

#### Findings

- **medium**: LLM endpoint discovered (no auth)
- **info**: LLM endpoint found (auth required)

---

### embedding_endpoint_discovery

**Discover embedding API endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `embedding_endpoints` |

#### Findings

- **low**: Embedding endpoint accessible

---

### model_info_check

**Extract model information from endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `model_info` |

Identifies model names, versions, and capabilities.

#### Findings

- **medium**: Model info exposed
- **info**: Model version detected

---

### ai_framework_fingerprint

**Fingerprint AI frameworks.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `ai_framework_{port}` |

Detects LangChain, LlamaIndex, Hugging Face, vLLM, Ollama, etc.

#### Findings

- **info**: Framework detected

---

## Phase 2 — Chat endpoint-level

### ai_error_leakage

**Test for information leakage in error responses.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `error_leaks` |

#### Findings

- **medium**: Stack trace in error
- **low**: Debug info leaked

---

### content_filter_check

**Test content filtering and safety guardrails.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `content_filter_{port}` |

#### Findings

- **medium**: Weak content filtering
- **info**: Content filter detected

---

### rate_limit_check

**Test rate limiting on LLM endpoints.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `rate_limit_{port}` |

#### Findings

- **medium**: No rate limiting detected
- **info**: Rate limit headers present

---

### context_window_check

**Probe context window limits.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `context_{port}` |

#### Findings

- **info**: Context window size detected

---

### auth_bypass

**Test AI endpoint authentication for bypass vulnerabilities.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `auth_status_{port}` |

Tests no-auth, empty bearer, default API keys (sk-test, demo, EMPTY, test-key), and Basic test:test.

#### Findings

- **critical**: AI endpoint requires no authentication
- **critical**: Default API key accepted
- **high**: Auth bypass via empty Bearer token
- **info**: Authentication enforced

---

### model_enumeration

**Enumerate available models via the model parameter.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `available_models` |

Tests provider-specific model names (OpenAI, Anthropic, Meta, Mistral) plus generic names (default, staging, internal).

#### Findings

- **high**: Internal/staging model accessible
- **medium**: N models available
- **info**: Single model (no enumeration possible)

---

### api_parameter_injection

**Test for mass assignment via extra API parameters.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `accepted_params_{port}` |

Tests temperature, max_tokens, tools, logprobs, user, system, response_format, seed, stop.

#### Findings

- **critical**: Tool/function injection accepted
- **critical**: User impersonation possible
- **high**: Temperature override / logprobs exposed
- **medium**: max_tokens / stop / response_format override
- **info**: Extra parameters rejected

---

### streaming_analysis

**Test streaming support and filter bypass via SSE.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `streaming_{port}` |

Checks if stream=true produces SSE responses, then tests whether streaming bypasses content filters that operate on complete responses.

#### Findings

- **medium**: Streaming bypasses content filter
- **low**: Streaming supported (with TTFT measurement)
- **info**: Streaming not supported

---

### system_prompt_injection

**Test if client-supplied system messages override service prompts.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `system_inject_{port}` |

#### Findings

- **critical**: Client-supplied system prompt overrides service prompt
- **high**: System prompt accepted and processed
- **medium**: System message appended (does not override)
- **info**: System message ignored

---

### response_caching

**Detect response caching by comparing identical requests.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `cache_detection_{port}` |

Sends identical requests, compares content and timing, checks cache headers, tests temperature override.

#### Findings

- **medium**: Response caching detected (overrides temperature)
- **low**: Cache headers present
- **info**: No caching detected

---

## Phase 2E — Embedding endpoint-level

### embedding_extraction

**Analyze embedding endpoints for model identification and metadata leakage.**

| Property | Value |
|----------|-------|
| Conditions | `embedding_endpoints is truthy` |
| Produces | `embedding_analysis_{port}` |

Captures vectors, maps dimensionality to known models (ada-002=1536, BERT=768, MiniLM=384, etc.), computes cosine similarity to verify real model.

#### Findings

- **medium**: Embedding endpoint returns metadata beyond vectors
- **low**: Embedding model identified from dimensions
- **info**: Embedding endpoint functional (N-dimensional vectors)
- **info**: Embedding similarity confirms real model

---

## Phase 3 — Depends on Phase 2 results

### tool_discovery

**Enumerate tools/functions available to LLM.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `discovered_tools`, `chatbot_capabilities` |

#### Findings

- **high**: Dangerous tools available
- **medium**: Tools enumerated

---

### prompt_leakage

**Test for system prompt leakage.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `prompt_leak_findings` |

Uses various techniques to extract system prompts.

#### Findings

- **critical**: System prompt leaked (contains secrets)
- **high**: System prompt leaked
- **medium**: Partial prompt leak

---

### model_behavior_fingerprint

**Identify the actual underlying model via behavioral signatures.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `model_identity_{port}` |

Tests self-identification, knowledge cutoff, strawberry counting, creator attribution. Detects model misrepresentation (e.g., advertised GPT-4 but behavior matches GPT-3.5).

#### Findings

- **low**: Model misrepresents identity
- **info**: Model self-identifies as X
- **info**: Knowledge cutoff detected

---

### output_format_manipulation

**Test if model output format can be controlled for downstream injection.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `format_risks_{port}` |

#### Findings

- **medium**: Model produces arbitrary JSON / response_format bypass
- **low**: Model produces markdown with URLs
- **info**: Output format constrained

---

### conversation_history_leak

**Test for cross-session conversation history leakage.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `history_leak_{port}` |

Plants a canary string, then probes for it from a "different session". Also checks for general cross-session indicators.

#### Findings

- **critical**: Canary recovered from separate session
- **high**: Shared context detected (references prior interactions)
- **info**: No cross-session leakage detected

---

### training_data_extraction

**Test for memorization by probing with known text prefixes and repetition attacks.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `training_data_{port}` |

Completion probes with public domain text, repetition attacks that may trigger divergence into memorized content, PII pattern detection.

#### Findings

- **high**: PII patterns found in generated text
- **medium**: Repetition probe triggered diverse (memorized) output
- **info**: No memorization detected

---

### adversarial_input

**Test input handling with adversarial formatting and unicode attacks.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `adversarial_input_{port}` |

Tests homoglyphs (Cyrillic a), zero-width spaces/joiners, RTL overrides, null bytes, 5000-char tokens, mixed scripts.

#### Findings

- **high**: Multiple adversarial techniques bypass filter
- **medium**: Unicode/adversarial bypass detected
- **info**: Input sanitization appears robust

---

## Phase 4 — Depends on Phase 2-3, uses filter/tool knowledge

### jailbreak_testing

**Test content filter bypass techniques.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `jailbreak_{port}` |

8 techniques: DAN, roleplay, base64 encoding, translation, hypothetical framing, authority confusion, token smuggling, multi-step decomposition.

#### Findings

- **critical**: 3+ jailbreak techniques bypassed filters
- **high**: Jailbreak bypass detected
- **info**: All jailbreak techniques blocked

---

### multi_turn_injection

**Multi-message prompt extraction via graduated trust-building.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `multi_turn_{port}` |

4 conversation sequences: trust building, context flooding, conversation pivoting, false memory injection.

#### Findings

- **critical**: System prompt extracted via multi-turn
- **high**: Partial prompt leaked after trust-building
- **medium**: Model behavior changed after context flooding
- **info**: Multi-turn extraction blocked

---

### input_format_injection

**Test if format markers in user input are interpreted as role boundaries.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `input_format_{port}` |

6 injection types: markdown, XML, delimiter, JSON role, chat template markers, whitespace abuse.

#### Findings

- **high**: XML/chat template injection changed model behavior
- **medium**: Markdown injection partially accepted
- **info**: Input format injection rejected

---

### guardrail_consistency

**Test content filter consistency across languages, encodings, and phrasings.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `guardrail_consistency_{port}` |

7 languages (French, Spanish, German, Chinese, Japanese, Russian, Arabic), 2 encodings (base64, ROT13), 3 phrasing variants (ALL CAPS, aLtErNaTiNg, extra spaces).

#### Findings

- **high**: Blocked in English but allowed in other languages
- **high**: Encoding bypass (base64/ROT13 accepted)
- **medium**: Phrasing variation bypass
- **info**: Guardrails consistent across all variations

---

### function_calling_abuse

**Probe discovered tools for invocation, parameter injection, and privilege escalation.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy`, `discovered_tools is truthy` |
| Produces | `function_abuse_{port}` |

Tests direct invocation, SQL-injection-style parameter injection, permission escalation, tool chaining, and probes for undocumented tools.

#### Findings

- **critical**: Tool executes with elevated permissions
- **high**: Tool parameter injection (SQL injection via tool)
- **medium**: Tool invocation confirmed
- **info**: Tool invocation blocked by guardrails

---

### token_cost_exhaustion

**Test if expensive operations can be triggered beyond rate limiting.**

| Property | Value |
|----------|-------|
| Conditions | `chat_endpoints is truthy` |
| Produces | `token_cost_{port}` |

#### Findings

- **high**: No output token limit
- **medium**: Large completions accepted
- **info**: Token limits enforced
