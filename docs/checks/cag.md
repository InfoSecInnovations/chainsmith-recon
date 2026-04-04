# CAG Suite

Cache-Augmented Generation discovery, infrastructure analysis, and cache exploitation testing.
17 checks organized in 5 phases by dependency order.

---

## Phase 1 — Discovery (depends on services)

### cag_discovery

**Detect Cache-Augmented Generation endpoints and caching infrastructure.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `cag_endpoints`, `cache_infrastructure` |

Probes cache-specific paths (/cache, /context, /precompute, /cache/warm, /prompt-cache, /semantic-cache). Detects cache infrastructure via signatures: GPTCache, semantic cache, prompt cache (Anthropic/OpenAI), KV cache, Redis. Analyzes response headers for cache indicators and performs timing analysis.

#### Findings

- **medium**: Cache infrastructure detected (no auth)
- **low**: CAG endpoint detected, caching behavior on AI endpoint
- **info**: Cache infrastructure detected (auth required)

---

### cag_cache_probe

**Probe CAG endpoints for cache leakage and poisoning vulnerabilities.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `cache_vulnerabilities`, `cache_timing_results` |

Runs 4 tests per endpoint: cross-session leak (marker in session A appears in session B), cache timing analysis (speedup ratio across successive requests), context ID enumeration (probes common IDs: 1, 0, admin, test, default), and cache key predictability (trailing space variation). Intrusive check.

#### Findings

- **high**: Cross-session cache leakage, cache key collision
- **medium**: Cache timing side-channel
- **low**: Context ID enumeration possible

---

## Phase 2 — Infrastructure Analysis (depends on cag_endpoints)

### cag_cache_eviction

**Test cache management endpoint accessibility and eviction behavior.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `eviction_capability` |

Tests bulk eviction endpoints (POST /cache/clear, /cache/flush, /cache/invalidate, DELETE /cache) and key-specific eviction (DELETE /cache/{key}). Intrusive check.

#### Findings

- **critical**: Cache eviction endpoint accessible without authentication
- **medium**: Cache eviction endpoint requires authentication

---

### cag_cache_warming

**Test if cache warming endpoints accept arbitrary content.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `warm_capability` |

Tests 4 warming endpoint categories (/cache/warm, /precompute, /cache/store, /cache/set) with test marker payloads. Verifies warming success and checks input validation. Cleanup attempted. Intrusive check.

#### Findings

- **critical**: Cache accepts arbitrary content without validation
- **high**: Cache warming endpoint accessible, no input validation
- **medium**: Cache warming accessible with validation, or requires auth

---

### cag_ttl_mapping

**Map cache TTL and expiry behavior to assess poisoning exposure windows.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `cache_ttl` |

Confirms caching via timing, extracts header-stated TTL (Cache-Control max-age, Expires, Age), re-queries at intervals (5s, 15s, 30s, 60s) to detect expiry. Compares header vs. observed TTL. Intrusive check.

#### Findings

- **medium**: Unbounded cache TTL (no expiry detected)
- **medium**: Cache TTL >300 seconds
- **low**: Cache TTL mismatch (header vs observed)
- **low/info**: Short/moderate TTL

---

### cag_multi_layer_cache

**Detect multiple cache layers and test bypass behavior.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `cache_layers` |

Tests 4 strategies with timing: normal request, Cache-Control: no-cache, Pragma: no-cache, and cache-buster parameter. Detects HTTP cache, application cache, semantic cache, and CDN layers.

#### Findings

- **medium**: Multiple cache layers detected (2+)
- **info**: Single cache layer

---

### cag_cache_quota

**Test cache size limits and eviction behavior under load.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `cache_size` |

Floods cache with 50 unique queries, then checks if early entries were evicted (LRU behavior). Estimates cache capacity. Intrusive check.

#### Findings

- **medium**: Cache exhaustion possible (LRU eviction confirmed)
- **medium**: Unbounded cache (memory exhaustion risk)
- **low**: Cache size estimated

---

### cag_provider_caching

**Analyze provider-level prompt caching behavior and token leakage.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `provider_cache_info` |

Tests OpenAI-style, Anthropic-style, and generic endpoints. Extracts usage metadata (cached_tokens, prompt_tokens_cached, cache_read_input_tokens). Detects shared system prompt prefix when multiple tests show similar cached token ratios.

#### Findings

- **medium**: Provider caching reveals shared system prompt
- **low**: Provider prompt caching active
- **info**: No provider-level prompt caching detected

---

## Phase 3 — Deep Probing (depends on Phase 1-2)

### cag_cross_user_leakage

**Test cache isolation across users, auth contexts, and API keys.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `isolation_status` |

Runs 4 isolation tests: auth vs no-auth, different tokens, user identity isolation, and API key isolation. Compares responses across contexts for leakage. Intrusive check.

#### Findings

- **critical**: Auth response served to no-auth request
- **critical**: Different tokens share cache
- **critical**: User identity not in cache key
- **high**: Different API keys share cache
- **info**: Cache properly isolates responses

---

### cag_cache_key_reverse

**Map cache key components by systematically varying query inputs.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `key_structure` |

Tests 5 query component variations (capitalization, punctuation, whitespace, prefix, suffix) and a system prompt test. Measures timing to determine which components are included in cache keys. Intrusive check.

#### Findings

- **high**: Cache key excludes system prompt (different systems share cache)
- **medium**: Cache key is case/whitespace/punctuation-insensitive
- **low**: Cache key includes most query components

---

### cag_semantic_threshold

**Probe semantic cache similarity threshold to estimate poisoning blast radius.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `similarity_threshold` |

Tests 6 query variations with decreasing semantic similarity (exact, minor_variation, rephrased, related, tangential, unrelated). Estimates threshold as midpoint between lowest hit and highest miss. Intrusive check.

#### Findings

- **high**: Loose semantic cache (threshold <= 0.6 or 4+ variations hit)
- **medium**: Moderate threshold (threshold <= 0.8 or 2+ hits)
- **low**: Tight semantic cache
- **info**: Exact match only (not a semantic cache)

---

### cag_side_channel

**Detect cache timing side-channels that reveal user query patterns.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `side_channel_risk` |

Establishes baseline with 3 unique queries, then tests 8 sensitive topics 3x each (salary, merger plans, employee reviews, API keys, vulnerabilities, financial projections, customer data, password procedures). Detects cache hits that reveal what users have been querying.

#### Findings

- **medium**: Cache timing side-channel (sensitive topics show cache hits)
- **low**: Cache timing oracle available (significant response variance)
- **info**: Timing analysis inconclusive

---

### cag_stale_context

**Test if cached context outlives its validity window enabling privilege persistence.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `stale_context_risk` |

Two tests: role-based (sends admin query, waits, checks if fresh user-role session gets admin response) and TTL staleness (confirms caching, waits past expected TTL, checks if entry persists). Intrusive check.

#### Findings

- **high**: Stale admin context served to fresh session (privilege persistence)
- **high**: Cached response still served past expected TTL
- **info**: Cache entries expire properly

---

## Phase 4 — Active Exploitation (intrusive)

### cag_cache_poisoning

**Test if injected content gets cached and served to other users.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `cache_poisoning_results` |

Exact query replay: injects marker in session A, queries from session B. Semantic poisoning: tests if 3 query variations also return the marker. Cleanup attempted. Intrusive check.

#### Findings

- **critical**: Injected marker found in cross-session response
- **critical**: Semantic cache amplifies poisoning (multiple variations affected)
- **high**: Poisoned response matched across sessions
- **medium/low**: Likely cached but cross-session delivery uncertain

---

### cag_injection_persistence

**Test if prompt injection responses get cached and persist across users.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `injection_persistence_results` |

Tests 3 injection patterns: ignore_instructions, system_override, role_escape. If injection succeeds, waits and queries from new session to check persistence. Semantic amplification test with 3 query variations. Cleanup attempted. Intrusive check.

#### Findings

- **critical**: Persistent injection via cache (served across users)
- **critical**: Semantic cache amplifies injection
- **high**: Injection cached but cross-user delivery unconfirmed
- **info**: Injection responses not cached

---

## Phase 5 — Advanced (infrastructure-dependent)

### cag_serialization

**Detect unsafe cache serialization formats that enable code execution.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `serialization_risks` |

Tests: direct Redis access (/redis, /cache/redis), serialization format detection (pickle header, type confusion JSON, malformed payloads), and path traversal in cache keys (../../../etc/passwd variants). Intrusive check.

#### Findings

- **critical**: Redis accessible without auth (RCE risk)
- **critical**: Cache uses pickle serialization (RCE via deserialization)
- **high**: Unsafe deserialization with type hints
- **high**: Path traversal in cache key mapping
- **medium**: Serialization format indicators detected

---

### cag_distributed_cache

**Detect multi-node cache topology and test replication consistency.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `distributed_cache_info` |

Sends 10 identical requests, extracts node identity from headers (x-cache-node, x-served-by, x-backend-server, x-instance-id, via, cf-ray). Detects load balancing pattern (sticky, round-robin, random) and checks response consistency across nodes. Intrusive check.

#### Findings

- **medium**: Cache replication inconsistency (different content from different nodes)
- **low**: Multiple cache nodes detected (consistent replication)
- **info**: Single node or consistent replication
