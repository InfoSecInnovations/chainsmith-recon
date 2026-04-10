# Phase 37 --- Scenario Expansion

## Problem

The `fakobanko` and `demo-domain` scenarios were authored when the tool had
far fewer checks and chain patterns.  Chainsmith now ships **133 checks
across 7 suites** and **42 attack-chain patterns**, but neither scenario
exercises the full breadth of these capabilities.

| Gap area | fakobanko | demo-domain |
|----------|-----------|-------------|
| CAG suite (17 checks) | Has `cache` service but only 2-3 CAG findings wired | No cache service at all |
| RAG suite (17 checks) | Has `rag` service but limited to 3 expected findings | No RAG service |
| Agent suite (17 checks) | Has `agent` service; only 3 of 17 checks represented | Has `agent` but only MCP-style, no LangServe/crew/autogen coverage |
| MCP suite (18 checks) | 2 expected findings; misses shadow tools, transport security, sampling, protocol downgrade | 3 MCP findings; same gaps |
| AI suite (27 checks) | Covers ~7; misses jailbreak, multiturn, adversarial_input, guardrail_consistency, training_data, streaming, history_leak, function_abuse, cache_detect | Covers ~7; same gaps |
| Web suite (23 checks) | Covers ~4; misses vcs_exposure, config_exposure, directory_listing, debug_endpoints, cookie_security, waf_detection, mass_assignment, etc. | Similar coverage gaps |
| Network suite (13 checks) | DNS only; misses TLS, ports, banner_grab, IPv6, whois, traceroute, geoip | DNS + service_probe only |
| Chain patterns (42 total) | 7 expected chains | 6 expected chains |

Both scenarios also lack findings and services that would trigger the newer
cross-suite chain patterns (e.g., `ssrf_via_agent_callback`,
`multi_agent_lateral_injection`, `cag_warming_injection_persistence`).

## Goals

1. Every check suite has at least one scenario that meaningfully exercises
   **every check** in that suite, so new users see representative output.
2. Every chain pattern has at least one scenario that can trigger it.
3. The two scenarios remain **thematically distinct** --- banking vs.
   corporate IT --- and each focuses on different parts of the attack
   surface so they complement rather than duplicate.
4. Scenario randomization (`random_pool` / `random_count`) is preserved to
   keep repeat runs interesting, but the union of `certain` + `random_pool`
   covers all reachable findings.
5. `expected_findings` and `expected_chains` stay accurate so test
   validation remains reliable.

## Plan

### 1. Fakobanko --- full-stack AI-bank (primary showcase)

Fakobanko already has the most services.  Expand it to be the
**comprehensive** scenario that touches all 7 suites.

#### New / expanded services

| Service | Purpose | New checks exercised |
|---------|---------|---------------------|
| `cache` (existing) | Expand simulations | All 17 CAG checks: cache_eviction, cache_warming, ttl_mapping, multi_layer_cache, cache_quota, provider_caching, cross_user_leakage, cache_key_reverse, semantic_threshold, side_channel, stale_context, cache_poisoning, injection_persistence, serialization, distributed_cache |
| `rag` (existing) | Expand simulations | All 17 RAG checks: vector_store_access, auth_bypass, collection_enumeration, embedding_fingerprint, document_exfiltration, retrieval_manipulation, source_attribution, cache_poisoning, corpus_poisoning, metadata_injection, chunk_boundary, multimodal_injection, fusion_reranker, cross_collection, adversarial_embedding |
| `agent` (existing) | Add multi-agent and advanced behaviors | multi_agent_detection, memory_extraction, privilege_escalation, loop_detection, callback_injection, streaming_injection, framework_exploits, memory_poisoning, context_overflow, reflection_abuse, state_manipulation, trust_chain, cross_injection |
| `mcp` (existing) | Add transport and advanced MCP | websocket_transport, tool_chain_analysis, shadow_tool_detection, schema_leakage, server_fingerprint, transport_security, notification_injection, resource_traversal, template_injection, prompt_injection, sampling_abuse, protocol_version, rate_limit, undeclared_capabilities |
| `www` (existing) | Add web-depth checks | vcs_exposure, config_exposure, directory_listing, debug_endpoints, cookie_security, waf_detection, sitemap, redirect_chain, error_page, ssrf_indicator, favicon, http2_detection, hsts_preload, sri_check, mass_assignment, default_creds, auth_detection, webdav |
| `chat` (existing) | Add advanced AI checks | jailbreak, multiturn, input_format, model_enum, token_cost, system_inject, output_format, param_inject, streaming, auth_bypass, model_fingerprint, history_leak, function_abuse, guardrail_consistency, training_data, adversarial_input, cache_detect |
| `api` (existing) | Expand network-layer | tls_analysis, ports, banner_grab, ipv6_discovery, whois_lookup, traceroute, geoip, http_method_enum |

#### New expected chains

Add chain coverage for all 42 patterns.  Notable additions:

- `ssrf_via_agent_callback`
- `multi_agent_lateral_injection`
- `agent_persistent_memory_compromise`
- `agent_privilege_escalation_via_tools`
- `cag_warming_injection_persistence`
- `cag_stale_privilege_persistence`
- `cag_timing_surveillance`
- `rag_corpus_poisoning_pipeline`
- `rag_cross_collection_leak`
- `rag_metadata_trust_manipulation`
- `mcp_shadow_tool_exploitation`
- `mcp_resource_traversal_chain`
- `mcp_agent_hybrid_attack`
- `full_llm_compromise_pipeline`
- `content_filter_bypass_pipeline`
- `infrastructure_informed_ai_attack`
- `embedding_data_extraction`
- `credential_compromise_chain`
- `openapi_mass_assignment`
- `cross_origin_ai_abuse`
- `financial_denial_of_service`

#### Randomization update

Move newly wired findings into `random_pool` so the scenario doesn't become
overwhelming on every run, but keep a representative `certain` set that
always fires for demos.

### 2. Demo-domain --- corporate IT with RAG and cache tiers

Demo-domain should stay simpler than fakobanko but gain the services it
currently lacks entirely.

#### New services

| Service | Port | Purpose |
|---------|------|---------|
| `rag` | 8204 | Internal knowledge base (HR policies, IT runbooks) |
| `cache` | 8205 | Semantic response cache for the chat assistant |
| `docs` | 8206 | Internal API/tool documentation portal |

#### Expanded coverage targets

- **RAG**: discovery, indirect_injection, document_exfiltration,
  collection_enumeration, source_attribution, corpus_poisoning (6 of 17 ---
  enough to show the suite without duplicating fakobanko's full depth)
- **CAG**: discovery, cache_probe, cross_user_leakage, cache_poisoning,
  stale_context (5 of 17)
- **Agent**: Expand from MCP-only to include agent_goal_injection,
  agent_memory_extraction, agent_tool_abuse, agent_privilege_escalation
- **Web**: Add cookie_security, config_exposure, debug_endpoints,
  directory_listing, auth_detection
- **AI**: Add jailbreak, multiturn, guardrail_consistency, history_leak
- **Network**: Add tls_analysis, http_method_enum

#### New expected chains

- `rag_pipeline_compromise`
- `rag_data_theft`
- `cag_cross_user_data_exposure`
- `cag_persistent_poisoning`
- `agent_hijacking`
- `agent_guardrail_bypass`
- `credential_compromise_chain`
- `security_header_weakness`

### 3. Service implementation work

For each new or expanded service endpoint:

- Add simulation YAML files so the scenario runs without a live target.
- Add or update service Python files under `scenarios/<name>/services/`.
- Update `docker-compose.yml` to include new service containers.
- Update `randomize.json` if new random finding pools are added.

### 4. Test updates

- Update or add test fixtures that validate every expected finding and
  expected chain fires correctly against the expanded simulations.
- Add a coverage matrix test that asserts: for every registered check,
  at least one scenario lists a corresponding expected finding.

## Open questions

- Should a **third scenario** be created instead of stretching the two
  existing ones?  A healthcare or e-commerce theme could cover domain-
  specific patterns (HIPAA language in RAG, PCI in caching).
- How deep should simulation fidelity go for the new checks?  Some checks
  (e.g., `traceroute`, `whois_lookup`) are inherently infrastructure-level
  and may not map cleanly to a simulated scenario.
- Should the `random_count` ranges increase to reflect the larger pools,
  or stay tight to keep demo runs focused?

## Success criteria

- `chainsmith scan --scenario fakobanko` produces findings from all 7
  suites and triggers >= 30 of 42 chain patterns.
- `chainsmith scan --scenario demo-domain` produces findings from all 7
  suites and triggers >= 15 of 42 chain patterns.
- No existing test breaks.
- Both scenarios remain runnable in under 5 minutes on a single machine.
