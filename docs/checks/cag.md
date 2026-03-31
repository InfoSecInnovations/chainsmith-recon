# CAG Suite

Cache-Augmented Generation discovery and vulnerability testing.

## cag_discovery

**Discover semantic cache infrastructure.**

| Property | Value |
|----------|-------|
| Conditions | `services is truthy` |
| Produces | `cag_endpoints`, `cache_infrastructure` |

Detects caching systems:

| Cache Type | Indicators |
|------------|------------|
| GPTCache | `/gptcache`, config patterns |
| Semantic Cache | `x-semantic-cache` header |
| Prompt Cache | `x-prompt-tokens-cached` header |
| Redis Cache | `x-cache-backend: redis` |

### Cache Headers

- `x-cache`, `x-cache-hit`, `x-cache-status`
- `x-cache-age`, `age`
- `x-context-id`
- `x-prompt-tokens-cached`

### Findings

- **medium**: Cache management endpoint exposed
- **low**: Cache infrastructure detected
- **info**: Caching enabled

---

## cag_cache_probe

**Probe cache for security vulnerabilities.**

| Property | Value |
|----------|-------|
| Conditions | `cag_endpoints is truthy` |
| Produces | `cache_vulnerabilities`, `cache_timing_results` |

Runs four tests:

### 1. Cross-Session Leak

Injects a unique marker in one session, checks if it appears in another.

**Severity**: high (if leaked)

### 2. Cache Timing

Measures response times across 3 requests:

```
Request 1: 245ms (miss)
Request 2: 18ms  (hit)
Request 3: 11ms  (hit)
```

Speedup ratio > 70% indicates timing side-channel.

**Severity**: medium

### 3. Context ID Enumeration

Probes predictable context IDs (`1`, `0`, `admin`, `test`, `default`).

**Severity**: medium (if accessible)

### 4. Cache Key Collision

Tests if semantically similar queries return identical cached responses.

**Severity**: low (integrity risk)

### Findings

- **high**: Cross-session data leakage
- **medium**: Context ID enumeration possible
- **medium**: Cache timing side-channel
- **low**: Cache key collision detected

### Example Output

```yaml
cache_vulnerabilities:
  - vulnerability_type: cross_session_leak
    severity: high
    evidence:
      marker_sent: "UNIQUE_MARKER_12345"
      marker_found_in_session_b: true

cache_timing_results:
  - test_type: cache_timing
    speedup_ratio: 0.95
    caching_detected: true
```

### References

- [CWE-524: Use of Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/524.html)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
