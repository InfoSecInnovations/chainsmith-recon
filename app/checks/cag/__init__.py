"""
app/checks/cag - CAG Suite

Cache-Augmented Generation reconnaissance checks.
Audits caching infrastructure for poisoning, cross-user leakage,
stale context exploitation, and timing-based side channels.

Implemented checks:
  cag_discovery      - Detect CAG endpoints and cache infrastructure
  cag_cache_probe    - Probe for cache vulnerabilities

Supported cache backends:
  - GPTCache (semantic caching)
  - Semantic cache layers
  - Prompt caching (Anthropic, OpenAI)
  - KV cache exposure
  - Redis-backed caches

Backlog checks:
  cag_cache_poisoning    - Inject malicious content into cache
  cag_cache_dos          - Cache-based denial of service testing
  cag_stale_context      - Exploit outdated cached context
  cag_cache_eviction     - Test cache eviction behavior
  cag_semantic_collision - Semantic cache key collision attacks
  cag_context_overflow   - Overflow context to evict cache entries

Attack patterns:
  cache_poison_to_exfil    - Poison cache -> serve to other users -> exfiltrate
  timing_oracle            - Timing analysis -> infer cache contents
  cross_user_context       - Cache leakage -> access other user data
  stale_context_abuse      - Trigger stale cache -> use outdated permissions

References:
  https://www.anthropic.com/news/prompt-caching
  https://platform.openai.com/docs/guides/prompt-caching
  https://github.com/zilliztech/GPTCache
  https://portswigger.net/web-security/web-cache-poisoning
"""

from app.checks.base import BaseCheck
from app.checks.cag.discovery import CAGDiscoveryCheck
from app.checks.cag.cache_probe import CAGCacheProbeCheck

__all__ = [
    "CAGDiscoveryCheck",
    "CAGCacheProbeCheck",
]


def get_checks() -> list[type[BaseCheck]]:
    """Return all implemented CAG checks."""
    return [
        CAGDiscoveryCheck,
        CAGCacheProbeCheck,
    ]
