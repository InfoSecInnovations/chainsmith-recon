"""
app/checks/cag - CAG Suite

Cache-Augmented Generation reconnaissance checks.
Audits caching infrastructure for poisoning, cross-user leakage,
stale context exploitation, and timing-based side channels.

Implemented checks:
  Phase 1 (discovery):
    cag_discovery          - Detect CAG endpoints and cache infrastructure
    cag_cache_probe        - Probe for cache vulnerabilities

  Phase 2 (infrastructure analysis):
    cag_cache_eviction     - Test cache management endpoint accessibility
    cag_cache_warming      - Test cache warming endpoint abuse
    cag_ttl_mapping        - Map cache TTL and expiry behavior
    cag_multi_layer_cache  - Detect multiple cache layers
    cag_cache_quota        - Test cache size limits and eviction
    cag_provider_caching   - Analyze provider-level prompt caching

  Phase 3 (deep probing):
    cag_cross_user_leakage - Test cache isolation across auth contexts
    cag_cache_key_reverse  - Map cache key components
    cag_semantic_threshold - Probe semantic cache similarity threshold
    cag_side_channel       - Detect cache timing side-channels
    cag_stale_context      - Test stale context exploitation

  Phase 4 (active exploitation, --aggressive):
    cag_cache_poisoning    - Test cache poisoning with injected content
    cag_injection_persistence - Test prompt injection persistence via cache

  Phase 5 (advanced, infrastructure-dependent):
    cag_serialization      - Detect unsafe cache serialization formats
    cag_distributed_cache  - Detect multi-node cache topology

Supported cache backends:
  - GPTCache (semantic caching)
  - Semantic cache layers
  - Prompt caching (Anthropic, OpenAI)
  - KV cache exposure
  - Redis-backed caches

Attack patterns:
  cache_poison_to_exfil    - Poison cache -> serve to other users -> exfiltrate
  timing_oracle            - Timing analysis -> infer cache contents
  cross_user_context       - Cache leakage -> access other user data
  stale_context_abuse      - Trigger stale cache -> use outdated permissions
  injection_persistence    - Prompt injection -> cache -> multi-user compromise

References:
  https://www.anthropic.com/news/prompt-caching
  https://platform.openai.com/docs/guides/prompt-caching
  https://github.com/zilliztech/GPTCache
  https://portswigger.net/web-security/web-cache-poisoning
"""

from app.checks.base import BaseCheck

# Phase 1: Discovery
from app.checks.cag.discovery import CAGDiscoveryCheck
from app.checks.cag.cache_probe import CAGCacheProbeCheck

# Phase 2: Infrastructure analysis
from app.checks.cag.cache_eviction import CacheEvictionCheck
from app.checks.cag.cache_warming import CacheWarmingCheck
from app.checks.cag.ttl_mapping import TTLMappingCheck
from app.checks.cag.multi_layer import MultiLayerCacheCheck
from app.checks.cag.cache_quota import CacheQuotaCheck
from app.checks.cag.provider_caching import ProviderCachingCheck

# Phase 3: Deep probing
from app.checks.cag.cross_user_leakage import CrossUserLeakageCheck
from app.checks.cag.cache_key_reverse import CacheKeyReverseCheck
from app.checks.cag.semantic_threshold import SemanticThresholdCheck
from app.checks.cag.side_channel import SideChannelCheck
from app.checks.cag.stale_context import StaleContextCheck

# Phase 4: Active exploitation
from app.checks.cag.cache_poisoning import CachePoisoningCheck
from app.checks.cag.injection_persistence import InjectionPersistenceCheck

# Phase 5: Advanced
from app.checks.cag.serialization import SerializationCheck
from app.checks.cag.distributed_cache import DistributedCacheCheck

__all__ = [
    # Phase 1
    "CAGDiscoveryCheck",
    "CAGCacheProbeCheck",
    # Phase 2
    "CacheEvictionCheck",
    "CacheWarmingCheck",
    "TTLMappingCheck",
    "MultiLayerCacheCheck",
    "CacheQuotaCheck",
    "ProviderCachingCheck",
    # Phase 3
    "CrossUserLeakageCheck",
    "CacheKeyReverseCheck",
    "SemanticThresholdCheck",
    "SideChannelCheck",
    "StaleContextCheck",
    # Phase 4
    "CachePoisoningCheck",
    "InjectionPersistenceCheck",
    # Phase 5
    "SerializationCheck",
    "DistributedCacheCheck",
]


def get_checks() -> list[type[BaseCheck]]:
    """Return all implemented CAG checks in dependency order."""
    return [
        # Phase 1
        CAGDiscoveryCheck,
        CAGCacheProbeCheck,
        # Phase 2
        CacheEvictionCheck,
        CacheWarmingCheck,
        TTLMappingCheck,
        MultiLayerCacheCheck,
        CacheQuotaCheck,
        ProviderCachingCheck,
        # Phase 3
        CrossUserLeakageCheck,
        CacheKeyReverseCheck,
        SemanticThresholdCheck,
        SideChannelCheck,
        StaleContextCheck,
        # Phase 4
        CachePoisoningCheck,
        InjectionPersistenceCheck,
        # Phase 5
        SerializationCheck,
        DistributedCacheCheck,
    ]
