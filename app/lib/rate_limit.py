"""
app/lib/rate_limit.py - Rate Limiter

Token-bucket rate limiter for controlling request cadence.
Supports per-host and global limits.

Usage:
    limiter = RateLimiter(requests_per_second=10.0)

    async def my_check():
        await limiter.acquire()      # blocks until token available
        response = await http.get(url)
"""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TokenBucket:
    """
    Simple token-bucket rate limiter for a single stream.

    Tokens refill continuously at `rate` per second up to `capacity`.
    Each acquire() consumes one token, sleeping if none are available.
    """
    rate: float                      # tokens per second
    capacity: float                  # maximum tokens (burst ceiling)
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)

    def __post_init__(self):
        self._tokens = self.capacity
        self._last_refill = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_refill
        added = elapsed * self.rate
        self._tokens = min(self.capacity, self._tokens + added)
        self._last_refill = now

    def available(self) -> float:
        """Return current token count after refill."""
        self._refill()
        return self._tokens

    def try_acquire(self) -> bool:
        """Attempt to acquire a token without blocking. Returns True if acquired."""
        self._refill()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def wait_time(self) -> float:
        """Seconds until a token is available."""
        self._refill()
        if self._tokens >= 1.0:
            return 0.0
        deficit = 1.0 - self._tokens
        return deficit / self.rate


class RateLimiter:
    """
    Async rate limiter backed by token buckets.

    Supports:
    - Global rate limit (all requests)
    - Per-host rate limit (optional, additive with global)

    Args:
        requests_per_second: Global rate (0 = unlimited)
        burst:               Max burst size (default: same as rate)
        per_host_rps:        Per-host rate limit (optional)
        per_host_burst:      Per-host burst ceiling (optional)
    """

    def __init__(
        self,
        requests_per_second: float = 10.0,
        burst: Optional[float] = None,
        per_host_rps: Optional[float] = None,
        per_host_burst: Optional[float] = None,
    ):
        self.requests_per_second = requests_per_second
        self.burst = burst or requests_per_second
        self.per_host_rps = per_host_rps
        self.per_host_burst = per_host_burst or per_host_rps

        self._global_bucket: Optional[TokenBucket] = None
        if requests_per_second > 0:
            self._global_bucket = TokenBucket(
                rate=requests_per_second,
                capacity=self.burst,
            )

        self._host_buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    def _get_host_bucket(self, host: str) -> Optional[TokenBucket]:
        if not self.per_host_rps:
            return None
        if host not in self._host_buckets:
            self._host_buckets[host] = TokenBucket(
                rate=self.per_host_rps,
                capacity=self.per_host_burst or self.per_host_rps,
            )
        return self._host_buckets[host]

    async def acquire(self, host: Optional[str] = None):
        """
        Wait until a request slot is available, then consume it.

        Args:
            host: Optional host for per-host limiting.
        """
        async with self._lock:
            buckets = []
            if self._global_bucket:
                buckets.append(self._global_bucket)
            if host:
                hb = self._get_host_bucket(host)
                if hb:
                    buckets.append(hb)

            if not buckets:
                return

            # Wait for the slowest bucket
            while True:
                wait_times = [b.wait_time() for b in buckets]
                max_wait = max(wait_times)
                if max_wait <= 0:
                    for b in buckets:
                        b.try_acquire()
                    return
                await asyncio.sleep(max_wait)

    def reset(self, host: Optional[str] = None):
        """Reset bucket(s) to full capacity."""
        if host is None:
            if self._global_bucket:
                self._global_bucket._tokens = self._global_bucket.capacity
            self._host_buckets.clear()
        else:
            if host in self._host_buckets:
                b = self._host_buckets[host]
                b._tokens = b.capacity


# ── Convenience factory ───────────────────────────────────────────

def make_polite_limiter(requests_per_second: float = 5.0) -> RateLimiter:
    """
    Create a rate limiter appropriate for recon against a target.
    Burst is capped at 2x rate to avoid hammering on startup.
    """
    return RateLimiter(
        requests_per_second=requests_per_second,
        burst=min(requests_per_second * 2, 20),
    )
