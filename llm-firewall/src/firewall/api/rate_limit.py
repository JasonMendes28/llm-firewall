"""Rate limiting.

Production Hardening:
- Striped / sharded mutexes: reduces thread lock contention by hashing keys across
  multiple independent locks (32 shards).
- Bounded memory & active eviction: buckets are limited by max_keys (default 10,000)
  and pruned of stale entries (idle > ttl_seconds), preventing memory leak DoS attacks.
- Protocol compatibility: implements the `RateLimiter` protocol for plug-and-play Redis
  or in-memory usage.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Protocol

_DEFAULT_MAX_KEYS = 10_000
_DEFAULT_TTL_SECONDS = 3600.0
_NUM_SHARDS = 32


class RateLimiter(Protocol):
    """Rate limiter interface. Implementations must be thread-safe."""

    def allow(self, key: str) -> bool:
        """Return True if this key can consume one unit of quota right now."""


@dataclass
class _Bucket:
    """Token bucket internal state."""

    tokens: float
    last_refill: float
    last_access: float


class InMemoryTokenBucket(RateLimiter):
    """Thread-safe, sharded, bounded in-memory token bucket per key.

    Attributes:
        rps: Sustained tokens per second (refill rate).
        burst: Bucket capacity — max short-burst tokens.
        max_keys: Maximum number of active tracked keys.
        ttl_seconds: Duration after which an idle full bucket can be purged.
    """

    def __init__(
        self,
        rps: int,
        burst: int,
        max_keys: int = _DEFAULT_MAX_KEYS,
        ttl_seconds: float = _DEFAULT_TTL_SECONDS,
    ) -> None:
        """Configure the bucket.

        Args:
            rps: Sustained rate (tokens per second).
            burst: Maximum burst capacity.
            max_keys: Maximum capacity of buckets across all shards.
            ttl_seconds: Idle time threshold for bucket eviction.

        Raises:
            ValueError: On non-positive parameters.
        """
        if rps <= 0 or burst <= 0:
            raise ValueError("rps and burst must be positive")
        self._rps = float(rps)
        self._burst = float(burst)
        self._max_keys_per_shard = max(1, max_keys // _NUM_SHARDS)
        self._ttl_seconds = ttl_seconds

        # Sharded buckets and locks to eliminate global mutex contention
        self._locks = [threading.Lock() for _ in range(_NUM_SHARDS)]
        self._shards: list[dict[str, _Bucket]] = [{} for _ in range(_NUM_SHARDS)]
        self._last_eviction: list[float] = [0.0 for _ in range(_NUM_SHARDS)]

    def _get_shard_index(self, key: str) -> int:
        return hash(key) % _NUM_SHARDS

    def _evict_stale_under_lock(self, shard_idx: int, now: float) -> None:
        """Purge idle buckets from the shard if TTL has expired or capacity is full."""
        shard = self._shards[shard_idx]
        if not shard:
            return

        # Prune expired keys
        expired_keys = [
            k
            for k, b in shard.items()
            if (now - b.last_access > self._ttl_seconds) and (b.tokens >= self._burst - 1e-6)
        ]
        for k in expired_keys:
            del shard[k]

        # If still over capacity, evict oldest accessed
        if len(shard) > self._max_keys_per_shard:
            sorted_by_access = sorted(shard.items(), key=lambda item: item[1].last_access)
            num_to_remove = len(shard) - self._max_keys_per_shard
            for k, _ in sorted_by_access[:num_to_remove]:
                del shard[k]

    def allow(self, key: str) -> bool:
        """Consume one token for `key`, if available.

        Args:
            key: An opaque identifier (API-key hash prefix or client IP).

        Returns:
            True if a token was available and consumed; False if over quota.
        """
        now = time.monotonic()
        shard_idx = self._get_shard_index(key)
        lock = self._locks[shard_idx]
        shard = self._shards[shard_idx]

        with lock:
            # Periodic cleanup per shard (every 60s or when exceeding shard capacity)
            if (now - self._last_eviction[shard_idx] > 60.0) or (
                len(shard) > self._max_keys_per_shard
            ):
                self._evict_stale_under_lock(shard_idx, now)
                self._last_eviction[shard_idx] = now

            bucket = shard.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self._burst, last_refill=now, last_access=now)
                shard[key] = bucket

            elapsed = now - bucket.last_refill
            bucket.tokens = min(self._burst, bucket.tokens + elapsed * self._rps)
            bucket.last_refill = now
            bucket.last_access = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True
            return False

    def active_keys(self) -> int:
        """Total active tracked keys across all shards."""
        total = 0
        for i in range(_NUM_SHARDS):
            with self._locks[i]:
                total += len(self._shards[i])
        return total
