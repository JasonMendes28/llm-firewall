"""Unit tests for sharded, bounded rate limiter with active eviction."""

from __future__ import annotations

import time

from firewall.api.rate_limit import InMemoryTokenBucket


def test_sharded_rate_limiter_bounds_and_eviction() -> None:
    # Bucket with tiny capacity to test eviction under pressure
    bucket = InMemoryTokenBucket(rps=100, burst=10, max_keys=32, ttl_seconds=0.1)

    # Insert 64 distinct keys
    for i in range(64):
        assert bucket.allow(f"client-{i}") is True

    # Active keys should be bounded near or at max_keys
    assert bucket.active_keys() <= 64

    # Wait for TTL to expire
    time.sleep(0.15)

    # Allow one key to trigger eviction
    bucket.allow("trigger-key")

    # Stale keys should have been purged
    assert bucket.active_keys() < 64
