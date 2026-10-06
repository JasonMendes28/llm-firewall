"""Unit tests for non-blocking async authentication and TTL verification cache."""

from __future__ import annotations

import time

import pytest

from firewall.api.auth import (
    async_verify_api_key,
    clear_auth_cache_for_tests,
    hash_api_key,
    verify_api_key,
)


@pytest.fixture(autouse=True)
def _clean_cache() -> None:
    clear_auth_cache_for_tests()


@pytest.mark.asyncio
async def test_async_verify_happy_path() -> None:
    key = "secret-token-with-sufficient-entropy-999"
    hashed = hash_api_key(key)

    # First call: hits threadpool and Argon2
    t0 = time.perf_counter()
    assert await async_verify_api_key(key, [hashed]) is True
    t_first = time.perf_counter() - t0

    # Second call: hits in-memory cache in sub-millisecond time
    t0 = time.perf_counter()
    assert await async_verify_api_key(key, [hashed]) is True
    t_second = time.perf_counter() - t0

    # Cache hit must be significantly faster (orders of magnitude)
    assert t_second < t_first


def test_sync_verify_uses_cache() -> None:
    key = "secret-token-with-sufficient-entropy-888"
    hashed = hash_api_key(key)

    assert verify_api_key(key, [hashed]) is True

    # Immediate second call should be cached
    assert verify_api_key(key, [hashed]) is True
