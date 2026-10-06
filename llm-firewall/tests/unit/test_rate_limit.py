"""Tests for firewall.api.rate_limit."""

from __future__ import annotations

import time

import pytest

from firewall.api.rate_limit import InMemoryTokenBucket


def test_rejects_bad_params() -> None:
    with pytest.raises(ValueError):
        InMemoryTokenBucket(rps=0, burst=1)
    with pytest.raises(ValueError):
        InMemoryTokenBucket(rps=1, burst=0)


def test_burst_then_deny() -> None:
    b = InMemoryTokenBucket(rps=1, burst=3)
    assert b.allow("k") is True
    assert b.allow("k") is True
    assert b.allow("k") is True
    # 4th within the same instant should be denied.
    assert b.allow("k") is False


def test_refill_over_time() -> None:
    b = InMemoryTokenBucket(rps=100, burst=1)  # 100/s so 10ms fills 1 token
    assert b.allow("k") is True
    assert b.allow("k") is False
    time.sleep(0.02)
    assert b.allow("k") is True


def test_per_key_independence() -> None:
    b = InMemoryTokenBucket(rps=1, burst=1)
    assert b.allow("alice") is True
    assert b.allow("bob") is True
    assert b.allow("alice") is False
    assert b.allow("bob") is False
