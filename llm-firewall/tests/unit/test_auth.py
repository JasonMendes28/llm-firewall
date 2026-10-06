"""Tests for firewall.api.auth."""

from __future__ import annotations

import pytest

from firewall.api.auth import extract_bearer_token, hash_api_key, verify_api_key
from firewall.api.errors import UnauthorizedError


def test_hash_then_verify_roundtrip() -> None:
    key = "a" * 32
    h = hash_api_key(key)
    assert verify_api_key(key, [h])


def test_verify_wrong_key_fails() -> None:
    h = hash_api_key("a" * 32)
    assert not verify_api_key("b" * 32, [h])


def test_verify_scans_all_hashes() -> None:
    h1 = hash_api_key("k1" * 16)
    h2 = hash_api_key("k2" * 16)
    assert verify_api_key("k2" * 16, [h1, h2])


def test_verify_handles_corrupt_hash_gracefully() -> None:
    """A corrupt hash in the config must not crash auth for valid keys."""
    good = hash_api_key("a" * 32)
    assert verify_api_key("a" * 32, ["not-a-real-hash-at-all", good])


def test_hash_rejects_short_keys() -> None:
    with pytest.raises(ValueError):
        hash_api_key("short")


def test_extract_bearer_missing_header() -> None:
    with pytest.raises(UnauthorizedError):
        extract_bearer_token(None)


def test_extract_bearer_wrong_scheme() -> None:
    with pytest.raises(UnauthorizedError):
        extract_bearer_token("Basic dXNlcjpwYXNz")


def test_extract_bearer_empty_token() -> None:
    with pytest.raises(UnauthorizedError):
        extract_bearer_token("Bearer   ")


def test_extract_bearer_happy_path() -> None:
    assert extract_bearer_token("Bearer  my-token-here") == "my-token-here"
