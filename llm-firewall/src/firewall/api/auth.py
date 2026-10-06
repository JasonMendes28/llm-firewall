"""API key authentication.

Design (ADR-005 + Production Concurrency Hardening):
- API keys are Argon2id-hashed at rest (config). The plaintext key never leaves
  the client.
- Comparison uses argon2's built-in verify (constant-time check).
- Concurrency Hardening: Argon2 verification is computationally heavy (~50-100ms
  per hash check). To prevent event-loop blocking and ReDoS/CPU starvation:
    1. An in-memory TTL verification cache (bounded LRU, 5-minute TTL) caches
       successfully verified API tokens by their SHA-256 digest. Subsequent requests
       authenticate in sub-microsecond time.
    2. Any cache-miss verification is executed off-thread via `async_verify_api_key`
       so the asyncio event loop remains non-blocking and responsive.
- Missing or malformed `Authorization` header -> 401.

CLI helper: `python -m firewall.api.auth hash <plaintext>` produces a hash you
can drop into FIREWALL_API_KEYS_HASHED.
"""

from __future__ import annotations

import asyncio
import hashlib
import sys
import threading
from collections.abc import Iterable

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cachetools import TTLCache

from firewall.api.errors import UnauthorizedError

# Argon2id defaults are pinned for security stability.
_HASHER = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)

# In-memory authentication cache: sha256(token) -> bool (only positive hits cached).
# Bounded to 2048 keys with 300s (5min) TTL.
_AUTH_CACHE: TTLCache[str, bool] = TTLCache(maxsize=2048, ttl=300.0)
_CACHE_LOCK = threading.Lock()


def clear_auth_cache_for_tests() -> None:
    """Clear cached authentication results — helper for test isolation."""
    with _CACHE_LOCK:
        _AUTH_CACHE.clear()


def hash_api_key(plaintext: str) -> str:
    """Hash a plaintext API key with Argon2id.

    Args:
        plaintext: The plaintext API key. Should be at least 16 chars.

    Returns:
        Argon2id encoded hash string.

    Raises:
        ValueError: If the plaintext is empty or suspiciously short.
    """
    if not plaintext or len(plaintext) < 16:
        raise ValueError("API key plaintext must be at least 16 characters")
    return _HASHER.hash(plaintext)


def _token_digest(token: str) -> str:
    """Compute a fast non-reversible digest of the token for cache indexing."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_api_key(plaintext: str, hashed_keys: Iterable[str]) -> bool:
    """Synchronous verification of plaintext API key against hashed keys.

    Checks the bounded in-memory cache first; falls back to Argon2 verification.
    """
    digest = _token_digest(plaintext)
    with _CACHE_LOCK:
        if _AUTH_CACHE.get(digest) is True:
            return True

    hashed_list = list(hashed_keys)
    for h in hashed_list:
        try:
            _HASHER.verify(h, plaintext)
            with _CACHE_LOCK:
                _AUTH_CACHE[digest] = True
            return True
        except VerifyMismatchError:
            continue
        except Exception:  # noqa: BLE001
            # A corrupt hash entry should not crash auth; skip it and continue.
            continue
    return False


async def async_verify_api_key(plaintext: str, hashed_keys: Iterable[str]) -> bool:
    """Non-blocking async verification of plaintext API key against hashed keys.

    Leverages the thread pool via `asyncio.to_thread` on cache miss to avoid
    blocking the asyncio event loop with CPU-intensive Argon2 calculations.
    """
    digest = _token_digest(plaintext)
    with _CACHE_LOCK:
        if _AUTH_CACHE.get(digest) is True:
            return True

    # Offload synchronous CPU-heavy Argon2 verification to worker threadpool.
    hashed_list = tuple(hashed_keys)
    return await asyncio.to_thread(verify_api_key, plaintext, hashed_list)


def extract_bearer_token(authorization_header: str | None) -> str:
    """Extract a bearer token from an `Authorization: Bearer <token>` header.

    Args:
        authorization_header: The raw header value or None.

    Returns:
        The token string.

    Raises:
        UnauthorizedError: If the header is missing, malformed, or empty.
    """
    if not authorization_header:
        raise UnauthorizedError("Authorization header is required")
    parts = authorization_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise UnauthorizedError("Authorization header must be 'Bearer <token>'")
    token = parts[1].strip()
    if not token:
        raise UnauthorizedError("Bearer token is empty")
    return token


def _cli_main(argv: list[str]) -> int:
    """CLI: `python -m firewall.api.auth hash <plaintext>`."""
    if len(argv) != 3 or argv[1] != "hash":
        print("usage: python -m firewall.api.auth hash <plaintext-key>", file=sys.stderr)
        return 2
    try:
        print(hash_api_key(argv[2]))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_cli_main(sys.argv))
