"""Tests for firewall.config.

The security-critical properties we assert:
- Prod refuses to start with unsafe defaults.
- warn_threshold must be strictly less than block_threshold.
- Dev is permissive so local development stays friction-free.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from firewall.config import BlockingMode, Environment, Settings


def _make(**overrides: object) -> Settings:
    """Construct Settings without pulling from .env."""
    defaults: dict[str, object] = {
        "firewall_env": Environment.DEV,
        "trust_proxy": False,
        "firewall_api_keys_hashed": "",
        "log_full_prompts": False,
        "debug_timing": False,
        "block_threshold": 0.8,
        "warn_threshold": 0.5,
    }
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)  # type: ignore[call-arg]


def test_dev_defaults_permitted() -> None:
    s = _make()
    assert s.firewall_env is Environment.DEV
    assert s.blocking_mode is BlockingMode.HARD_BLOCK


def test_prod_requires_trust_proxy() -> None:
    with pytest.raises(ValidationError) as excinfo:
        _make(
            firewall_env=Environment.PROD,
            trust_proxy=False,
            firewall_api_keys_hashed="$argon2id$v=19$m=65536,t=3,p=4$abc$def",
        )
    assert "TRUST_PROXY" in str(excinfo.value)


def test_prod_requires_api_keys() -> None:
    with pytest.raises(ValidationError) as excinfo:
        _make(
            firewall_env=Environment.PROD,
            trust_proxy=True,
            firewall_api_keys_hashed="",
        )
    assert "FIREWALL_API_KEYS_HASHED" in str(excinfo.value)


def test_prod_refuses_full_prompt_logging_default() -> None:
    with pytest.raises(ValidationError) as excinfo:
        _make(
            firewall_env=Environment.PROD,
            trust_proxy=True,
            firewall_api_keys_hashed="$argon2id$v=19$m=65536,t=3,p=4$abc$def",
            log_full_prompts=True,
        )
    assert "LOG_FULL_PROMPTS" in str(excinfo.value)


def test_prod_refuses_debug_timing() -> None:
    with pytest.raises(ValidationError) as excinfo:
        _make(
            firewall_env=Environment.PROD,
            trust_proxy=True,
            firewall_api_keys_hashed="$argon2id$v=19$m=65536,t=3,p=4$abc$def",
            debug_timing=True,
        )
    assert "DEBUG_TIMING" in str(excinfo.value)


def test_prod_happy_path() -> None:
    s = _make(
        firewall_env=Environment.PROD,
        trust_proxy=True,
        firewall_api_keys_hashed="$argon2id$v=19$m=65536,t=3,p=4$abc$def",
    )
    assert s.firewall_env is Environment.PROD


def test_warn_must_be_below_block() -> None:
    with pytest.raises(ValidationError):
        _make(block_threshold=0.5, warn_threshold=0.5)
    with pytest.raises(ValidationError):
        _make(block_threshold=0.4, warn_threshold=0.5)


def test_hashed_api_keys_parsing_uses_safe_delimiter() -> None:
    # Simulates a real Argon2 hash string containing commas internally.
    fake_hash_1 = "$argon2id$v=19$m=65536,t=3,p=4$abc$def"
    fake_hash_2 = "$argon2id$v=19$m=65536,t=3,p=4$ghi$jkl"
    # Newline-separated:
    s = _make(firewall_api_keys_hashed=f"{fake_hash_1}\n{fake_hash_2}")
    assert s.hashed_api_keys == [fake_hash_1, fake_hash_2]
    # ';;' delimiter also works:
    s2 = _make(firewall_api_keys_hashed=f"{fake_hash_1};;{fake_hash_2}")
    assert s2.hashed_api_keys == [fake_hash_1, fake_hash_2]
    # Commas inside a single hash are preserved (not split).
    s3 = _make(firewall_api_keys_hashed=fake_hash_1)
    assert s3.hashed_api_keys == [fake_hash_1]
