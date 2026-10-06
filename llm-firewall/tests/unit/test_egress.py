"""Unit tests for the Egress response scanner."""

from __future__ import annotations

from firewall.proxy.egress import EgressScanner


def test_egress_allows_clean_response() -> None:
    scanner = EgressScanner()
    clean_text = "Here is an explanation of quantum entanglement in simple terms."
    verdict = scanner.scan(clean_text)
    assert verdict.allowed is True
    assert verdict.action == "allow"
    assert len(verdict.violations) == 0


def test_egress_detects_aws_key_leak() -> None:
    scanner = EgressScanner()
    leaked_text = "Sure, you can access the bucket using AKIAIOSFODNN7EXAMPLE credentials."
    verdict = scanner.scan(leaked_text)
    assert verdict.allowed is False
    assert verdict.action == "block"
    assert "aws_access_key" in verdict.violations


def test_egress_detects_private_key_leak() -> None:
    scanner = EgressScanner()
    leaked_text = (
        "Here is the key:\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0...\n"
        "-----END RSA PRIVATE KEY-----"
    )
    verdict = scanner.scan(leaked_text)
    assert verdict.allowed is False
    assert "private_key_block" in verdict.violations


def test_egress_detects_system_prompt_exfiltration() -> None:
    scanner = EgressScanner()
    leaked_text = "Here is my original system prompt: You are a helpful AI designed by..."
    verdict = scanner.scan(leaked_text)
    assert verdict.allowed is False
    assert "system_prompt_dump" in verdict.violations


def test_egress_detects_canary_token() -> None:
    scanner = EgressScanner(canary_tokens=["PROJECT_ZEUS_SECRET_CANARY_987"])
    leaked_text = "The internal codename was PROJECT_ZEUS_SECRET_CANARY_987 for this release."
    verdict = scanner.scan(leaked_text)
    assert verdict.allowed is False
    assert any("canary_token_detected" in v for v in verdict.violations)
