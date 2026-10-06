"""Unit tests for Prometheus metrics module."""

from __future__ import annotations

from firewall.api.metrics import (
    RATE_LIMIT_REJECTED_TOTAL,
    REQUESTS_TOTAL,
    get_metrics_payload,
)


def test_metrics_payload_generation() -> None:
    # Increment counter
    REQUESTS_TOTAL.labels(endpoint="/v1/check", status="200").inc()
    RATE_LIMIT_REJECTED_TOTAL.inc()

    payload, content_type = get_metrics_payload()
    assert isinstance(payload, bytes)
    assert "text/plain" in content_type or "version=0.0.4" in content_type
    assert b"firewall_requests_total" in payload
    assert b"firewall_rate_limit_rejected_total" in payload
