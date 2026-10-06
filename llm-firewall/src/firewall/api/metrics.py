"""Prometheus observability and telemetry metrics.

Provides standard Golden Signals:
- Traffic: requests_total by endpoint & HTTP status code.
- Latency: request_duration_seconds histogram.
- Errors: error codes & rate-limiting rejections.
- Saturation/Detection: verdicts_total, risk_score histogram, rules_matched_total.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)

# Request-level metrics
REQUESTS_TOTAL = Counter(
    "firewall_requests_total",
    "Total HTTP requests received by the firewall",
    ["endpoint", "status"],
)

REQUEST_DURATION_SECONDS = Histogram(
    "firewall_request_duration_seconds",
    "End-to-end HTTP request duration in seconds",
    ["endpoint"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)

# Detection pipeline metrics
VERDICTS_TOTAL = Counter(
    "firewall_verdicts_total",
    "Total detection verdicts issued",
    ["action", "mode", "degraded"],
)

RISK_SCORE_HISTOGRAM = Histogram(
    "firewall_risk_score",
    "Distribution of calculated prompt risk scores",
    ["action"],
    buckets=(0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

STAGE_DURATION_SECONDS = Histogram(
    "firewall_stage_duration_seconds",
    "Duration of individual detection pipeline stages",
    ["stage"],
    buckets=(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1),
)

RULES_MATCHED_TOTAL = Counter(
    "firewall_rules_matched_total",
    "Total occurrences of matched detection rules",
    ["rule_id"],
)

# Policy & Rate-limiting metrics
RATE_LIMIT_REJECTED_TOTAL = Counter(
    "firewall_rate_limit_rejected_total",
    "Total requests rejected by rate limiting",
)

EGRESS_BLOCKED_TOTAL = Counter(
    "firewall_egress_blocked_total",
    "Total egress responses blocked by policy",
    ["reason"],
)


def get_metrics_payload() -> tuple[bytes, str]:
    """Generate Prometheus exposition format payload and content-type."""
    return generate_latest(), CONTENT_TYPE_LATEST
