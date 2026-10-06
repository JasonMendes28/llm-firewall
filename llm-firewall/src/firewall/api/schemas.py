"""Pydantic request/response schemas.

These are the contract exposed to callers. We keep them narrow: minimal fields,
strict types, explicit length limits. Length limits are enforced here (Pydantic)
so malformed input is rejected before it ever reaches the detection pipeline.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CheckRequest(BaseModel):
    """Request body for /v1/check — evaluate a prompt without forwarding it."""

    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(..., min_length=1, max_length=16_384)
    request_id: str | None = Field(default=None, max_length=64)


class BatchCheckRequest(BaseModel):
    """Request body for /v1/batch — evaluate many prompts (red-team / offline)."""

    model_config = ConfigDict(extra="forbid")

    prompts: list[str] = Field(..., min_length=1, max_length=256)


class ProxyRequest(BaseModel):
    """Request body for /v1/proxy — evaluate then forward to Claude if allowed.

    Supports both buffered JSON responses and real-time streaming (SSE).
    """

    model_config = ConfigDict(extra="forbid")

    prompt: str = Field(..., min_length=1, max_length=16_384)
    model: str = Field(default="claude-3-5-sonnet-latest", max_length=128)
    max_tokens: int = Field(default=1024, ge=1, le=4096)
    request_id: str | None = Field(default=None, max_length=64)
    stream: bool = Field(default=False)


class VerdictResponse(BaseModel):
    """API-facing verdict — matches Verdict.to_public_dict()."""

    model_config = ConfigDict(extra="allow")  # allow optional `latency` field

    request_id: str
    allowed: bool
    action_taken: str
    risk_score: float
    classifier_confidence: float | None
    matched_rule_ids: list[str]
    mode: str
    degraded: bool
    prompt_hash: str
    prompt_length: int
    timestamp: str


class BatchCheckResponse(BaseModel):
    """Response body for /v1/batch."""

    verdicts: list[VerdictResponse]


class ProxyResponse(BaseModel):
    """Response body for /v1/proxy on success."""

    verdict: VerdictResponse
    upstream: dict[str, Any]
    egress_verdict: dict[str, Any] | None = None


class ErrorBody(BaseModel):
    """Uniform error envelope. Never contains prompt content."""

    error_code: str
    message: str
    request_id: str | None = None


class HealthResponse(BaseModel):
    """Response body for /health."""

    status: str
    version: str
    rules_loaded: int
    classifier_available: bool
    degraded: bool
    re2_active: bool = False
