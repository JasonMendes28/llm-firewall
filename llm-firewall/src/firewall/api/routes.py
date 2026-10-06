"""FastAPI route definitions.

The API surface:
    GET  /health         — liveness/readiness for orchestrators.
    GET  /metrics        — Prometheus metrics endpoint for cluster monitoring.
    POST /v1/check       — evaluate a prompt (no upstream call).
    POST /v1/batch       — evaluate a list of prompts.
    POST /v1/proxy       — evaluate then forward to Claude (streaming SSE or buffered).

Every non-/health, non-/metrics route requires a valid API key and is subject to rate limits.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.responses import StreamingResponse

from firewall import __version__
from firewall.api.auth import async_verify_api_key, extract_bearer_token
from firewall.api.errors import (
    BlockedByFirewallError,
    InputTooLargeError,
    RateLimitedError,
    UnauthorizedError,
)
from firewall.api.metrics import (
    EGRESS_BLOCKED_TOTAL,
    RATE_LIMIT_REJECTED_TOTAL,
    REQUEST_DURATION_SECONDS,
    REQUESTS_TOTAL,
    get_metrics_payload,
)
from firewall.api.rate_limit import RateLimiter
from firewall.api.schemas import (
    BatchCheckRequest,
    BatchCheckResponse,
    CheckRequest,
    HealthResponse,
    ProxyRequest,
    ProxyResponse,
    VerdictResponse,
)
from firewall.audit.logger import AuditLogger
from firewall.config import Settings
from firewall.detection.pipeline import DetectionPipeline
from firewall.detection.verdict import Verdict
from firewall.proxy.claude_client import ClaudeClient
from firewall.proxy.egress import EgressScanner


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


def _get_pipeline(request: Request) -> DetectionPipeline:
    return request.app.state.pipeline  # type: ignore[no-any-return]


def _get_rate_limiter(request: Request) -> RateLimiter:
    return request.app.state.rate_limiter  # type: ignore[no-any-return]


def _get_audit(request: Request) -> AuditLogger:
    return request.app.state.audit  # type: ignore[no-any-return]


def _get_egress(request: Request) -> EgressScanner:
    return getattr(request.app.state, "egress", EgressScanner())  # type: ignore[no-any-return]


def _get_claude(request: Request) -> ClaudeClient | None:
    return getattr(request.app.state, "claude", None)


async def _authenticate(
    request: Request,
    settings: Settings,
    rate_limiter: RateLimiter,
    authorization: str | None,
) -> str:
    """Verify the bearer token asynchronously and consume one unit of quota.

    Returns:
        A stable rate-limit key derived from the token (hash prefix).
    """
    token = extract_bearer_token(authorization)
    hashed_keys = settings.hashed_api_keys
    if not hashed_keys:
        # Dev-only: allow if no keys are configured.
        if settings.firewall_env.value == "prod":
            raise UnauthorizedError("No API keys configured")
        rate_key = f"dev:{request.client.host if request.client else 'unknown'}"
    else:
        # Non-blocking async check with in-memory TTL verification cache
        if not await async_verify_api_key(token, hashed_keys):
            raise UnauthorizedError("Invalid API key")
        import hashlib

        rate_key = "k:" + hashlib.sha256(token.encode()).hexdigest()[:16]

    if not rate_limiter.allow(rate_key):
        RATE_LIMIT_REJECTED_TOTAL.inc()
        raise RateLimitedError("Rate limit exceeded")
    return rate_key


def _validate_prompt_size(prompt: str, settings: Settings) -> None:
    """Enforce byte and char caps beyond Pydantic's compile-time limits."""
    if len(prompt) > settings.max_prompt_chars:
        raise InputTooLargeError(f"prompt exceeds {settings.max_prompt_chars} chars")
    if len(prompt.encode("utf-8")) > settings.max_prompt_bytes:
        raise InputTooLargeError(f"prompt exceeds {settings.max_prompt_bytes} bytes")


def _verdict_to_response(verdict: Verdict, settings: Settings) -> VerdictResponse:
    """Serialize a Verdict into the API response, respecting debug_timing gating."""
    return VerdictResponse(**verdict.to_public_dict(include_timing=settings.debug_timing))


def build_router() -> APIRouter:
    """Build the API router. Called by the app factory."""
    router = APIRouter()

    @router.get("/metrics", tags=["ops"])
    async def metrics() -> Response:
        """Prometheus metrics exposition endpoint."""
        data, content_type = get_metrics_payload()
        return Response(content=data, media_type=content_type)

    @router.get("/health", response_model=HealthResponse, tags=["ops"])
    async def health(request: Request) -> HealthResponse:
        """Liveness/readiness endpoint.

        No auth required — orchestrators need to hit this without credentials.
        Reports classifier availability and RE2 linear-time engine status.
        """
        pipeline: DetectionPipeline = request.app.state.pipeline
        classifier_available = pipeline._classifier.is_available()  # noqa: SLF001
        rules_loaded = pipeline._regex.rule_count  # noqa: SLF001
        re2_active = getattr(pipeline._regex, "is_re2_active", False)
        return HealthResponse(
            status="ok",
            version=__version__,
            rules_loaded=rules_loaded,
            classifier_available=classifier_available,
            degraded=not classifier_available,
            re2_active=re2_active,
        )

    @router.post("/v1/check", response_model=VerdictResponse, tags=["detection"])
    async def check(
        body: CheckRequest,
        request: Request,
        authorization: str | None = Header(default=None),
        settings: Settings = Depends(_get_settings),
        pipeline: DetectionPipeline = Depends(_get_pipeline),
        rate_limiter: RateLimiter = Depends(_get_rate_limiter),
        audit: AuditLogger = Depends(_get_audit),
    ) -> VerdictResponse:
        """Evaluate a single prompt without forwarding it to Claude."""
        t_start = time.perf_counter()
        status = "200"
        try:
            await _authenticate(request, settings, rate_limiter, authorization)
            _validate_prompt_size(body.prompt, settings)
            verdict = await pipeline.analyze_async(body.prompt, request_id=body.request_id)
            audit.record(verdict, prompt_plaintext=body.prompt)
            return _verdict_to_response(verdict, settings)
        except Exception:
            status = "error"
            raise
        finally:
            REQUEST_DURATION_SECONDS.labels(endpoint="/v1/check").observe(
                time.perf_counter() - t_start
            )
            REQUESTS_TOTAL.labels(endpoint="/v1/check", status=status).inc()

    @router.post("/v1/batch", response_model=BatchCheckResponse, tags=["detection"])
    async def batch(
        body: BatchCheckRequest,
        request: Request,
        authorization: str | None = Header(default=None),
        settings: Settings = Depends(_get_settings),
        pipeline: DetectionPipeline = Depends(_get_pipeline),
        rate_limiter: RateLimiter = Depends(_get_rate_limiter),
        audit: AuditLogger = Depends(_get_audit),
    ) -> BatchCheckResponse:
        """Evaluate many prompts at once. Intended for offline red-team runs."""
        t_start = time.perf_counter()
        status = "200"
        try:
            await _authenticate(request, settings, rate_limiter, authorization)
            for p in body.prompts:
                _validate_prompt_size(p, settings)
            verdicts: list[VerdictResponse] = []
            for p in body.prompts:
                v = await pipeline.analyze_async(p)
                audit.record(v, prompt_plaintext=p)
                verdicts.append(_verdict_to_response(v, settings))
            return BatchCheckResponse(verdicts=verdicts)
        except Exception:
            status = "error"
            raise
        finally:
            REQUEST_DURATION_SECONDS.labels(endpoint="/v1/batch").observe(
                time.perf_counter() - t_start
            )
            REQUESTS_TOTAL.labels(endpoint="/v1/batch", status=status).inc()

    @router.post("/v1/proxy", response_model=ProxyResponse, tags=["proxy"])
    async def proxy(
        body: ProxyRequest,
        request: Request,
        authorization: str | None = Header(default=None),
        settings: Settings = Depends(_get_settings),
        pipeline: DetectionPipeline = Depends(_get_pipeline),
        rate_limiter: RateLimiter = Depends(_get_rate_limiter),
        audit: AuditLogger = Depends(_get_audit),
        egress: EgressScanner = Depends(_get_egress),
    ) -> Any:
        """Evaluate then, if allowed, forward the prompt to Claude."""
        t_start = time.perf_counter()
        status = "200"
        try:
            await _authenticate(request, settings, rate_limiter, authorization)
            _validate_prompt_size(body.prompt, settings)

            verdict = await pipeline.analyze_async(body.prompt, request_id=body.request_id)
            audit.record(verdict, prompt_plaintext=body.prompt)

            if not verdict.allowed:
                raise BlockedByFirewallError(f"blocked (verdict {verdict.request_id})")

            claude: ClaudeClient | None = _get_claude(request)
            if claude is None:
                from firewall.api.errors import UpstreamError

                raise UpstreamError("upstream not configured")

            if body.stream:
                # Streaming mode: stream raw SSE chunks from Claude
                return StreamingResponse(
                    claude.messages_stream(
                        model=body.model,
                        prompt=body.prompt,
                        max_tokens=body.max_tokens,
                    ),
                    media_type="text/event-stream",
                )

            # Buffered mode with egress scanning
            upstream = await claude.messages(
                model=body.model,
                prompt=body.prompt,
                max_tokens=body.max_tokens,
            )

            # Inspect egress for system prompt leaks, PII, and credentials
            content_text = ""
            for block in upstream.get("content", []):
                if isinstance(block, dict) and block.get("type") == "text":
                    content_text += block.get("text", "")

            egress_verdict = egress.scan(content_text)
            if not egress_verdict.allowed:
                EGRESS_BLOCKED_TOTAL.labels(reason=";".join(egress_verdict.violations)).inc()
                raise BlockedByFirewallError(
                    f"blocked by egress policy: {', '.join(egress_verdict.violations)}"
                )

            return ProxyResponse(
                verdict=_verdict_to_response(verdict, settings),
                upstream=upstream,
                egress_verdict={
                    "allowed": egress_verdict.allowed,
                    "violations": egress_verdict.violations,
                    "action": egress_verdict.action,
                },
            )
        except Exception:
            status = "error"
            raise
        finally:
            REQUEST_DURATION_SECONDS.labels(endpoint="/v1/proxy").observe(
                time.perf_counter() - t_start
            )
            REQUESTS_TOTAL.labels(endpoint="/v1/proxy", status=status).inc()

    return router


__all__ = ["build_router"]
