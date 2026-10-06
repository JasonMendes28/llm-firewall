"""FastAPI application factory.

Startup responsibilities:
1. Load & validate Settings (may raise; that's the point).
2. Configure structured logging.
3. Load regex rules from `rules/default_rules.yaml` (with RE2 linear-time engine).
4. Construct the classifier and attempt to load it; degraded mode is OK.
5. Wire detection pipeline, sharded rate limiter, audit logger, egress scanner, and Claude client.
6. Register exception handlers that map FirewallError -> uniform JSON errors.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from firewall.api.errors import FirewallError
from firewall.api.rate_limit import InMemoryTokenBucket
from firewall.api.routes import build_router
from firewall.api.schemas import ErrorBody
from firewall.audit.logger import AuditLogger
from firewall.config import Settings, get_settings
from firewall.detection.classifier import (
    Classifier,
    ClassifierUnavailable,
    build_classifier_from_settings,
)
from firewall.detection.pipeline import DetectionPipeline, PipelineConfig
from firewall.detection.regex_engine import RegexEngine, load_rules
from firewall.logging_setup import configure_logging, get_logger
from firewall.proxy.claude_client import ClaudeClient
from firewall.proxy.egress import EgressScanner

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_RULES_PATH = REPO_ROOT / "rules" / "default_rules.yaml"


def _build_pipeline(settings: Settings, rules_path: Path) -> DetectionPipeline:
    """Assemble the detection pipeline from settings."""
    rules = load_rules(rules_path)
    engine = RegexEngine(rules)
    classifier: Classifier = build_classifier_from_settings(settings)
    try:
        classifier.load()
    except ClassifierUnavailable as e:
        # Fail-degraded, not fail-closed: service still starts.
        get_logger("startup").warning(
            "classifier_load_failed_starting_in_degraded_mode",
            reason=str(e),
        )
    return DetectionPipeline(
        engine,
        classifier,
        PipelineConfig(
            block_threshold=settings.block_threshold,
            warn_threshold=settings.warn_threshold,
            mode=settings.blocking_mode,
            capture_timing=settings.debug_timing,
        ),
    )


def create_app(
    settings: Settings | None = None,
    rules_path: Path | None = None,
) -> FastAPI:
    """Application factory.

    Args:
        settings: Optional pre-built Settings (for tests). If None, loaded from env.
        rules_path: Optional override for the ruleset path (for tests).

    Returns:
        A configured FastAPI app.
    """
    settings = settings or get_settings()
    configure_logging(settings.firewall_log_level)
    rules_path = rules_path or DEFAULT_RULES_PATH

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Detection pipeline.
        app.state.settings = settings
        app.state.pipeline = _build_pipeline(settings, rules_path)
        app.state.rate_limiter = InMemoryTokenBucket(
            rps=settings.rate_limit_rps, burst=settings.rate_limit_burst
        )
        app.state.audit = AuditLogger(log_full_prompts=settings.log_full_prompts)
        app.state.egress = EgressScanner()

        # Claude client (optional — /v1/proxy needs it, /v1/check does not).
        claude: ClaudeClient | None = None
        if settings.anthropic_api_key:
            claude = ClaudeClient(
                api_key=settings.anthropic_api_key,
                base_url=settings.anthropic_base_url,
                timeout_s=settings.anthropic_timeout_s,
            )
        app.state.claude = claude

        get_logger("startup").info(
            "firewall_started",
            env=settings.firewall_env.value,
            mode=settings.blocking_mode.value,
            rules_loaded=app.state.pipeline._regex.rule_count,  # noqa: SLF001
            re2_engine=app.state.pipeline._regex.is_re2_active,  # noqa: SLF001
            classifier_available=app.state.pipeline._classifier.is_available(),  # noqa: SLF001
            upstream_configured=claude is not None,
        )

        try:
            yield
        finally:
            if claude is not None:
                await claude.close()

    app = FastAPI(
        title="LLM Firewall",
        version="0.1.0",
        description="Production-grade jailbreak / prompt-injection detection proxy.",
        lifespan=lifespan,
    )
    app.include_router(build_router())

    @app.exception_handler(FirewallError)
    async def _firewall_error_handler(
        request: Request,  # noqa: ARG001
        exc: FirewallError,
    ) -> JSONResponse:
        """Map typed firewall errors to uniform JSON envelopes."""
        body = ErrorBody(error_code=exc.error_code, message=str(exc)).model_dump()
        return JSONResponse(status_code=exc.status_code, content=body)

    return app


# Uvicorn entrypoint: `uvicorn firewall.main:app`.
def _lazy_app() -> FastAPI:
    return create_app()


app = _lazy_app()
