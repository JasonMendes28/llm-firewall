"""Structured JSON logging setup.

We emit one JSON object per log line to stdout, suitable for ingestion by any
log aggregator (Loki, ELK, Datadog, etc.). No PII by default — see ADR-003.

Rationale for structlog:
- Zero-config JSON output.
- Context binding (`.bind(request_id=...)`) so we don't have to thread IDs by hand.
- Timestamp is ISO-8601 UTC.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


def configure_logging(level: str = "INFO") -> None:
    """Configure the process-wide logger.

    Args:
        level: Standard logging level name (DEBUG, INFO, WARNING, ERROR).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Route stdlib logging through structlog so third-party libs get JSON too.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> Any:
    """Return a bound structlog logger.

    Args:
        name: Optional logger name; defaults to the caller's module.

    Returns:
        A structlog BoundLogger.
    """
    return structlog.get_logger(name)
