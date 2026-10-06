"""Typed exceptions with HTTP status mappings.

Using typed exceptions rather than raising HTTPException directly keeps the
detection/proxy code framework-agnostic; only the route layer knows about HTTP.
"""

from __future__ import annotations


class FirewallError(Exception):
    """Base class for firewall errors that map to a specific HTTP status."""

    status_code: int = 500
    error_code: str = "internal_error"


class UnauthorizedError(FirewallError):
    """Missing or invalid API key."""

    status_code = 401
    error_code = "unauthorized"


class RateLimitedError(FirewallError):
    """Client exceeded configured rate limit."""

    status_code = 429
    error_code = "rate_limited"


class InputTooLargeError(FirewallError):
    """Prompt exceeded configured size limits."""

    status_code = 413
    error_code = "input_too_large"


class InvalidInputError(FirewallError):
    """Request body failed validation (encoding, structure, etc.)."""

    status_code = 400
    error_code = "invalid_input"


class UpstreamError(FirewallError):
    """The upstream Claude API returned an error we couldn't recover from."""

    status_code = 502
    error_code = "upstream_error"


class BlockedByFirewallError(FirewallError):
    """The firewall's verdict said 'block'; upstream was NOT contacted."""

    status_code = 403
    error_code = "blocked_by_firewall"
