"""Minimal async Claude API client with streaming and buffering support.

We use httpx directly rather than the official SDK to keep dependencies small
and to guarantee our timeout/retry story is explicit.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import httpx

from firewall.api.errors import UpstreamError

_API_VERSION = "2023-06-01"


class ClaudeClient:
    """Async client for the Anthropic Messages API."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.anthropic.com",
        timeout_s: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Configure the client.

        Args:
            api_key: Anthropic API key. Read from env, never hardcoded.
            base_url: API base URL.
            timeout_s: Per-request timeout.
            transport: Optional transport for tests to inject respx mocks.
        """
        if not api_key:
            raise ValueError("ClaudeClient requires a non-empty API key")
        self._headers = {
            "x-api-key": api_key,
            "anthropic-version": _API_VERSION,
            "content-type": "application/json",
        }
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout_s,
            transport=transport,
        )

    async def close(self) -> None:
        """Release resources; safe to call multiple times."""
        await self._client.aclose()

    async def messages(
        self,
        *,
        model: str,
        prompt: str,
        max_tokens: int,
    ) -> dict[str, Any]:
        """Send a single-turn user message to Claude (buffered).

        Args:
            model: Anthropic model id (e.g. `claude-3-5-sonnet-latest`).
            prompt: User content — already vetted by the firewall.
            max_tokens: Completion length cap.

        Returns:
            The parsed JSON response body.

        Raises:
            UpstreamError: On any transport or non-2xx response.
        """
        body = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        try:
            resp = await self._client.post("/v1/messages", headers=self._headers, json=body)
        except httpx.HTTPError as e:
            raise UpstreamError(f"claude request failed: {e}") from e

        if resp.status_code >= 400:
            raise UpstreamError(f"claude returned HTTP {resp.status_code}")

        try:
            return resp.json()
        except ValueError as e:
            raise UpstreamError(f"claude returned non-JSON body: {e}") from e

    async def messages_stream(
        self,
        *,
        model: str,
        prompt: str,
        max_tokens: int,
    ) -> AsyncIterator[str]:
        """Stream a single-turn user message from Claude via SSE chunks.

        Args:
            model: Anthropic model id.
            prompt: User content.
            max_tokens: Completion length cap.

        Yields:
            Raw chunk strings formatted for SSE consumption.

        Raises:
            UpstreamError: If the upstream stream fails or returns non-2xx.
        """
        body = {
            "model": model,
            "max_tokens": max_tokens,
            "stream": True,
            "messages": [{"role": "user", "content": prompt}],
        }
        try:
            req = self._client.build_request(
                "POST", "/v1/messages", headers=self._headers, json=body
            )
            resp = await self._client.send(req, stream=True)
        except httpx.HTTPError as e:
            raise UpstreamError(f"claude streaming connection failed: {e}") from e

        if resp.status_code >= 400:
            await resp.aclose()
            raise UpstreamError(f"claude returned HTTP {resp.status_code}")

        try:
            async for chunk in resp.aiter_text():
                if chunk:
                    yield chunk
        finally:
            await resp.aclose()
