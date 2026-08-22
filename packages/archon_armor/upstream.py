"""Upstream LLM transport abstraction.

Keeps the armor app testable (fake upstreams in tests) and provider-agnostic
(any OpenAI-compatible endpoint works; Gemini's OpenAI-compat endpoint is the
same shape with a different base_url).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx


class UpstreamError(RuntimeError):
    """Raised when the upstream LLM call fails."""


class LLMUpstream(ABC):
    @abstractmethod
    async def complete(
        self, payload: dict, base_url: str, api_key: str | None = None
    ) -> dict: ...


class HTTPOpenAIUpstream(LLMUpstream):
    """Forwards OpenAI-shaped payloads to an OpenAI-compatible base URL."""

    def __init__(self, timeout_seconds: float = 60.0):
        self._client = httpx.AsyncClient(timeout=timeout_seconds)

    async def complete(
        self, payload: dict, base_url: str, api_key: str | None = None
    ) -> dict:
        url = f"{base_url.rstrip('/')}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            resp = await self._client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPError as exc:
            raise UpstreamError(f"upstream call failed: {exc}") from exc

    async def aclose(self) -> None:
        await self._client.aclose()
