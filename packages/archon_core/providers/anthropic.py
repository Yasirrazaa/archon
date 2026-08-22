"""Anthropic-native provider (Claude) via the Messages API.

Kept SDK-free on purpose: one httpx POST to /v1/messages, same as the rest
of archon_core's stdlib+httpx posture. System prompts are extracted from the
OpenAI-style message list into Anthropic's top-level ``system`` field.
"""

from __future__ import annotations

import httpx

from .base import Completion, LLMProvider, ProviderError

_ANTHROPIC_API_VERSION = "2023-06-01"
_DEFAULT_BASE_URL = "https://api.anthropic.com"


class ClaudeNativeProvider(LLMProvider):
    """Talks to Anthropic's native /v1/messages endpoint."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-5",
        base_url: str = _DEFAULT_BASE_URL,
        timeout_seconds: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=timeout_seconds, transport=transport
        )

    async def generate(self, messages: list[dict], **kwargs) -> Completion:
        system_parts = [
            m["content"] for m in messages if m.get("role") == "system"
        ]
        chat = [m for m in messages if m.get("role") != "system"]
        payload: dict = {
            "model": kwargs.get("model", self.model),
            "max_tokens": kwargs.get("max_tokens", 1024),
            "messages": chat,
        }
        if system_parts:
            payload["system"] = "\n".join(system_parts)
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": _ANTHROPIC_API_VERSION,
        }
        try:
            resp = await self._client.post(
                f"{self.base_url}/v1/messages", json=payload, headers=headers
            )
            resp.raise_for_status()
            data = resp.json()
            text = "\n".join(
                block.get("text", "")
                for block in data.get("content", [])
                if block.get("type") == "text"
            )
            return Completion(
                content=text, model=data.get("model", self.model), raw=data
            )
        except (httpx.HTTPError, KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"provider call failed: {exc}") from exc

    async def aclose(self) -> None:
        await self._client.aclose()
