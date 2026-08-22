"""OpenAI-compatible providers, including Gemini via its OpenAI-compat endpoint."""

from __future__ import annotations

import httpx

from .base import Completion, LLMProvider, ProviderError

_GEMINI_OPENAI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai"


class OpenAICompatProvider(LLMProvider):
    """Talks to any /v1/chat/completions-compatible endpoint."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        model: str = "default",
        timeout_seconds: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self._client = httpx.AsyncClient(
            timeout=timeout_seconds, transport=transport
        )

    async def generate(self, messages: list[dict], **kwargs) -> Completion:
        payload = {"model": kwargs.get("model", self.model), "messages": messages}
        if "temperature" in kwargs:
            payload["temperature"] = kwargs["temperature"]
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            resp = await self._client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers
            )
            resp.raise_for_status()
            data = resp.json()
            return Completion(
                content=data["choices"][0]["message"]["content"],
                model=data.get("model", self.model),
                raw=data,
            )
        except (httpx.HTTPError, KeyError, IndexError) as exc:
            raise ProviderError(f"provider call failed: {exc}") from exc

    async def aclose(self) -> None:
        await self._client.aclose()


class GeminiOpenAICompatProvider(OpenAICompatProvider):
    """Gemini through Google's documented OpenAI-compatibility endpoint."""

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.0-flash",
        base_url: str = _GEMINI_OPENAI_BASE,
        **kwargs,
    ):
        super().__init__(base_url=base_url, api_key=api_key, model=model, **kwargs)
