"""TDD Phase 5a: provider seam — OpenAI-compat + Gemini adapters (mocked transport)."""

import httpx
import pytest

from archon_core.providers.base import LLMProvider, ProviderError
from archon_core.providers.openai_compat import GeminiOpenAICompatProvider, OpenAICompatProvider


def _mock_transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_openai_compat_provider_posts_chat_and_parses():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("Authorization")
        seen["body"] = request.read()
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": "hello!"}}],
                "model": "gpt-test",
            },
        )

    provider = OpenAICompatProvider(
        base_url="https://api.example.test/v1",
        api_key="sk-test",
        model="gpt-test",
        transport=_mock_transport(handler),
    )
    completion = await provider.generate([{"role": "user", "content": "hi"}])

    assert completion.content == "hello!"
    assert completion.model == "gpt-test"
    assert seen["url"] == "https://api.example.test/v1/chat/completions"
    assert seen["auth"] == "Bearer sk-test"


@pytest.mark.asyncio
async def test_gemini_provider_uses_google_openai_compat_endpoint():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"role": "assistant", "content": "gemini says hi"}}]},
        )

    provider = GeminiOpenAICompatProvider(
        api_key="g-key", model="gemini-2.0-flash", transport=_mock_transport(handler)
    )
    completion = await provider.generate([{"role": "user", "content": "hi"}])

    assert completion.content == "gemini says hi"
    assert seen["url"].startswith("https://generativelanguage.googleapis.com")
    assert "/chat/completions" in seen["url"]


@pytest.mark.asyncio
async def test_provider_error_wraps_http_failures():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    provider = OpenAICompatProvider(
        base_url="https://api.example.test/v1",
        api_key="k",
        model="m",
        transport=_mock_transport(handler),
    )
    with pytest.raises(ProviderError):
        await provider.generate([{"role": "user", "content": "hi"}])
