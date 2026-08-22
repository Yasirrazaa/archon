"""TDD Phase 5a: provider seam — OpenAI-compat + Gemini adapters (mocked transport).
Aug 23 addition: ClaudeNativeProvider (Anthropic /v1/messages) + env-based selection."""

import httpx
import pytest

from archon_core.providers.anthropic import ClaudeNativeProvider
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


# --- ClaudeNativeProvider (Anthropic Messages API) -------------------------


@pytest.mark.asyncio
async def test_claude_native_posts_messages_api_and_parses():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["api_key"] = request.headers.get("x-api-key")
        seen["version"] = request.headers.get("anthropic-version")
        seen["body"] = httpx.Request.content.__get__(request) if False else request.read()
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "claude says hi"}],
                "model": "claude-test",
            },
        )

    provider = ClaudeNativeProvider(
        api_key="ak-test", model="claude-test", transport=_mock_transport(handler)
    )
    completion = await provider.generate(
        [{"role": "user", "content": "hi"}], max_tokens=256
    )

    assert completion.content == "claude says hi"
    assert completion.model == "claude-test"
    assert seen["url"] == "https://api.anthropic.com/v1/messages"
    assert seen["api_key"] == "ak-test"
    assert seen["version"] == "2023-06-01"
    body = __import__("json").loads(seen["body"])
    assert body["model"] == "claude-test"
    assert body["max_tokens"] == 256
    assert body["messages"] == [{"role": "user", "content": "hi"}]


@pytest.mark.asyncio
async def test_claude_native_extracts_system_prompt_to_top_level():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.read()
        return httpx.Response(
            200,
            json={"content": [{"type": "text", "text": "ok"}], "model": "m"},
        )

    provider = ClaudeNativeProvider(
        api_key="k", model="m", transport=_mock_transport(handler)
    )
    await provider.generate(
        [
            {"role": "system", "content": "be terse"},
            {"role": "user", "content": "hi"},
        ]
    )
    body = __import__("json").loads(seen["body"])
    assert body["system"] == "be terse"
    assert body["messages"] == [{"role": "user", "content": "hi"}]
    assert "system" not in [m.get("role") for m in body["messages"]]


@pytest.mark.asyncio
async def test_claude_native_joins_multiple_text_blocks():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "part one"},
                    {"type": "tool_use", "id": "t1"},
                    {"type": "text", "text": "part two"},
                ],
                "model": "m",
            },
        )

    provider = ClaudeNativeProvider(
        api_key="k", model="m", transport=_mock_transport(handler)
    )
    completion = await provider.generate([{"role": "user", "content": "hi"}])
    assert completion.content == "part one\npart two"


@pytest.mark.asyncio
async def test_claude_native_error_wraps_http_failures():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"error": {"type": "rate_limit"}})

    provider = ClaudeNativeProvider(
        api_key="k", model="m", transport=_mock_transport(handler)
    )
    with pytest.raises(ProviderError):
        await provider.generate([{"role": "user", "content": "hi"}])


def test_provider_from_env_selects_claude(monkeypatch):
    from archon_core.providers import provider_from_env

    monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_KIND", "anthropic")
    monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_API_KEY", "ak-env")
    monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_MODEL", "claude-test-model")
    provider = provider_from_env(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"content": [], "model": "m"})
    ))
    assert isinstance(provider, ClaudeNativeProvider)
    assert provider.model == "claude-test-model"
    assert provider.api_key == "ak-env"


def test_provider_from_env_defaults_to_openai_compat(monkeypatch):
    from archon_core.providers import provider_from_env

    monkeypatch.delenv("ARCHON_ATTACK_PROVIDER_KIND", raising=False)
    provider = provider_from_env(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"choices": []})
    ))
    assert isinstance(provider, OpenAICompatProvider)


def test_plugins_inventory_lists_claude(capsys):
    # the seam inventory must advertise the new provider
    import archon_cli.main as cli_main

    names = cli_main._provider_names()
    assert "ClaudeNativeProvider" in names
