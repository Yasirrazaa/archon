"""Sprint W8-C: local vLLM provider path — thin OpenAI-compat preset + env factory."""

import json

import httpx
import pytest
from archon_core.providers.base import ProviderError
from archon_core.providers.openai_compat import OpenAICompatProvider
from archon_core.providers.vllm import (
    VLLM_DEFAULT_API_KEY,
    VLLM_DEFAULT_BASE_URL,
    VllmProvider,
    vllm_from_env,
    vllm_provider,
)


def _handler_factory(seen: dict, content: str = "local llama says hi"):
    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("Authorization")
        seen["body"] = request.read()
        return httpx.Response(
            200,
            json={
                "choices": [{"message": {"role": "assistant", "content": content}}],
                "model": "meta-llama/Llama-3.1-8B-Instruct",
            },
        )

    return handler


# --- VllmProvider defaults ---------------------------------------------------


def test_vllm_provider_defaults_to_local_vllm_server():
    provider = VllmProvider(model="meta-llama/Llama-3.1-8B-Instruct")
    assert provider.base_url == "http://localhost:8000/v1"
    assert provider.base_url == VLLM_DEFAULT_BASE_URL


def test_vllm_provider_api_key_defaults_to_empty():
    provider = VllmProvider(model="m")
    assert provider.api_key == VLLM_DEFAULT_API_KEY == "EMPTY"


def test_vllm_provider_is_openai_compat_preset_not_new_transport():
    provider = VllmProvider(model="m")
    assert isinstance(provider, OpenAICompatProvider)


def test_vllm_provider_custom_base_url_override():
    provider = VllmProvider(model="m", base_url="http://gpu-box.lan:8000/v1/")
    assert provider.base_url == "http://gpu-box.lan:8000/v1"


# --- request shape over injected transport -----------------------------------


@pytest.mark.asyncio
async def test_vllm_generate_posts_to_chat_completions_with_model_in_body():
    seen: dict = {}
    provider = vllm_provider(
        "meta-llama/Llama-3.1-8B-Instruct", transport=httpx.MockTransport(_handler_factory(seen))
    )
    completion = await provider.generate([{"role": "user", "content": "hi"}])

    assert completion.content == "local llama says hi"
    assert completion.model == "meta-llama/Llama-3.1-8B-Instruct"
    assert seen["url"] == "http://localhost:8000/v1/chat/completions"
    body = json.loads(seen["body"])
    assert body["model"] == "meta-llama/Llama-3.1-8B-Instruct"


@pytest.mark.asyncio
async def test_vllm_sends_bearer_empty_auth_header():
    seen: dict = {}
    provider = vllm_provider("m", transport=httpx.MockTransport(_handler_factory(seen)))
    await provider.generate([{"role": "user", "content": "hi"}])
    assert seen["auth"] == f"Bearer {VLLM_DEFAULT_API_KEY}"


@pytest.mark.asyncio
async def test_vllm_custom_base_url_used_in_request():
    seen: dict = {}
    provider = vllm_provider(
        "m",
        base_url="http://gpu-box.lan:8000/v1",
        transport=httpx.MockTransport(_handler_factory(seen)),
    )
    await provider.generate([{"role": "user", "content": "hi"}])
    assert seen["url"] == "http://gpu-box.lan:8000/v1/chat/completions"


@pytest.mark.asyncio
async def test_vllm_error_surface_matches_openai_compat_provider():
    def failing_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "vllm oom"})

    provider = vllm_provider("m", transport=httpx.MockTransport(failing_handler))
    with pytest.raises(ProviderError):
        await provider.generate([{"role": "user", "content": "hi"}])


# --- vllm_from_env ------------------------------------------------------------


def test_vllm_from_env_reads_base_url_and_model(monkeypatch):
    monkeypatch.setenv("ARCHON_VLLM_BASE_URL", "http://10.0.0.9:8000/v1")
    monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_MODEL", "Qwen/Qwen2.5-7B-Instruct")
    provider = vllm_from_env()
    assert isinstance(provider, VllmProvider)
    assert provider.base_url == "http://10.0.0.9:8000/v1"
    assert provider.model == "Qwen/Qwen2.5-7B-Instruct"


def test_vllm_from_env_defaults_when_unset(monkeypatch):
    monkeypatch.delenv("ARCHON_VLLM_BASE_URL", raising=False)
    monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_MODEL", "m")
    provider = vllm_from_env()
    assert provider.base_url == VLLM_DEFAULT_BASE_URL


def test_vllm_from_env_requires_model(monkeypatch):
    monkeypatch.delenv("ARCHON_VLLM_BASE_URL", raising=False)
    monkeypatch.delenv("ARCHON_ATTACK_PROVIDER_MODEL", raising=False)
    with pytest.raises(ValueError, match="ARCHON_ATTACK_PROVIDER_MODEL"):
        vllm_from_env()


def test_vllm_from_env_passes_transport_through(monkeypatch):
    monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_MODEL", "m")

    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(
            200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]}
        )

    provider = vllm_from_env(transport=httpx.MockTransport(handler))

    import asyncio

    asyncio.run(provider.generate([{"role": "user", "content": "hi"}]))
    assert seen["url"].startswith(VLLM_DEFAULT_BASE_URL)


# --- docs & example guardrails -------------------------------------------------


def test_docs_local_models_page_exists_and_covers_the_story():
    text = open("docs-site/local-models.md").read()
    assert "vllm serve" in text
    assert "ARCHON_ATTACK_PROVIDER_KIND" in text
    assert "vllm_from_env" in text
    assert "/v1/chat/completions" in text or "OpenAI-compatible" in text


def test_examples_vllm_yaml_parses_and_validates_clean_against_schema():
    from archon_armor.config_schema import validate_config_file

    errors = validate_config_file("examples/vllm.yaml")
    assert errors == []
