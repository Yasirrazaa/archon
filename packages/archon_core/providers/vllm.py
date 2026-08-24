"""Local vLLM provider — a thin preset over the OpenAI-compat transport.

vLLM ships an OpenAI-compatible server (`vllm serve`), so no new transport is
needed: this module only fixes the defaults (localhost:8000/v1, api_key 'EMPTY')
and wires an env-based factory for air-gapped / sovereign deployments.
"""

from __future__ import annotations

import httpx

from .base import LLMProvider
from .openai_compat import OpenAICompatProvider

VLLM_DEFAULT_BASE_URL = "http://localhost:8000/v1"
VLLM_DEFAULT_API_KEY = "EMPTY"


class VllmProvider(OpenAICompatProvider):
    """OpenAI-compat provider preconfigured for a local vLLM server."""

    def __init__(
        self,
        model: str,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = 60.0,
        transport: httpx.BaseTransport | None = None,
    ):
        super().__init__(
            base_url=base_url or VLLM_DEFAULT_BASE_URL,
            api_key=api_key or VLLM_DEFAULT_API_KEY,
            model=model,
            timeout_seconds=timeout_seconds,
            transport=transport,
        )


def vllm_provider(
    model: str,
    base_url: str | None = None,
    transport: httpx.BaseTransport | None = None,
) -> LLMProvider:
    """Build a VllmProvider with vLLM defaults; additive to provider_from_env."""
    return VllmProvider(model=model, base_url=base_url, transport=transport)


def vllm_from_env(transport: httpx.BaseTransport | None = None) -> LLMProvider:
    """Build a VllmProvider from ARCHON_VLLM_BASE_URL + ARCHON_ATTACK_PROVIDER_MODEL.

    Kept separate from providers.provider_from_env so that file stays stable;
    set ARCHON_ATTACK_PROVIDER_KIND=vllm and call this instead.
    """
    import os

    model = os.environ.get("ARCHON_ATTACK_PROVIDER_MODEL")
    if not model:
        raise ValueError(
            "vllm_from_env requires ARCHON_ATTACK_PROVIDER_MODEL to name the served model"
        )
    return VllmProvider(
        model=model,
        base_url=os.environ.get("ARCHON_VLLM_BASE_URL"),
        transport=transport,
    )


__all__ = [
    "VLLM_DEFAULT_API_KEY",
    "VLLM_DEFAULT_BASE_URL",
    "VllmProvider",
    "vllm_from_env",
    "vllm_provider",
]
