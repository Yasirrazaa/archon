from .anthropic import ClaudeNativeProvider
from .base import Completion, LLMProvider, ProviderError
from .openai_compat import GeminiOpenAICompatProvider, OpenAICompatProvider


def provider_from_env(transport=None) -> LLMProvider:
    """Build the attack-engine provider from ARCHON_ATTACK_PROVIDER_* env vars.

    ARCHON_ATTACK_PROVIDER_KIND: 'anthropic' (native Claude) | 'gemma' (Gemma via
    Gemini's OpenAI-compat endpoint) | 'openai' (default, any OpenAI-compatible
    endpoint incl. Gemini's compat API).
    """
    import os

    kind = os.environ.get("ARCHON_ATTACK_PROVIDER_KIND", "openai").lower()
    api_key = os.environ.get("ARCHON_ATTACK_PROVIDER_API_KEY")
    model = os.environ.get("ARCHON_ATTACK_PROVIDER_MODEL")
    if kind == "anthropic":
        return ClaudeNativeProvider(
            api_key=api_key or "",
            model=model or "claude-sonnet-4-5",
            transport=transport,
        )
    default_model = "gemma-3-27b-it" if kind == "gemma" else "gemini-2.5-flash"
    return OpenAICompatProvider(
        base_url=os.environ.get(
            "ARCHON_ATTACK_PROVIDER_BASE_URL",
            "https://generativelanguage.googleapis.com/v1beta/openai",
        ),
        api_key=api_key,
        model=model or default_model,
        transport=transport,
    )


__all__ = [
    "ClaudeNativeProvider",
    "Completion",
    "GeminiOpenAICompatProvider",
    "LLMProvider",
    "OpenAICompatProvider",
    "ProviderError",
    "provider_from_env",
]
