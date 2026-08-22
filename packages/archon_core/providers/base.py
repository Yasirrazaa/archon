"""Provider contracts: how Archon calls LLMs (attack engine + paraphrase layers).

Providers are the only place vendor SDKs are allowed; archon_core itself
stays stdlib + httpx. Any OpenAI-compatible endpoint (including Gemini's
OpenAI-compat API and local vLLM servers) is one configuration away.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


class ProviderError(RuntimeError):
    """Raised when an LLM provider call fails."""


@dataclass
class Completion:
    content: str
    model: str = ""
    raw: dict | None = None


class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, messages: list[dict], **kwargs) -> Completion: ...
