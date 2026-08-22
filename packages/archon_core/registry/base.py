"""Registry contracts: agent identity, security policy, backend ABC.

The Registry is the zero-trust anchor of archon-armor: every request must
carry an agent identity that resolves to a SecurityPolicy before any
upstream LLM call is made.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


class RegistryError(Exception):
    """Base class for registry failures."""


class DuplicateAgentError(RegistryError):
    """Raised when registering an agent_id that already exists."""


class AgentNotFoundError(RegistryError):
    """Raised when an agent_id cannot be resolved."""


@dataclass
class SecurityPolicy:
    """Per-agent defense configuration enforced by archon-armor."""

    block_categories: tuple[str, ...] = (
        "indirect_injection",
        "jailbreak",
        "prompt_extraction",
    )
    min_confidence: float = 0.4
    output_guardrails: bool = True
    max_llm_budget: int = 4
    upstream_base_url: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class AgentCard:
    """Registered agent identity and metadata."""

    agent_id: str
    name: str
    version: str
    capabilities: list[str] = field(default_factory=list)
    policy: SecurityPolicy = field(default_factory=SecurityPolicy)
    api_secret: str | None = None  # HMAC signing secret (server-side only)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class Registry(ABC):
    """Backend-agnostic agent registry interface."""

    @abstractmethod
    def register(self, card: AgentCard) -> None: ...

    @abstractmethod
    def get(self, agent_id: str) -> AgentCard: ...

    @abstractmethod
    def get_policy(self, agent_id: str) -> SecurityPolicy: ...

    @abstractmethod
    def list_agents(self) -> list[AgentCard]: ...

    @abstractmethod
    def delete(self, agent_id: str) -> bool: ...
