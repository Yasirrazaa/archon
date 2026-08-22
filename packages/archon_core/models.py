"""Shared data models for the Archon defense pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Exchange:
    """A single request/response exchange flowing through the defense pipeline.

    Attributes:
        content: The current user content being processed (may be rewritten
            by layers such as normalization or spotlighting).
        system_prompt: Optional system prompt associated with the exchange.
        response: The upstream model response (set before output layers run).
        blocked: True when a layer decided the exchange must not proceed.
        block_reason: Human-readable reason when blocked.
        metadata: Layer-annotated context (threat classification, segments,
            execution mode, guardrail results). Layers must namespace keys.
    """

    content: str
    system_prompt: str | None = None
    response: str | None = None
    blocked: bool = False
    block_reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def block(self, reason: str) -> None:
        self.blocked = True
        self.block_reason = reason
