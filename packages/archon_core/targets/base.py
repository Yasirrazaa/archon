"""Target contracts: anything that behaves like an agent can be probed."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetResponse:
    """What a target returned for one probe."""

    content: str
    blocked: bool = False
    block_reason: str | None = None
    raw: dict[str, Any] | None = field(default_factory=dict)


class TargetAdapter(ABC):
    """Send one probe payload to a target and classify the outcome.

    Implementations decide what "blocked" means for their transport
    (refusal phrasing for chat endpoints, tool-call traces for MCP, etc.).
    """

    @abstractmethod
    async def send(self, payload: str) -> TargetResponse: ...
