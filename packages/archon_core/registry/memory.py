"""In-memory registry backend (tests, local runs, single-process deployments)."""

from __future__ import annotations

from .base import (
    AgentCard,
    AgentNotFoundError,
    DuplicateAgentError,
    Registry,
    SecurityPolicy,
)


class InMemoryRegistry(Registry):
    def __init__(self) -> None:
        self._agents: dict[str, AgentCard] = {}

    def register(self, card: AgentCard) -> None:
        if card.agent_id in self._agents:
            raise DuplicateAgentError(f"agent already registered: {card.agent_id}")
        self._agents[card.agent_id] = card

    def get(self, agent_id: str) -> AgentCard:
        try:
            return self._agents[agent_id]
        except KeyError:
            raise AgentNotFoundError(f"unknown agent: {agent_id}") from None

    def get_policy(self, agent_id: str) -> SecurityPolicy:
        return self.get(agent_id).policy

    def list_agents(self) -> list[AgentCard]:
        return list(self._agents.values())

    def delete(self, agent_id: str) -> bool:
        return self._agents.pop(agent_id, None) is not None
