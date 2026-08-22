"""Versioned registry wrapper: policy history + audit trail over any Registry.

Decorates a concrete Registry (InMemory, Sqlite, later Postgres) with the
governance layer enterprises need: every policy change becomes a numbered
version, and registration/update/deletion events land in the audit trail.
"""

from __future__ import annotations

import json

from ..audit import SqliteAuditTrail
from archon_core.registry.base import (
    AgentCard,
    Registry,
    SecurityPolicy,
)


class VersionedRegistry(Registry):
    def __init__(self, inner: Registry, audit_path: str | None = None):
        self._inner = inner
        self._audit = SqliteAuditTrail(audit_path or "archon_audit.db")
        self._versions: dict[str, list[dict]] = {}

    def register(self, card: AgentCard) -> None:
        self._inner.register(card)
        self._record_version(card.agent_id, card.policy, actor="system")
        self._audit.append("agent.registered", card.agent_id, actor="system",
                           details={"name": card.name, "version": card.version})

    def update_policy(self, agent_id: str, policy: SecurityPolicy, actor: str = "system") -> int:
        self._inner.update_policy(agent_id, policy)
        version = self._record_version(agent_id, policy, actor=actor)
        self._audit.append("policy.updated", agent_id, actor=actor,
                           details={"version": version})
        return version

    def get(self, agent_id: str) -> AgentCard:
        return self._inner.get(agent_id)

    def get_policy(self, agent_id: str) -> SecurityPolicy:
        return self._inner.get_policy(agent_id)

    def list_agents(self) -> list[AgentCard]:
        return self._inner.list_agents()

    def delete(self, agent_id: str) -> bool:
        deleted = self._inner.delete(agent_id)
        if deleted:
            self._audit.append("agent.deleted", agent_id, actor="system")
        return deleted

    def policy_history(self, agent_id: str) -> list[dict]:
        return [dict(v) for v in self._versions.get(agent_id, [])]

    @property
    def audit(self):
        return self._audit

    def _record_version(self, agent_id: str, policy: SecurityPolicy, actor: str) -> int:
        history = self._versions.setdefault(agent_id, [])
        version = len(history) + 1
        history.append({
            "version": version,
            "actor": actor,
            "policy_json": json.dumps({
                "block_categories": list(policy.block_categories),
                "min_confidence": policy.min_confidence,
                "output_guardrails": policy.output_guardrails,
                "max_llm_budget": policy.max_llm_budget,
                "upstream_base_url": policy.upstream_base_url,
            }),
        })
        return version
