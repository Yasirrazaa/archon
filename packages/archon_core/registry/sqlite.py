"""SQLite registry backend (stdlib-only, durable default for self-hosted runs)."""

from __future__ import annotations

import json
import sqlite3
import threading

from .base import (
    AgentCard,
    AgentNotFoundError,
    DuplicateAgentError,
    Registry,
    SecurityPolicy,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    capabilities TEXT NOT NULL,
    policy TEXT NOT NULL,
    created_at TEXT NOT NULL,
    api_secret TEXT
);
"""


def _connect(path: str) -> sqlite3.Connection:
    # check_same_thread=False: the registry is used from server request threads.
    # All access is serialized through SqliteRegistry._lock.
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute(_SCHEMA)
    return conn


class SqliteRegistry(Registry):
    def __init__(self, path: str = "archon_registry.db") -> None:
        self._conn = _connect(path)
        self._lock = threading.Lock()

    def register(self, card: AgentCard) -> None:
        with self._lock:
            self._register(card)

    def _register(self, card: AgentCard) -> None:
        try:
            self._conn.execute(
                "INSERT INTO agents VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    card.agent_id,
                    card.name,
                    card.version,
                    json.dumps(card.capabilities),
                    json.dumps(_policy_to_dict(card.policy)),
                    card.created_at,
                    card.api_secret,
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            raise DuplicateAgentError(
                f"agent already registered: {card.agent_id}"
            ) from exc

    def get(self, agent_id: str) -> AgentCard:
        with self._lock:
            return self._get(agent_id)

    def _get(self, agent_id: str) -> AgentCard:
        row = self._conn.execute(
            "SELECT agent_id, name, version, capabilities, policy, created_at, api_secret "
            "FROM agents WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if row is None:
            raise AgentNotFoundError(f"unknown agent: {agent_id}")
        return _row_to_card(row)

    def get_policy(self, agent_id: str) -> SecurityPolicy:
        return self.get(agent_id).policy

    def list_agents(self) -> list[AgentCard]:
        with self._lock:
            return self._list_agents()

    def _list_agents(self) -> list[AgentCard]:
        rows = self._conn.execute(
            "SELECT agent_id, name, version, capabilities, policy, created_at, api_secret FROM agents"
        ).fetchall()
        return [_row_to_card(row) for row in rows]

    def delete(self, agent_id: str) -> bool:
        with self._lock:
            return self._delete(agent_id)

    def _delete(self, agent_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
        self._conn.commit()
        return cur.rowcount > 0


def _policy_to_dict(policy: SecurityPolicy) -> dict:
    data = policy.__dict__.copy()
    data["block_categories"] = list(policy.block_categories)
    return data


def _policy_from_dict(data: dict) -> SecurityPolicy:
    kwargs = dict(data)
    kwargs["block_categories"] = tuple(kwargs.get("block_categories", ()))
    return SecurityPolicy(**kwargs)


def _row_to_card(row) -> AgentCard:
    agent_id, name, version, capabilities, policy, created_at, api_secret = row
    return AgentCard(
        agent_id=agent_id,
        name=name,
        version=version,
        capabilities=json.loads(capabilities),
        policy=_policy_from_dict(json.loads(policy)),
        created_at=created_at,
        api_secret=api_secret,
    )
