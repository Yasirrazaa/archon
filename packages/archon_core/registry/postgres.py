"""Postgres registry backend (psycopg3) — the enterprise durability option.

Mirrors SqliteRegistry's contract with the same JSON-column layout so agents,
policies, and secrets migrate between backends without code changes. Each
operation uses a short-lived connection from the injected ``connector``
(default: a real psycopg connection, autocommit). Swap in a pool such as
``psycopg_pool.ConnectionPool`` in production by passing a connector that
hands out pooled connections.

Set ``ARCHON_DATABASE_URL`` in archon-armor's server to use this backend.
"""

from __future__ import annotations

import json
import threading
from typing import Callable

from .base import (
    AgentCard,
    AgentNotFoundError,
    DuplicateAgentError,
    Registry,
    SecurityPolicy,
)

_DDL = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id      TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    capabilities  TEXT NOT NULL,
    policy        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    api_secret    TEXT
);
"""

_SELECT_COLS = "agent_id, name, version, capabilities, policy, created_at, api_secret"


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


class PostgresRegistry(Registry):
    """Agent registry persisted in PostgreSQL via psycopg3."""

    def __init__(
        self,
        dsn: str,
        connector: Callable[[], object] | None = None,
    ):
        self.dsn = dsn
        self._connector = connector or self._default_connector
        self._lock = threading.Lock()
        self._bootstrap()

    def _default_connector(self):
        import psycopg

        return psycopg.connect(self.dsn, autocommit=True, connect_timeout=10)

    def _bootstrap(self) -> None:
        with self._lock:
            conn = self._connector()
            try:
                with conn.cursor() as cur:
                    cur.execute(_DDL)
            finally:
                conn.close()

    def register(self, card: AgentCard) -> None:
        with self._lock:
            conn = self._connector()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO agents VALUES (%s, %s, %s, %s, %s, %s, %s)",
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
            except Exception as exc:
                from psycopg import errors

                if isinstance(exc, errors.UniqueViolation):
                    raise DuplicateAgentError(
                        f"agent already registered: {card.agent_id}"
                    ) from exc
                raise
            finally:
                conn.close()

    def get(self, agent_id: str) -> AgentCard:
        with self._lock:
            conn = self._connector()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        f"SELECT {_SELECT_COLS} FROM agents WHERE agent_id = %s",
                        (agent_id,),
                    )
                    row = cur.fetchone()
            finally:
                conn.close()
        if row is None:
            raise AgentNotFoundError(f"unknown agent: {agent_id}")
        return _row_to_card(row)

    def get_policy(self, agent_id: str) -> SecurityPolicy:
        return self.get(agent_id).policy

    def update_policy(self, agent_id: str, policy: SecurityPolicy) -> None:
        with self._lock:
            conn = self._connector()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE agents SET policy = %s WHERE agent_id = %s",
                        (json.dumps(_policy_to_dict(policy)), agent_id),
                    )
                    if cur.rowcount == 0:
                        raise AgentNotFoundError(f"unknown agent: {agent_id}")
            finally:
                conn.close()

    def list_agents(self) -> list[AgentCard]:
        with self._lock:
            conn = self._connector()
            try:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT {_SELECT_COLS} FROM agents")
                    rows = cur.fetchall()
            finally:
                conn.close()
        return [_row_to_card(row) for row in rows]

    def delete(self, agent_id: str) -> bool:
        with self._lock:
            conn = self._connector()
            try:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM agents WHERE agent_id = %s", (agent_id,))
                    return cur.rowcount > 0
            finally:
                conn.close()
