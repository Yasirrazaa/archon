"""Durable battle-results store (SQLite).

Persists battle summaries so they survive process restarts, support fleet
queries (newest-first, per-agent), and can be shared via a deterministic,
unguessable-by-enumeration token derived from the battle id.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS battle_results (
    battle_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    summary_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    share_token TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL DEFAULT ''
);
"""

_LEGACY_TENANT_COLUMN_SQL = (
    "ALTER TABLE battle_results ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''"
)

_UPSERT_SQL = """
INSERT INTO battle_results
    (battle_id, agent_id, summary_json, created_at, share_token, tenant_id)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(battle_id) DO UPDATE SET
    agent_id = excluded.agent_id,
    summary_json = excluded.summary_json,
    created_at = excluded.created_at,
    share_token = excluded.share_token,
    tenant_id = excluded.tenant_id;
"""


def _share_token(battle_id: str) -> str:
    """Deterministic 16-hex token: sha256(battle_id)[:16]."""
    return hashlib.sha256(battle_id.encode("utf-8")).hexdigest()[:16]


class ResultsStore:
    """SQLite-backed store for finished battle summaries."""

    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._ensure_tenant_column()
        self._conn.commit()

    def _ensure_tenant_column(self) -> None:
        cols = {row[1] for row in self._conn.execute(
            "PRAGMA table_info(battle_results)"
        ).fetchall()}
        if "tenant_id" not in cols:
            self._conn.execute(_LEGACY_TENANT_COLUMN_SQL)

    def save_battle(
        self,
        battle_id: str,
        agent_id: str,
        summary: dict[str, Any],
        tenant_id: str = "default",
    ) -> None:
        from datetime import datetime, timezone

        self._conn.execute(
            _UPSERT_SQL,
            (
                battle_id,
                agent_id,
                json.dumps(summary),
                datetime.now(timezone.utc).isoformat(),
                _share_token(battle_id),
                tenant_id,
            ),
        )
        self._conn.commit()

    def get_battle(self, battle_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT battle_id, agent_id, summary_json, created_at, tenant_id "
            "FROM battle_results WHERE battle_id = ?",
            (battle_id,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def list_battles(
        self,
        agent_id: str | None = None,
        tenant_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        sql = (
            "SELECT battle_id, agent_id, summary_json, created_at, tenant_id "
            "FROM battle_results"
        )
        conditions: list[str] = []
        params: list[Any] = []
        if agent_id is not None:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if tenant_id is not None:
            # Exact-match semantics: '' (pre-v4 legacy rows) only matches ''.
            conditions.append("tenant_id = ?")
            params.append(tenant_id)
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def share_token(self, battle_id: str) -> str:
        return _share_token(battle_id)

    def resolve_share(self, token: str) -> dict[str, Any] | None:
        # Share links are capability URLs and remain cross-tenant by design:
        # possession of the token grants read access regardless of tenancy.
        row = self._conn.execute(
            "SELECT battle_id, agent_id, summary_json, created_at, tenant_id "
            "FROM battle_results WHERE share_token = ?",
            (token,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    @staticmethod
    def _row_to_record(row) -> dict[str, Any]:
        battle_id, agent_id, summary_json, created_at, tenant_id = row
        return {
            "battle_id": battle_id,
            "agent_id": agent_id,
            "summary": json.loads(summary_json),
            "created_at": created_at,
            "tenant_id": tenant_id,
        }

    def close(self) -> None:
        self._conn.close()
