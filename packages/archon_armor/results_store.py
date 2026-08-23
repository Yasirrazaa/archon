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
    share_token TEXT NOT NULL UNIQUE
);
"""

_UPSERT_SQL = """
INSERT INTO battle_results (battle_id, agent_id, summary_json, created_at, share_token)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(battle_id) DO UPDATE SET
    agent_id = excluded.agent_id,
    summary_json = excluded.summary_json,
    created_at = excluded.created_at,
    share_token = excluded.share_token;
"""


def _share_token(battle_id: str) -> str:
    """Deterministic 16-hex token: sha256(battle_id)[:16]."""
    return hashlib.sha256(battle_id.encode("utf-8")).hexdigest()[:16]


class ResultsStore:
    """SQLite-backed store for finished battle summaries."""

    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def save_battle(self, battle_id: str, agent_id: str, summary: dict[str, Any]) -> None:
        from datetime import datetime, timezone

        self._conn.execute(
            _UPSERT_SQL,
            (
                battle_id,
                agent_id,
                json.dumps(summary),
                datetime.now(timezone.utc).isoformat(),
                _share_token(battle_id),
            ),
        )
        self._conn.commit()

    def get_battle(self, battle_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT battle_id, agent_id, summary_json, created_at "
            "FROM battle_results WHERE battle_id = ?",
            (battle_id,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def list_battles(
        self, agent_id: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        sql = (
            "SELECT battle_id, agent_id, summary_json, created_at FROM battle_results"
        )
        params: list[Any] = []
        if agent_id is not None:
            sql += " WHERE agent_id = ?"
            params.append(agent_id)
        sql += " ORDER BY created_at DESC, rowid DESC LIMIT ?"
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_record(row) for row in rows]

    def share_token(self, battle_id: str) -> str:
        return _share_token(battle_id)

    def resolve_share(self, token: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT battle_id, agent_id, summary_json, created_at "
            "FROM battle_results WHERE share_token = ?",
            (token,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    @staticmethod
    def _row_to_record(row) -> dict[str, Any]:
        battle_id, agent_id, summary_json, created_at = row
        return {
            "battle_id": battle_id,
            "agent_id": agent_id,
            "summary": json.loads(summary_json),
            "created_at": created_at,
        }

    def close(self) -> None:
        self._conn.close()
