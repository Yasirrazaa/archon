"""Agent kill switch — atomic revocation with measured time-to-containment.

OWASP State of Agentic AI Security v2.01 lists "a kill switch that works at
agent speed rather than committee speed" among the five survival capabilities.
This module provides the enforcement primitive: one call revokes an agent's
authority to transact through archon-armor, records the action in the audit
trail, and measures the wall-clock containment time (MTTC).

Design:
    - Revocations persist to a SQLite table (survives process restarts).
    - ``trigger`` is idempotent: re-revoking a revoked agent is a no-op that
      still returns the original revocation evidence.
    - ``restore`` clears the revocation (operator-controlled re-enable).
    - The armor app consults ``is_revoked`` per request (see app.py), so a
      revoked agent receives 503 on every route until restored.

Run: `archon kill-switch --store /data/killswitch.db --agent my-agent`
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class KillSwitchResult:
    """Evidence record for one kill-switch action."""

    agent_id: str
    revoked_at: str  # ISO-8601 UTC
    actions: list[str] = field(default_factory=list)
    mttc_ms: float = 0.0  # wall-clock milliseconds from trigger() entry

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "revoked_at": self.revoked_at,
            "actions": list(self.actions),
            "mttc_ms": self.mttc_ms,
        }


class KillSwitch:
    """Persistent, auditable agent revocation store."""

    def __init__(self, store_path: str | None = None, audit=None) -> None:
        self._audit = audit
        self._conn = sqlite3.connect(store_path or ":memory:", check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS revocations ("
            "agent_id TEXT PRIMARY KEY, revoked_at TEXT NOT NULL)"
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------
    def trigger(self, agent_id: str) -> KillSwitchResult:
        """Revoke the agent atomically; idempotent. Returns evidence."""
        start = time.perf_counter()
        actions: list[str] = []
        now = datetime.now(timezone.utc).isoformat()

        row = self._conn.execute(
            "SELECT revoked_at FROM revocations WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        if row is None:
            self._conn.execute(
                "INSERT INTO revocations (agent_id, revoked_at) VALUES (?, ?)",
                (agent_id, now),
            )
            self._conn.commit()
            actions.append("revoked_agent")
            if self._audit is not None:
                self._audit.append(
                    "agent.kill_switch",
                    agent_id,
                    actor="killswitch",
                    details={"action": "revoke"},
                )
            revoked_at = now
        else:
            revoked_at = row[0]

        mttc_ms = round((time.perf_counter() - start) * 1000.0, 3)
        return KillSwitchResult(
            agent_id=agent_id,
            revoked_at=revoked_at,
            actions=actions if actions else ["already_revoked"],
            mttc_ms=mttc_ms,
        )

    def restore(self, agent_id: str) -> bool:
        """Clear a revocation. Returns True if a revocation was removed."""
        cur = self._conn.execute(
            "DELETE FROM revocations WHERE agent_id = ?", (agent_id,)
        )
        self._conn.commit()
        removed = cur.rowcount > 0
        if removed and self._audit is not None:
            self._audit.append(
                "agent.kill_switch",
                agent_id,
                actor="killswitch",
                details={"action": "restore"},
            )
        return removed

    def is_revoked(self, agent_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM revocations WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        return row is not None

    def revoked_agents(self) -> list[str]:
        rows = self._conn.execute("SELECT agent_id FROM revocations").fetchall()
        return sorted(r[0] for r in rows)

    def close(self) -> None:
        self._conn.close()


def save_result_json(result: KillSwitchResult, path: str) -> None:
    """Persist a result as JSON (used by the CLI drill output)."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2)


__all__ = ["KillSwitch", "KillSwitchResult", "save_result_json"]
