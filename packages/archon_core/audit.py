"""Append-only audit trail (SQLite default backend).

Auditors require an immutable record of who did what and when. This store is
append-only by convention: no update/delete APIs exist. For tamper-evidence
at scale, ship rows to WORM storage / Cloud Audit Logs via the JSONL sink.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    agent_id TEXT,
    actor TEXT NOT NULL DEFAULT 'system',
    details TEXT
);
"""


class SqliteAuditTrail:
    def __init__(self, path: str = "archon_audit.db"):
        # check_same_thread=False + lock: the trail may be written from the
        # server's request threads while owned by the creating thread.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def append(self, action: str, agent_id: str | None, actor: str = "system",
               details: dict | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_events (ts, action, agent_id, actor, details) VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    action,
                    agent_id,
                    actor,
                    json.dumps(details) if details else None,
                ),
            )
            self._conn.commit()

    def query(self, action: str | None = None, agent_id: str | None = None) -> list[dict]:
        sql = "SELECT ts, action, agent_id, actor, details FROM audit_events WHERE 1=1"
        params: list = []
        if action:
            sql += " AND action = ?"
            params.append(action)
        if agent_id:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        sql += " ORDER BY id ASC"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [
            {"ts": r[0], "action": r[1], "agent_id": r[2], "actor": r[3], "details": r[4]}
            for r in rows
        ]
