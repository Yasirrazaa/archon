"""Run-history experiment store (ROADMAP item 84).

deepeval local_store pattern: persist every scan/battle invocation as an
immutable timestamped row so policy regressions can be diffed over time.
Complements ResultsStore (which holds the latest battle per id) with an
append-only timeline.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS run_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    agent_id TEXT NOT NULL DEFAULT '',
    label TEXT,
    block_rate REAL NOT NULL DEFAULT 0.0,
    total_probes INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    report_json TEXT NOT NULL DEFAULT '{}'
)
"""


class RunHistory:
    """Append-only store of battle/scan reports with diff support."""

    def __init__(self, store_path: str | Path) -> None:
        self._path = Path(store_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def record(self, report: dict, *, agent_id: str, label: str | None = None) -> int:
        summary = report.get("summary", {})
        cur = self._conn.execute(
            "INSERT INTO run_history (agent_id, label, block_rate, total_probes, blocked,"
            " report_json) VALUES (?, ?, ?, ?, ?, ?)",
            (
                agent_id,
                label,
                float(summary.get("block_rate", 0.0)),
                int(summary.get("total_probes", 0)),
                int(summary.get("blocked", 0)),
                json.dumps(report),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def history(self, agent_id: str | None = None, limit: int = 50) -> list[dict]:
        sql = "SELECT * FROM run_history"
        params: tuple = ()
        if agent_id is not None:
            sql += " WHERE agent_id = ?"
            params = (agent_id,)
        sql += " ORDER BY id DESC LIMIT ?"
        params = (*params, int(limit))
        return [self._row(r) for r in self._conn.execute(sql, params)]

    def latest(self, agent_id: str | None = None) -> dict | None:
        rows = self.history(agent_id=agent_id, limit=1)
        return rows[0] if rows else None

    def diff(self, run_id_a: int, run_id_b: int) -> dict:
        a = self._load(run_id_a)
        b = self._load(run_id_b)

        def blocked_names(row: dict) -> set[str]:
            return {
                r["probe_name"]
                for r in row["report"].get("results", [])
                if r.get("blocked")
            }

        names_a = blocked_names(a)
        names_b = blocked_names(b)
        rate_a = float(a["report"].get("summary", {}).get("block_rate", 0.0))
        rate_b = float(b["report"].get("summary", {}).get("block_rate", 0.0))
        return {
            "block_rate": {"a": rate_a, "b": rate_b, "delta": round(rate_b - rate_a, 6)},
            "newly_blocked": sorted(names_b - names_a),
            "newly_unblocked": sorted(names_a - names_b),
        }

    def close(self) -> None:
        self._conn.close()

    # -- internals ---------------------------------------------------------

    def _load(self, run_id: int) -> dict:
        row = self._conn.execute(
            "SELECT * FROM run_history WHERE id = ?", (int(run_id),)
        ).fetchone()
        if row is None:
            raise ValueError(f"run {run_id} not found")
        return self._row(row)

    @staticmethod
    def _row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["run_id"] = d.pop("id")
        d["report"] = json.loads(d.pop("report_json"))
        return d
