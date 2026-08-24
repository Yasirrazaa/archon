"""Minimal schema-migration framework for Archon's SQLite stores.

Each migration is a versioned, ordered list of SQL statements recorded in a
`schema_migrations` table so `apply_all()` is idempotent: already-applied
versions are skipped, and each new migration runs inside its own transaction
(all-or-nothing per version).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Migration:
    """One forward-only schema change, applied atomically."""

    version: int
    name: str
    statements: list[str] = field(default_factory=list)


MIGRATIONS: list[Migration] = [
    Migration(
        version=1,
        name="agents_table",
        statements=[
            """
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                policy_json TEXT NOT NULL DEFAULT '{}'
            )
            """,
        ],
    ),
    Migration(
        version=2,
        name="battles_table",
        statements=[
            """
            CREATE TABLE IF NOT EXISTS battles (
                battle_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                summary_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """,
        ],
    ),
    Migration(
        version=3,
        name="battles_agent_index",
        statements=[
            "CREATE INDEX IF NOT EXISTS idx_battles_agent_id ON battles(agent_id)",
        ],
    ),
    Migration(
        version=4,
        name="battles_tenant_id",
        statements=[
            "ALTER TABLE battles ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''",
        ],
    ),
]

_MIGRATIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
)
"""


def _open(target: sqlite3.Connection | str | Path) -> sqlite3.Connection:
    if isinstance(target, sqlite3.Connection):
        return target
    return sqlite3.connect(str(target))


class SchemaMigrator:
    """Applies MIGRATIONS to a SQLite database (path or existing connection)."""

    def __init__(self, conn_or_path: sqlite3.Connection | str | Path) -> None:
        self._owns_conn = not isinstance(conn_or_path, sqlite3.Connection)
        self._conn = _open(conn_or_path)

    def ensure_migrations_table(self) -> None:
        self._conn.execute(_MIGRATIONS_TABLE_SQL)
        self._conn.commit()

    def applied_versions(self) -> set[int]:
        rows = self._conn.execute("SELECT version FROM schema_migrations").fetchall()
        return {int(r[0]) for r in rows}

    def apply_all(self) -> list[int]:
        """Apply pending migrations oldest-first; returns newly-applied versions."""
        self.ensure_migrations_table()
        applied = self.applied_versions()
        newly_applied: list[int] = []
        for migration in sorted(MIGRATIONS, key=lambda m: m.version):
            if migration.version in applied:
                continue
            # One transaction per migration: partial application rolls back.
            try:
                with self._conn:
                    for statement in migration.statements:
                        self._conn.execute(statement)
                    self._conn.execute(
                        "INSERT INTO schema_migrations (version, name, applied_at) "
                        "VALUES (?, ?, ?)",
                        (
                            migration.version,
                            migration.name,
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )
            except sqlite3.Error:
                raise
            newly_applied.append(migration.version)
        return newly_applied

    def close(self) -> None:
        if self._owns_conn:
            self._conn.close()
