"""Multi-tenancy v2 — first-class tenants with isolated agent registries.

Enterprise RFP requirements: per-tenant audit trails queryable by tenant and
SOC2 / ISO 42001 multi-tenant isolation. This module promotes TENANT to a
first-class entity: every agent enrollment is scoped to exactly one tenant,
and cross-tenant access is denied by default (strict isolation — no
super-tenant shortcuts, not even for the 'default' tenant).

Design:
    - Tenants and enrollments persist to SQLite (survives process restarts).
    - TenantStore owns its own tables (tenants / agent_tenants), keeping the
      shared SchemaMigrator untouched.
    - Enforcement primitives (``resolve_tenant``, ``assert_agent_tenant``)
      return bool/None on malformed input and never raise, so request paths
      fail closed without crashing the gateway.

Run: see tests/armor/test_tenancy.py for the TDD spec.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

TENANT_HEADER = "X-Tenant-ID"
DEFAULT_TENANT = "default"


@dataclass(frozen=True)
class Tenant:
    """One isolated customer/workspace boundary."""

    tenant_id: str  # slug
    name: str
    created_at: str  # ISO-8601 UTC
    metadata: dict = field(default_factory=dict)


class TenantStore:
    """Persistent store of tenants and their agent enrollments."""

    def __init__(self, path_or_conn: str | sqlite3.Connection | None = None) -> None:
        self._lock = threading.Lock()
        if isinstance(path_or_conn, sqlite3.Connection):
            self._conn = path_or_conn
        else:
            self._conn = sqlite3.connect(
                path_or_conn or ":memory:", check_same_thread=False
            )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS tenants ("
            "tenant_id TEXT PRIMARY KEY, name TEXT NOT NULL, "
            "created_at TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}')"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS agent_tenants ("
            "agent_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, "
            "enrolled_at TEXT NOT NULL)"
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Tenant CRUD
    # ------------------------------------------------------------------
    def create_tenant(self, tenant_id: str, name: str, metadata: dict | None = None) -> Tenant:
        now = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata or {})
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO tenants "
                "(tenant_id, name, created_at, metadata_json) VALUES (?, ?, ?, ?)",
                (tenant_id, name, now, meta_json),
            )
            self._conn.commit()
        return Tenant(
            tenant_id=tenant_id, name=name, created_at=now, metadata=dict(metadata or {})
        )

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT tenant_id, name, created_at, metadata_json FROM tenants "
                "WHERE tenant_id = ?",
                (tenant_id,),
            ).fetchone()
        if row is None:
            return None
        try:
            meta = json.loads(row[3])
        except (TypeError, ValueError):
            meta = {}
        return Tenant(tenant_id=row[0], name=row[1], created_at=row[2], metadata=meta)

    def list_tenants(self) -> list[Tenant]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT tenant_id FROM tenants ORDER BY tenant_id ASC"
            ).fetchall()
        return [t for t in (self.get_tenant(r[0]) for r in rows) if t is not None]

    def delete_tenant(self, tenant_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM tenants WHERE tenant_id = ?", (tenant_id,)
            )
            self._conn.execute(  # cascade: enrollment dies with its tenant
                "DELETE FROM agent_tenants WHERE tenant_id = ?", (tenant_id,)
            )
            self._conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Agent enrollment
    # ------------------------------------------------------------------
    def enroll_agent(self, agent_id: str, tenant_id: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            # re-enroll overwrites: an agent lives in one tenant
            self._conn.execute(
                "INSERT OR REPLACE INTO agent_tenants "
                "(agent_id, tenant_id, enrolled_at) VALUES (?, ?, ?)",
                (agent_id, tenant_id, now),
            )
            self._conn.commit()
        return True

    def is_enrolled(self, agent_id: str, tenant_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM agent_tenants WHERE agent_id = ? AND tenant_id = ?",
                (agent_id, tenant_id),
            ).fetchone()
        return row is not None

    def agents_for_tenant(self, tenant_id: str) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT agent_id FROM agent_tenants WHERE tenant_id = ? "
                "ORDER BY agent_id ASC",
                (tenant_id,),
            ).fetchall()
        return [r[0] for r in rows]

    def list_agent_tenants(self) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT agent_id, tenant_id FROM agent_tenants ORDER BY agent_id ASC"
            ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def close(self) -> None:
        self._conn.close()


def resolve_tenant(headers, store: TenantStore) -> str | None:
    """Extract the tenant from request headers; None when absent/unknown.

    Fails closed: a header naming a nonexistent (or malformed, e.g. numeric)
    tenant yields None so callers can reject the request rather than guess.
    """
    try:
        raw = headers.get(TENANT_HEADER)
    except AttributeError:
        return None
    if not isinstance(raw, str):
        return None
    tenant_id = raw.strip()
    if not tenant_id:
        return None
    if store.get_tenant(tenant_id) is None:
        return None
    return tenant_id


def assert_agent_tenant(store: TenantStore, agent_id: str, tenant_id: str) -> bool:
    """Strict-isolation access check: True iff agent is enrolled in that tenant.

    No super-tenant bypass — even agents of the 'default' tenant cannot touch
    another tenant's resources.
    """
    try:
        return store.is_enrolled(agent_id, tenant_id)
    except Exception:
        return False


__all__ = [
    "DEFAULT_TENANT",
    "TENANT_HEADER",
    "Tenant",
    "TenantStore",
    "assert_agent_tenant",
    "resolve_tenant",
]
