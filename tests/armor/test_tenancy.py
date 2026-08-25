"""TDD spec for Sprint MT-A: multi-tenancy v2 enforcement primitives.

Enterprise RFP requirements: per-tenant audit trails queryable by tenant,
SOC2 / ISO 42001 multi-tenant isolation. TENANT becomes a first-class entity
with an isolated agent registry: every agent enrollment is scoped to exactly
one tenant and cross-tenant access is denied by default (strict isolation).
"""

from __future__ import annotations

import threading

from archon_core.security.tenancy import (
    Tenant,
    TenantStore,
    assert_agent_tenant,
    resolve_tenant,
)


def _make_store(tmp_path):
    return TenantStore(str(tmp_path / "tenants.db"))


class TestTenantCRUD:
    def test_create_and_get_roundtrip(self, tmp_path):
        store = _make_store(tmp_path)
        t = store.create_tenant("acme", "Acme Corp", {"tier": "enterprise"})
        assert isinstance(t, Tenant)
        got = store.get_tenant("acme")
        assert got is not None
        assert got.tenant_id == "acme"
        assert got.name == "Acme Corp"
        assert got.metadata == {"tier": "enterprise"}
        assert got.created_at  # UTC ISO timestamp present

    def test_create_tenant_defaults(self, tmp_path):
        store = _make_store(tmp_path)
        t = store.create_tenant("beta", "Beta LLC")
        assert t.metadata == {}
        assert t.created_at.endswith("+00:00") or t.created_at.endswith("Z")

    def test_get_missing_tenant_returns_none(self, tmp_path):
        store = _make_store(tmp_path)
        assert store.get_tenant("nope") is None

    def test_list_tenants_sorted(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("zeta", "Z")
        store.create_tenant("alpha", "A")
        assert [t.tenant_id for t in store.list_tenants()] == ["alpha", "zeta"]

    def test_delete_tenant_removes_it(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        assert store.delete_tenant("acme") is True
        assert store.get_tenant("acme") is None

    def test_delete_missing_tenant_returns_false(self, tmp_path):
        store = _make_store(tmp_path)
        assert store.delete_tenant("ghost") is False


class TestEnrollment:
    def test_enroll_and_is_enrolled(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        assert store.is_enrolled("agent-a", "acme") is False
        store.enroll_agent("agent-a", "acme")
        assert store.is_enrolled("agent-a", "acme") is True

    def test_reenroll_overwrites_no_duplicate(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        store.enroll_agent("agent-a", "acme")
        store.enroll_agent("agent-a", "acme")
        assert len(store.agents_for_tenant("acme")) == 1

    def test_agents_for_tenant(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        store.enroll_agent("b-agent", "acme")
        store.enroll_agent("a-agent", "acme")
        assert store.agents_for_tenant("acme") == ["a-agent", "b-agent"]

    def test_list_agent_tenants(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme")
        store.create_tenant("globex", "Globex")
        store.enroll_agent("agent-a", "acme")
        store.enroll_agent("agent-b", "globex")
        assert ("agent-a", "acme") in store.list_agent_tenants()
        assert ("agent-b", "globex") in store.list_agent_tenants()

    def test_delete_tenant_cascades_enrollments(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        store.enroll_agent("agent-a", "acme")
        store.delete_tenant("acme")
        assert store.agents_for_tenant("acme") == []
        assert store.is_enrolled("agent-a", "acme") is False
        assert ("agent-a", "acme") not in store.list_agent_tenants()


class TestResolveTenant:
    def test_header_present_returns_tenant(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        assert resolve_tenant({"X-Tenant-ID": "acme"}, store) == "acme"

    def test_header_absent_returns_none(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        assert resolve_tenant({}, store) is None

    def test_unknown_tenant_returns_none_strict(self, tmp_path):
        store = _make_store(tmp_path)
        assert resolve_tenant({"X-Tenant-ID": "ghost"}, store) is None

    def test_malformed_headers_never_raise(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        assert resolve_tenant(None, store) is None
        assert resolve_tenant({"X-Tenant-ID": 12345}, store) is None
        assert resolve_tenant({"X-Tenant-ID": "   "}, store) is None


class TestAssertAgentTenant:
    def test_allow_enrolled_agent(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        store.enroll_agent("agent-a", "acme")
        assert assert_agent_tenant(store, "agent-a", "acme") is True

    def test_deny_unenrolled_agent(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        assert assert_agent_tenant(store, "stranger", "acme") is False

    def test_cross_tenant_denied_strict_isolation(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        store.create_tenant("default", "Default")
        store.enroll_agent("agent-a", "acme")
        # Super-tenant 'default' sees nothing extra — strict isolation.
        assert assert_agent_tenant(store, "agent-a", "default") is False


class TestPersistenceAndThreads:
    def test_persistence_across_instances(self, tmp_path):
        path = str(tmp_path / "tenants.db")
        s1 = TenantStore(path)
        s1.create_tenant("acme", "Acme Corp")
        s1.enroll_agent("agent-a", "acme")
        s2 = TenantStore(path)
        assert s2.get_tenant("acme").name == "Acme Corp"
        assert s2.is_enrolled("agent-a", "acme") is True

    def test_accepts_existing_connection(self, tmp_path):
        import sqlite3

        conn = sqlite3.connect(str(tmp_path / "tenants.db"), check_same_thread=False)
        store = TenantStore(conn)
        store.create_tenant("acme", "Acme Corp")
        assert store.get_tenant("acme") is not None

    def test_thread_safety_smoke(self, tmp_path):
        store = _make_store(tmp_path)
        store.create_tenant("acme", "Acme Corp")
        errors: list[Exception] = []

        def worker(i: int) -> None:
            try:
                store.enroll_agent(f"agent-{i}", "acme")
                store.is_enrolled(f"agent-{i}", "acme")
                store.agents_for_tenant("acme")
            except Exception as exc:  # pragma: no cover - captured below
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert errors == []
        assert len(store.agents_for_tenant("acme")) == 8
