"""TDD Phase 9: policy versioning, immutable audit trail, armor audit events."""

import json

from archon_armor.app import create_app
from archon_armor.audit import SqliteAuditTrail
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.registry.versioned import VersionedRegistry
from archon_core.security.authn import AllowAllVerifier
from fastapi.testclient import TestClient

from .test_app import BENIGN_BODY, INJECTION_BODY, FakeUpstream


def make_card(policy=None):
    return AgentCard(
        agent_id="a1", name="n", version="1",
        policy=policy or SecurityPolicy(upstream_base_url="https://u.test/v1"),
    )


class TestVersionedRegistry:
    def test_policy_updates_create_versions(self, tmp_path):
        inner = InMemoryRegistry()
        registry = VersionedRegistry(inner, audit_path=tmp_path / "audit.db")
        registry.register(make_card())

        p2 = SecurityPolicy(upstream_base_url="https://u.test/v1", min_confidence=0.7)
        v2 = registry.update_policy("a1", p2, actor="admin@corp")
        assert v2 == 2

        assert registry.get_policy("a1").min_confidence == 0.7

    def test_policy_history_is_queryable_and_ordered(self, tmp_path):
        registry = VersionedRegistry(InMemoryRegistry(), audit_path=tmp_path / "a.db")
        registry.register(make_card())
        registry.update_policy("a1", SecurityPolicy(min_confidence=0.5), actor="bob")
        registry.update_policy("a1", SecurityPolicy(min_confidence=0.9), actor="alice")

        history = registry.policy_history("a1")
        assert [h["version"] for h in history] == [1, 2, 3]
        actors = {h["actor"] for h in history}
        assert {"system", "bob", "alice"} == actors

    def test_registration_and_deletion_are_audited(self, tmp_path):
        path = tmp_path / "a.db"
        registry = VersionedRegistry(InMemoryRegistry(), audit_path=path)
        registry.register(make_card())
        registry.delete("a1")

        events = registry.audit.query()
        actions = {e["action"] for e in events}
        assert {"agent.registered", "agent.deleted"} <= actions


class TestSqliteAuditTrail:
    def test_append_only_query_with_filters(self, tmp_path):
        trail = SqliteAuditTrail(tmp_path / "audit.db")
        trail.append("agent.registered", "a1", actor="system")
        trail.append("request.blocked", "a1", actor="armor", details={"reason": "injection"})
        trail.append("agent.registered", "b2", actor="system")

        a1_events = trail.query(agent_id="a1")
        assert len(a1_events) == 2
        blocked = trail.query(action="request.blocked")
        assert json.loads(blocked[0]["details"])["reason"] == "injection"


class TestArmorAuditIntegration:
    def test_blocked_requests_write_audit_events(self, tmp_path):
        registry = InMemoryRegistry()
        registry.register(make_card())
        audit = SqliteAuditTrail(tmp_path / "runtime-audit.db")
        client = TestClient(create_app(
            registry=registry, upstream=FakeUpstream(),
            identity=AllowAllVerifier(), audit=audit,
        ))
        client.post("/v1/chat/completions", json=INJECTION_BODY,
                    headers={"X-Agent-ID": "a1"})
        client.post("/v1/chat/completions", json=BENIGN_BODY,
                    headers={"X-Agent-ID": "a1"})

        events = audit.query(agent_id="a1")
        actions = {e["action"] for e in events}
        assert "request.blocked" in actions
        assert "request.allowed" in actions
