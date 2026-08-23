"""Web UI dashboard: read-only fleet view over the registry (+ live battles)."""

from __future__ import annotations

import pytest
from archon_armor.ui import create_ui_app
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from fastapi.testclient import TestClient


def _card(agent_id: str = "demo-agent", **policy_kwargs) -> AgentCard:
    return AgentCard(
        agent_id,
        "Demo Agent",
        "1.0.0",
        policy=SecurityPolicy(**policy_kwargs) if policy_kwargs else SecurityPolicy(),
    )


@pytest.fixture()
def registry():
    reg = InMemoryRegistry()
    reg.register(_card())
    reg.register(
        _card(
            "strict-agent",
            block_categories=("indirect_injection",),
            min_confidence=0.7,
            output_guardrails=False,
        )
    )
    return reg


class TestSummaryApi:
    def test_lists_registered_agents_with_policy(self, registry):
        client = TestClient(create_ui_app(registry))
        r = client.get("/ui/api/summary")
        assert r.status_code == 200
        data = r.json()
        assert data["total_agents"] == 2
        ids = {a["agent_id"] for a in data["agents"]}
        assert {"demo-agent", "strict-agent"} <= ids

    def test_policy_fields_exposed(self, registry):
        client = TestClient(create_ui_app(registry))
        agent = next(
            a
            for a in client.get("/ui/api/summary").json()["agents"]
            if a["agent_id"] == "strict-agent"
        )
        assert agent["policy"]["min_confidence"] == 0.7
        assert agent["policy"]["block_categories"] == ["indirect_injection"]
        assert agent["policy"]["output_guardrails"] is False

    def test_empty_registry_ok(self):
        client = TestClient(create_ui_app(InMemoryRegistry()))
        data = client.get("/ui/api/summary").json()
        assert data["total_agents"] == 0
        assert data["agents"] == []

    def test_no_secret_leakage(self, registry):
        """api_secret must never appear in UI payloads."""
        card = _card("with-secret")
        card.api_secret = "super-secret-value"
        registry.register(card)
        body = TestClient(create_ui_app(registry)).get("/ui/api/summary").text
        assert "super-secret-value" not in body


class TestBattlesApi:
    def test_battles_empty_without_manager(self, registry):
        client = TestClient(create_ui_app(registry))
        assert client.get("/ui/api/battles").json() == []

    def test_battle_manager_recent_listing(self, registry):
        from archon_armor.battles import BattleManager

        mgr = BattleManager(registry)
        b1 = mgr.create("demo-agent")
        b2 = mgr.create("demo-agent")
        recent = [b.battle_id for b in mgr.recent()]
        assert recent == [b1.battle_id, b2.battle_id]

    def test_battles_endpoint_with_manager(self, registry):
        from archon_armor.battles import BattleManager

        mgr = BattleManager(registry)
        battle = mgr.create("demo-agent")
        client = TestClient(create_ui_app(registry, battles=mgr))
        data = client.get("/ui/api/battles").json()
        assert len(data) == 1
        assert data[0]["battle_id"] == battle.battle_id
        assert data[0]["agent_id"] == "demo-agent"


class TestDashboardPage:
    def test_html_served(self, registry):
        client = TestClient(create_ui_app(registry))
        r = client.get("/ui")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]

    def test_html_references_summary_api(self, registry):
        html = TestClient(create_ui_app(registry)).get("/ui").text
        assert "/ui/api/summary" in html
