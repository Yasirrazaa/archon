"""TDD Phase 5b: async battle/scan API — submit probes against a registered agent."""

import time

import pytest
from fastapi.testclient import TestClient

from archon_armor.app import create_app
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry

from .test_app import FakeUpstream


def make_client(policy=None):
    registry = InMemoryRegistry()
    registry.register(
        AgentCard(
            agent_id="agent-1",
            name="t",
            version="1",
            policy=policy or SecurityPolicy(upstream_base_url="https://api.upstream.test/v1"),
        )
    )
    app = create_app(registry=registry, upstream=FakeUpstream())
    return TestClient(app)


def test_submit_battle_returns_id_and_completes():
    client = make_client()
    resp = client.post("/v1/battles", json={"agent_id": "agent-1"}, headers={"X-Agent-ID": "agent-1"})
    assert resp.status_code == 202
    battle_id = resp.json()["battle_id"]
    assert resp.json()["status"] == "queued"

    # TestClient runs background tasks synchronously after the response
    status = client.get(f"/v1/battles/{battle_id}").json()
    assert status["status"] == "completed"
    assert len(status["results"]) > 0
    summary = status["summary"]
    assert summary["total_probes"] == len(status["results"])
    assert 0.0 <= summary["block_rate"] <= 1.0


def test_battle_includes_benign_control_and_injection_probe():
    client = make_client()
    battle_id = client.post("/v1/battles", json={"agent_id": "agent-1"}, headers={"X-Agent-ID": "agent-1"}).json()["battle_id"]
    status = client.get(f"/v1/battles/{battle_id}").json()

    by_name = {r["probe_name"]: r for r in status["results"]}
    assert "benign_control" in by_name
    assert by_name["benign_control"]["blocked"] is False
    assert any("injection" in name for name in by_name)


def test_battle_for_unknown_agent_rejected():
    client = make_client()
    resp = client.post("/v1/battles", json={"agent_id": "ghost"}, headers={"X-Agent-ID": "agent-1"})
    assert resp.status_code == 404


def test_unknown_battle_404():
    client = make_client()
    assert client.get("/v1/battles/does-not-exist").status_code == 404
