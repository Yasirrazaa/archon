"""TDD spec for IMP-3: agent kill switch (OWASP survival capability #5).

A kill switch that works at agent speed, not committee speed: one action
revokes an agent's identity everywhere, with measured time-to-contain (MTTC).
"""

from __future__ import annotations

import json
import time

from archon_armor.app import create_app
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.security.authn import HmacVerifier, sign_request
from archon_core.security.killswitch import KillSwitch, KillSwitchResult
from fastapi.testclient import TestClient

PATH = "/v1/chat/completions"


class _FakeUpstream:
    async def complete(self, payload, base_url):
        return {
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "model": payload.get("model", "unknown"),
        }


def _register(registry: InMemoryRegistry, agent_id: str = "ks-agent") -> str:
    secret = "ks-secret-123"
    card = AgentCard(
        agent_id,
        "Kill Switch Demo",
        "1.0.0",
        policy=SecurityPolicy(upstream_base_url="https://u.test/v1"),
        api_secret=secret,
    )
    registry.register(card)
    return secret


def _headers(secret: str, body: bytes) -> dict:
    ts = int(time.time())
    return {
        "X-Agent-ID": "ks-agent",
        "X-Timestamp": str(ts),
        "X-Signature": sign_request(secret, "POST", PATH, body, ts),
    }


class TestKillSwitchCore:
    def test_trigger_returns_result_with_actions_and_mttc(self, tmp_path):
        ks = KillSwitch(store_path=str(tmp_path / "revocations.db"))
        result = ks.trigger("agent-x")
        assert isinstance(result, KillSwitchResult)
        assert result.agent_id == "agent-x"
        assert len(result.actions) >= 1
        assert result.mttc_ms >= 0.0
        assert result.revoked_at  # ISO timestamp present

    def test_is_revoked_true_after_trigger(self, tmp_path):
        ks = KillSwitch(store_path=str(tmp_path / "r.db"))
        assert not ks.is_revoked("agent-x")
        ks.trigger("agent-x")
        assert ks.is_revoked("agent-x")

    def test_restore_clears_revocation(self, tmp_path):
        ks = KillSwitch(store_path=str(tmp_path / "r.db"))
        ks.trigger("agent-x")
        assert ks.restore("agent-x") is True
        assert not ks.is_revoked("agent-x")

    def test_persistence_across_instances(self, tmp_path):
        path = str(tmp_path / "r.db")
        KillSwitch(store_path=path).trigger("agent-x")
        assert KillSwitch(store_path=path).is_revoked("agent-x")

    def test_double_trigger_is_idempotent(self, tmp_path):
        ks = KillSwitch(store_path=str(tmp_path / "r.db"))
        first = ks.trigger("agent-x")
        second = ks.trigger("agent-x")
        assert first.agent_id == second.agent_id == "agent-x"
        assert ks.revoked_agents() == ["agent-x"]

    def test_mttc_is_fast_well_under_a_second(self, tmp_path):
        ks = KillSwitch(store_path=str(tmp_path / "r.db"))
        start = time.perf_counter()
        ks.trigger("agent-x")
        wall = (time.perf_counter() - start) * 1000
        assert wall < 1000.0  # agent-speed, not committee-speed


class TestArmorEnforcement:
    def _client_with_killswitch(self, tmp_path):
        registry = InMemoryRegistry()
        secret = _register(registry)
        ks = KillSwitch(store_path=str(tmp_path / "r.db"))
        app = create_app(
            registry=registry,
            upstream=_FakeUpstream(),
            identity=HmacVerifier(registry),
            kill_switch=ks,
        )
        return TestClient(app, raise_server_exceptions=False), secret, ks

    def _post(self, client, secret, body: dict):
        raw = json.dumps(body).encode()
        return client.post(PATH, content=raw, headers=_headers(secret, raw))

    def test_revoked_agent_rejected_503(self, tmp_path):
        client, secret, ks = self._client_with_killswitch(tmp_path)
        ks.trigger("ks-agent")
        resp = self._post(client, secret, {"messages": [{"role": "user", "content": "hi"}]})
        assert resp.status_code == 503
        assert "revoked" in resp.json()["error"]["message"].lower()

    def test_non_revoked_agent_passes_identity_gate(self, tmp_path):
        client, secret, ks = self._client_with_killswitch(tmp_path)
        resp = self._post(client, secret, {"messages": [{"role": "user", "content": "hi"}]})
        # Not 401/404/503 — identity accepted (upstream failure is fine here).
        assert resp.status_code not in (401, 404, 503)

    def test_restore_reenables_agent(self, tmp_path):
        client, secret, ks = self._client_with_killswitch(tmp_path)
        ks.trigger("ks-agent")
        assert self._post(client, secret, {"messages": [{"role": "user", "content": "hi"}]}).status_code == 503
        ks.restore("ks-agent")
        assert self._post(client, secret, {"messages": [{"role": "user", "content": "hi"}]}).status_code != 503


class TestAuditIntegration:
    def test_trigger_writes_audit_event(self, tmp_path):
        from archon_core.audit import SqliteAuditTrail

        audit = SqliteAuditTrail(str(tmp_path / "audit.db"))
        ks = KillSwitch(store_path=str(tmp_path / "r.db"), audit=audit)
        ks.trigger("agent-x")
        events = audit.query(action="agent.kill_switch")
        assert len(events) == 1
        assert events[0]["agent_id"] == "agent-x"


class TestJsonShape:
    def test_result_serializes_to_json(self, tmp_path):
        ks = KillSwitch(store_path=str(tmp_path / "r.db"))
        result = ks.trigger("agent-x")
        payload = json.loads(json.dumps(result.to_dict()))
        assert payload["agent_id"] == "agent-x"
        assert "mttc_ms" in payload
