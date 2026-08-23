"""Sprint E0.3: auth-boundary verification tests for the HMAC scheme.

Asserts the REAL behavior of HmacVerifier (packages/archon_core/security/authn.py):
  - timestamp window (default +/-300s) rejects expired/future timestamps
  - body hash binds signatures to exact payloads (substitution rejected)
  - per-agent secrets are not interchangeable
  - NOTE: there is no nonce store -- an identical request replayed WITHIN the
    window still verifies. This is a documented limitation (see SECURITY.md),
    asserted here as real behavior rather than invented semantics.
"""

from __future__ import annotations

import json
import time

from archon_armor.app import create_app
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.security.authn import HmacVerifier, sign_request
from fastapi.testclient import TestClient

PATH = "/v1/chat/completions"
SECRET_ONE = "secret-agent-one"
SECRET_TWO = "secret-agent-two"


class FakeUpstream:
    async def complete(self, payload: dict, base_url: str, api_key: str | None = None):
        return {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "model": payload.get("model", "test-model"),
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "ok"},
                }
            ],
        }


def make_registry() -> InMemoryRegistry:
    registry = InMemoryRegistry()
    policy = SecurityPolicy(upstream_base_url="https://api.upstream.test/v1")
    registry.register(AgentCard("agent-1", "One", "1.0.0", policy=policy, api_secret=SECRET_ONE))
    registry.register(AgentCard("agent-2", "Two", "1.0.0", policy=policy, api_secret=SECRET_TWO))
    return registry


def make_signed_client():
    registry = make_registry()
    app = create_app(registry=registry, upstream=FakeUpstream(),
                     identity=HmacVerifier(registry))
    # raise_server_exceptions=False so failures surface as HTTP status codes
    return TestClient(app, raise_server_exceptions=False)


def headers_for(secret: str, agent_id: str, body: bytes, ts: int | None = None,
                path: str = PATH, method: str = "POST"):
    ts = ts if ts is not None else int(time.time())
    return {
        "X-Agent-ID": agent_id,
        "X-Timestamp": str(ts),
        "X-Signature": sign_request(secret, method, path, body, ts),
    }


BENIGN = json.dumps({"model": "m", "messages": [{"role": "user", "content": "hi"}]}).encode()
OTHER = json.dumps({"model": "m", "messages": [{"role": "user", "content": "EVIL"}]}).encode()


# ------------------------------------------------------------- verifier ----

def test_replay_same_signature_within_window_verifies():
    """REAL behavior: no nonce store exists; the timestamp window is the only
    replay defense, so an identical request replayed inside the window is
    accepted. Documented limitation in SECURITY.md."""
    verifier = HmacVerifier(make_registry())
    headers = headers_for(SECRET_ONE, "agent-1", BENIGN)
    first = verifier.verify(headers, BENIGN, "POST", PATH)
    second = verifier.verify(headers, BENIGN, "POST", PATH)
    assert first.ok and second.ok


def test_expired_timestamp_rejected():
    verifier = HmacVerifier(make_registry())
    old_ts = int(time.time()) - 400  # beyond default 300s tolerance
    verdict = verifier.verify(headers_for(SECRET_ONE, "agent-1", BENIGN, ts=old_ts),
                              BENIGN, "POST", PATH)
    assert verdict.ok is False
    assert "replay/expired" in verdict.reason


def test_future_timestamp_beyond_window_rejected():
    verifier = HmacVerifier(make_registry())
    future_ts = int(time.time()) + 400
    verdict = verifier.verify(headers_for(SECRET_ONE, "agent-1", BENIGN, ts=future_ts),
                              BENIGN, "POST", PATH)
    assert verdict.ok is False


def test_timestamp_within_window_accepted():
    verifier = HmacVerifier(make_registry())
    recent_ts = int(time.time()) - 60  # safely inside the 300s tolerance
    verdict = verifier.verify(headers_for(SECRET_ONE, "agent-1", BENIGN, ts=recent_ts),
                              BENIGN, "POST", PATH)
    assert verdict.ok is True


def test_body_substitution_rejected():
    """A valid signature over body A must not authorize delivery of body B."""
    verifier = HmacVerifier(make_registry())
    headers = headers_for(SECRET_ONE, "agent-1", BENIGN)
    verdict = verifier.verify(headers, OTHER, "POST", PATH)
    assert verdict.ok is False
    assert verdict.reason == "invalid signature"


def test_cross_agent_secret_rejected():
    """Signing with another agent's secret must not authenticate."""
    verifier = HmacVerifier(make_registry())
    headers = headers_for(SECRET_TWO, "agent-1", BENIGN)  # wrong secret for agent-1
    verdict = verifier.verify(headers, BENIGN, "POST", PATH)
    assert verdict.ok is False
    assert verdict.reason == "invalid signature"


# ------------------------------------------------------- end-to-end app ----

def test_app_accepts_signed_request_and_replay_within_window():
    client = make_signed_client()
    headers = headers_for(SECRET_ONE, "agent-1", BENIGN)
    first = client.post(PATH, content=BENIGN, headers=headers)
    replay = client.post(PATH, content=BENIGN, headers=headers)  # same signature reused
    assert first.status_code == 200
    assert replay.status_code == 200  # REAL behavior: window-only replay defense


def test_app_rejects_expired_timestamp_with_401():
    client = make_signed_client()
    old_ts = int(time.time()) - 400
    resp = client.post(PATH, content=BENIGN,
                       headers=headers_for(SECRET_ONE, "agent-1", BENIGN, ts=old_ts))
    assert resp.status_code == 401


def test_app_rejects_body_substitution_with_401():
    client = make_signed_client()
    resp = client.post(PATH, content=OTHER,
                       headers=headers_for(SECRET_ONE, "agent-1", BENIGN))
    assert resp.status_code == 401


def test_app_rejects_cross_agent_secret_with_401():
    client = make_signed_client()
    resp = client.post(PATH, content=BENIGN,
                       headers=headers_for(SECRET_TWO, "agent-1", BENIGN))
    assert resp.status_code == 401
