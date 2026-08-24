"""Sprint IMP-7: nonce store closing the HMAC replay window.

Asserts the REAL behavior of NonceStore and HmacVerifier's optional nonce
support (packages/archon_core/security/authn.py):
  - nonces are single-use within a TTL (monotonic clock)
  - the store is bounded (oldest entries evicted past max_entries)
  - HmacVerifier with a nonce_store requires X-Nonce and rejects reuse
  - HmacVerifier without a nonce store keeps legacy window-only semantics
"""

from __future__ import annotations

import json
import time

import archon_core.security.authn as authn_module
from archon_armor.app import create_app
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.security.authn import HmacVerifier, NonceStore, sign_request
from fastapi.testclient import TestClient

PATH = "/v1/chat/completions"
SECRET = "secret-agent-one"


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
    registry.register(AgentCard("agent-1", "One", "1.0.0", policy=policy, api_secret=SECRET))
    return registry


def signed_headers(body: bytes, nonce: str | None = None) -> dict[str, str]:
    ts = int(time.time())
    headers = {
        "X-Agent-ID": "agent-1",
        "X-Timestamp": str(ts),
        "X-Signature": sign_request(SECRET, "POST", PATH, body, ts),
    }
    if nonce is not None:
        headers["X-Nonce"] = nonce
    return headers


BENIGN = json.dumps({"model": "m", "messages": [{"role": "user", "content": "hi"}]}).encode()
OTHER = json.dumps({"model": "m", "messages": [{"role": "user", "content": "EVIL"}]}).encode()


# ---------------------------------------------------------- NonceStore ----

def test_register_first_time_returns_true():
    store = NonceStore()
    assert store.register("nonce-a") is True


def test_register_duplicate_returns_false():
    store = NonceStore()
    assert store.register("nonce-a") is True
    assert store.register("nonce-a") is False


def test_ttl_expiry_allows_reregistration(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(authn_module.time, "monotonic", lambda: clock["now"])
    store = NonceStore(ttl_seconds=10)
    assert store.register("nonce-a") is True
    assert store.register("nonce-a") is False  # inside TTL
    clock["now"] += 11  # beyond TTL -> entry pruned on next insert
    assert store.register("nonce-a") is True


def test_expired_entries_pruned_on_insert(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(authn_module.time, "monotonic", lambda: clock["now"])
    store = NonceStore(ttl_seconds=10)
    store.register("old-1")
    store.register("old-2")
    assert len(store._nonces) == 2
    clock["now"] += 11
    store.register("fresh")
    assert set(store._nonces) == {"fresh"}


def test_eviction_respects_max_entries():
    store = NonceStore(max_entries=2)
    assert store.register("a") is True
    assert store.register("b") is True
    assert store.register("c") is True  # pushes size to 3 -> evicts oldest ("a")
    assert store.register("a") is True  # was evicted; reinserting evicts "b"
    assert store.register("c") is False  # still resident
    assert len(store._nonces) <= 2


# --------------------------------------------------- HmacVerifier wiring ---

def test_verifier_without_nonce_store_keeps_legacy_replay_semantics():
    """Legacy mode (documented opt-in): no store -> same signed request
    verifies again within the timestamp window."""
    verifier = HmacVerifier(make_registry())
    headers = signed_headers(BENIGN)
    assert verifier.verify(headers, BENIGN, "POST", PATH).ok
    assert verifier.verify(headers, BENIGN, "POST", PATH).ok


def test_verifier_with_store_requires_nonce_header():
    verifier = HmacVerifier(make_registry(), nonce_store=NonceStore())
    verdict = verifier.verify(signed_headers(BENIGN), BENIGN, "POST", PATH)
    assert verdict.ok is False
    assert "nonce required" in verdict.reason


def test_verifier_accepts_fresh_nonce():
    verifier = HmacVerifier(make_registry(), nonce_store=NonceStore())
    verdict = verifier.verify(signed_headers(BENIGN, nonce="n-1"), BENIGN, "POST", PATH)
    assert verdict.ok is True
    assert verdict.agent_id == "agent-1"


def test_verifier_rejects_replayed_nonce():
    verifier = HmacVerifier(make_registry(), nonce_store=NonceStore())
    headers = signed_headers(BENIGN, nonce="n-1")
    assert verifier.verify(headers, BENIGN, "POST", PATH).ok
    second = verifier.verify(headers, BENIGN, "POST", PATH)
    assert second.ok is False
    assert "replay detected" in second.reason


def test_different_body_same_nonce_rejected():
    """A captured nonce must not authorize a different payload; signature
    binding rejects it before the nonce check can be abused."""
    verifier = HmacVerifier(make_registry(), nonce_store=NonceStore())
    assert verifier.verify(signed_headers(BENIGN, nonce="n-1"), BENIGN, "POST", PATH).ok
    verdict = verifier.verify(signed_headers(OTHER, nonce="n-1"), OTHER, "POST", PATH)
    assert verdict.ok is False


def test_expired_nonce_reusable_after_ttl(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(authn_module.time, "monotonic", lambda: clock["now"])
    verifier = HmacVerifier(make_registry(), nonce_store=NonceStore(ttl_seconds=10))
    headers = signed_headers(BENIGN, nonce="n-1")
    assert verifier.verify(headers, BENIGN, "POST", PATH).ok
    clock["now"] += 11
    headers = signed_headers(BENIGN, nonce="n-1")  # fresh timestamp/signature
    assert verifier.verify(headers, BENIGN, "POST", PATH).ok


# ------------------------------------------------------- end-to-end app ----

def make_client_with_nonces():
    registry = make_registry()
    app = create_app(registry=registry, upstream=FakeUpstream(),
                     identity=HmacVerifier(registry, nonce_store=NonceStore()))
    return TestClient(app, raise_server_exceptions=False)


def test_app_accepts_fresh_nonce_and_rejects_replay_with_401():
    client = make_client_with_nonces()
    headers = signed_headers(BENIGN, nonce="n-e2e")
    first = client.post(PATH, content=BENIGN, headers=headers)
    replay = client.post(PATH, content=BENIGN, headers=headers)
    assert first.status_code == 200
    assert replay.status_code == 401
    assert "replay detected" in replay.json()["error"]["message"]


def test_app_rejects_missing_nonce_with_401():
    client = make_client_with_nonces()
    resp = client.post(PATH, content=BENIGN, headers=signed_headers(BENIGN))
    assert resp.status_code == 401
    assert "nonce required" in resp.json()["error"]["message"]
