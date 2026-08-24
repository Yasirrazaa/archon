"""Sprint W7-B: ed25519-signed agent credentials (Identity v2).

Tests the REAL behavior of packages/archon_core/security/identity.py:
  - keypair generation roundtrips through PEM serialization
  - signatures cover the SAME canonical string as HMAC (authn.py §2)
  - Ed25519Verifier mirrors HmacVerifier's verdict interface so it drops in
    via create_app(identity=...) unchanged
  - rejection reasons: 'unknown agent', 'expired', 'revoked',
    'bad signature'; malformed headers never raise
  - CredentialStore persists across instances (sqlite-backed)
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

from archon_armor.app import create_app
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.security.identity import (
    AgentCredential,
    CredentialStore,
    Ed25519Verifier,
    generate_keypair,
    sign_request_ed25519,
)
from fastapi.testclient import TestClient

PATH = "/v1/chat/completions"
BENIGN = json.dumps({"model": "m", "messages": [{"role": "user", "content": "hi"}]}).encode()
OTHER = json.dumps({"model": "m", "messages": [{"role": "user", "content": "EVIL"}]}).encode()


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


def signed_headers(priv_pem, agent_id, body, ts=None):
    ts = ts if ts is not None else int(time.time())
    return {
        "X-Agent-ID": agent_id,
        "X-Timestamp": str(ts),
        "X-Signature-Ed25519": sign_request_ed25519(priv_pem, "POST", PATH, body, timestamp=ts),
    }


def make_store_and_verifier(path=None):
    store = CredentialStore(path)
    verifier = Ed25519Verifier(store)
    return store, verifier


# ------------------------------------------------------------ keypair ----

def test_generate_keypair_roundtrip():
    """PEM roundtrip: loading the private key back must yield signatures
    verifiable with the returned public key."""
    priv_pem, pub_pem = generate_keypair()
    assert isinstance(priv_pem, str) and isinstance(pub_pem, str)
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    pub = serialization.load_pem_public_key(pub_pem.encode())
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    assert isinstance(key, Ed25519PrivateKey)
    assert isinstance(pub, Ed25519PublicKey)
    sig = key.sign(b"payload")
    pub.verify(sig, b"payload")


def test_sign_request_ed25519_covers_canonical_string():
    """Signature verifies against f'{METHOD}:{path}:{ts}:{sha256(body)}' --
    the identical canonical string documented in SECURITY.md §2 / authn.py."""
    priv_pem, _ = generate_keypair()
    sig_b64 = sign_request_ed25519(priv_pem, "POST", PATH, BENIGN, timestamp=1234567890)

    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
    digest = hashlib.sha256(BENIGN).hexdigest()
    message = f"POST:{PATH}:1234567890:{digest}".encode()
    raw_sig = base64.b64decode(sig_b64)
    # raises InvalidSignature on mismatch -- absence of exception is the pass
    key.public_key().verify(raw_sig, message)


def test_sign_request_ed25519_default_timestamp_is_int():
    priv_pem, _ = generate_keypair()
    sig = sign_request_ed25519(priv_pem, "GET", "/x", b"")
    assert isinstance(sig, str)


# ----------------------------------------------------------- verifier ----

def test_verifier_happy_path():
    store, verifier = make_store_and_verifier()
    _, priv = store.issue("agent-ed")
    verdict = verifier.verify(signed_headers(priv, "agent-ed", BENIGN), BENIGN, "POST", PATH)
    assert verdict.ok is True
    assert verdict.agent_id == "agent-ed"


def test_verifier_rejects_tampered_body():
    store, verifier = make_store_and_verifier()
    _, priv = store.issue("agent-ed")
    verdict = verifier.verify(signed_headers(priv, "agent-ed", BENIGN), OTHER, "POST", PATH)
    assert verdict.ok is False
    assert verdict.reason == "bad signature"


def test_verifier_stale_timestamp_rejected():
    """Mirrors HmacVerifier's +/-300s tolerance convention."""
    _, verifier = make_store_and_verifier()
    store = verifier._store
    _, priv = store.issue("agent-ed")
    old_ts = int(time.time()) - 400
    verdict = verifier.verify(
        signed_headers(priv, "agent-ed", BENIGN, old_ts), BENIGN, "POST", PATH
    )
    assert verdict.ok is False
    assert "replay/expired" in verdict.reason


def test_verifier_future_timestamp_rejected():
    _, verifier = make_store_and_verifier()
    _, priv = verifier._store.issue("agent-ed")
    future_ts = int(time.time()) + 400
    verdict = verifier.verify(
        signed_headers(priv, "agent-ed", BENIGN, future_ts), BENIGN, "POST", PATH
    )
    assert verdict.ok is False


def test_verifier_accepts_timestamp_within_window():
    _, verifier = make_store_and_verifier()
    _, priv = verifier._store.issue("agent-ed")
    recent_ts = int(time.time()) - 60
    verdict = verifier.verify(
        signed_headers(priv, "agent-ed", BENIGN, recent_ts), BENIGN, "POST", PATH
    )
    assert verdict.ok is True


def test_verifier_unknown_agent():
    _, verifier = make_store_and_verifier()
    priv, _ = generate_keypair()
    verdict = verifier.verify(signed_headers(priv, "ghost", BENIGN), BENIGN, "POST", PATH)
    assert verdict.ok is False
    assert "unknown agent" in verdict.reason


def test_verifier_revoked_credential():
    store, verifier = make_store_and_verifier()
    _, priv = store.issue("agent-ed")
    store.revoke("agent-ed")
    verdict = verifier.verify(signed_headers(priv, "agent-ed", BENIGN), BENIGN, "POST", PATH)
    assert verdict.ok is False
    assert verdict.reason == "revoked"


def test_verifier_expired_credential():
    store, verifier = make_store_and_verifier()
    _, priv = store.issue("agent-ed", ttl_days=-1)  # already expired
    verdict = verifier.verify(signed_headers(priv, "agent-ed", BENIGN), BENIGN, "POST", PATH)
    assert verdict.ok is False
    assert verdict.reason == "expired"


# ----------------------------------------------- malformed input armor ----

def test_missing_headers_rejected_not_raised():
    _, verifier = make_store_and_verifier()
    for headers in ({}, {"X-Agent-ID": "a"}, {"X-Agent-ID": "a", "X-Timestamp": "1"}):
        verdict = verifier.verify(headers, BENIGN, "POST", PATH)
        assert verdict.ok is False


def test_malformed_timestamp_rejected_not_raised():
    _, verifier = make_store_and_verifier()
    _, priv = verifier._store.issue("agent-ed")
    headers = {
        "X-Agent-ID": "agent-ed",
        "X-Timestamp": "not-a-number",
        "X-Signature-Ed25519": "AAAA",
    }
    verdict = verifier.verify(headers, BENIGN, "POST", PATH)
    assert verdict.ok is False


def test_malformed_signature_rejected_not_raised():
    _, verifier = make_store_and_verifier()
    _, priv = verifier._store.issue("agent-ed")
    headers = {
        "X-Agent-ID": "agent-ed",
        "X-Timestamp": str(int(time.time())),
        "X-Signature-Ed25519": "***not base64!!***",
    }
    verdict = verifier.verify(headers, BENIGN, "POST", PATH)
    assert verdict.ok is False
    assert verdict.reason == "bad signature"


def test_corrupt_public_key_in_store_never_raises():
    """A tampered/corrupt PEM must yield a clean rejection, not an exception."""
    store, verifier = make_store_and_verifier()
    store._conn.execute(
        "INSERT INTO credentials VALUES (?, ?, ?, ?, 0)",
        ("broken", "NOT-A-VALID-PEM", "2026-01-01T00:00:00+00:00", None),
    )
    store._conn.commit()
    priv, _ = generate_keypair()
    verdict = verifier.verify(signed_headers(priv, "broken", BENIGN), BENIGN, "POST", PATH)
    assert verdict.ok is False


# ------------------------------------------------------- CredentialStore ----

def test_issue_returns_usable_private_key():
    store, _ = make_store_and_verifier()
    cred, priv = store.issue("agent-ed")
    assert isinstance(cred, AgentCredential)
    assert cred.agent_id == "agent-ed"
    assert priv.startswith("-----BEGIN PRIVATE KEY-----")


def test_public_key_for_unknown_agent_is_none():
    store, _ = make_store_and_verifier()
    assert store.public_key_for("nobody") is None


def test_store_persists_across_instances(tmp_path):
    """Credentials issued on one instance must be verifiable by a verifier
    built over a *newly opened* store at the same path."""
    db = str(tmp_path / "creds.sqlite")
    store_a = CredentialStore(db)
    _, priv = store_a.issue("agent-ed")
    store_b = CredentialStore(db)
    assert store_b.public_key_for("agent-ed") is not None
    verdict = Ed25519Verifier(store_b).verify(
        signed_headers(priv, "agent-ed", BENIGN), BENIGN, "POST", PATH
    )
    assert verdict.ok is True


def test_list_credentials_roundtrip():
    store, _ = make_store_and_verifier()
    store.issue("a")
    store.issue("b")
    ids = sorted(c.agent_id for c in store.list_credentials())
    assert ids == ["a", "b"]


def test_end_to_end_issue_store_verify():
    store, verifier = make_store_and_verifier()
    _, priv = store.issue("agent-ed")
    # second instance over the same in-memory state sees the same credential
    verdict = verifier.verify(signed_headers(priv, "agent-ed", BENIGN), BENIGN, "POST", PATH)
    assert verdict.ok is True


# ---------------------------------------------------------- end-to-end ----

def make_registry() -> InMemoryRegistry:
    registry = InMemoryRegistry()
    policy = SecurityPolicy(upstream_base_url="https://api.upstream.test/v1")
    registry.register(AgentCard("agent-ed", "Ed", "1.0.0", policy=policy))
    return registry


def make_client(store):
    registry = make_registry()
    app = create_app(registry=registry, upstream=FakeUpstream(), identity=Ed25519Verifier(store))
    return TestClient(app, raise_server_exceptions=False)


def test_app_dropin_signed_request_passes_identity_gate():
    """create_app(identity=Ed25519Verifier(...)) is a true drop-in: a properly
    signed request reaches the upstream (200), i.e. NOT rejected for
    signature reasons."""
    store = CredentialStore()
    _, priv = store.issue("agent-ed")
    client = make_client(store)
    resp = client.post(PATH, content=BENIGN, headers=signed_headers(priv, "agent-ed", BENIGN))
    assert resp.status_code == 200


def test_app_bad_signature_returns_401():
    store = CredentialStore()
    _, priv = store.issue("agent-ed")
    client = make_client(store)
    headers = signed_headers(priv, "agent-ed", BENIGN)
    resp = client.post(PATH, content=OTHER, headers=headers)
    assert resp.status_code == 401
    assert "bad signature" in resp.json()["error"]["message"]


def test_app_revoked_agent_returns_401():
    store = CredentialStore()
    _, priv = store.issue("agent-ed")
    client = make_client(store)
    store.revoke("agent-ed")
    resp = client.post(PATH, content=BENIGN, headers=signed_headers(priv, "agent-ed", BENIGN))
    assert resp.status_code == 401
