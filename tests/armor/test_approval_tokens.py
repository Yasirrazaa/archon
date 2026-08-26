"""Sprint 91: APC C3 context-binding + C4 one-shot approval tokens."""

import base64
from datetime import datetime, timedelta, timezone

import pytest
from archon_core.security.approval import (
    ContextBinding,
    TokenVerdict,
    binding_fields,
    issue_approval,
    verify_approval,
)
from archon_core.security.identity import generate_keypair

NOW = datetime(2026, 8, 26, 12, 0, 0, tzinfo=timezone.utc)

ACTION = {"tool": "web.search", "params": {"query": "archon", "limit": 5}}


@pytest.fixture(scope="module")
def keys():
    priv, pub = generate_keypair()
    return priv, pub


def _canonical_bytes(obj) -> bytes:
    import json

    return base64.b64encode(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    )


class TestContextBinding:
    def test_binding_fields_format(self):
        envelope = {"task_instance_id": "t-42", "policy_version": "v7"}
        assert binding_fields(envelope) == "task:t-42:policy:v7"

    def test_context_binding_dataclass(self):
        b = ContextBinding(task_instance_id="t-1", policy_version="v1")
        assert b.task_instance_id == "t-1"
        assert b.policy_version == "v1"

    def test_binding_fields_usable_in_canonical_string(self):
        """binding_fields output composes into a sign_request_ed25519-style
        colon-delimited canonical string."""
        envelope = {"task_instance_id": "abc", "policy_version": "v2"}
        canonical = f"POST:/approve:{binding_fields(envelope)}"
        assert canonical == "POST:/approve:task:abc:policy:v2"


class TestIssueApproval:
    def test_roundtrip_ok(self, keys):
        priv, pub = keys
        token_dict, sig_hex = issue_approval(priv, "agent-1", ACTION)
        verdict = verify_approval(sig_hex, token_dict, pub, action=ACTION)
        assert isinstance(verdict, TokenVerdict)
        assert verdict.ok is True
        assert verdict.reason == "ok"

    def test_token_shape(self, keys):
        priv, _ = keys
        token_dict, _sig = issue_approval(priv, "agent-9", ACTION, ttl_seconds=60)
        assert token_dict["agent_id"] == "agent-9"
        assert set(token_dict) == {
            "agent_id",
            "action_hash",
            "issued_at",
            "expires_at",
            "nonce",
        }

    def test_action_hash_is_sha256_of_canonical_json(self, keys):
        import hashlib
        import json

        priv, _ = keys
        token_dict, _sig = issue_approval(priv, "a", ACTION)
        expected = hashlib.sha256(
            json.dumps(ACTION, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert token_dict["action_hash"] == expected
        # param order must not matter
        token2, _ = issue_approval(priv, "a", dict(reversed(list(ACTION.items()))))
        assert token2["action_hash"] == expected

    def test_ttl_reflected_in_expires_at(self, keys):
        priv, _ = keys
        token_dict, _ = issue_approval(priv, "a", ACTION, ttl_seconds=900)
        issued = datetime.fromisoformat(token_dict["issued_at"])
        expires = datetime.fromisoformat(token_dict["expires_at"])
        assert (expires - issued).total_seconds() == 900

    def test_nonces_unique(self, keys):
        priv, _ = keys
        t1, _ = issue_approval(priv, "a", ACTION)
        t2, _ = issue_approval(priv, "a", ACTION)
        assert t1["nonce"] != t2["nonce"]

    def test_nonce_is_uuid4_hex(self, keys):
        import uuid

        priv, _ = keys
        token_dict, _ = issue_approval(priv, "a", ACTION)
        assert uuid.UUID(token_dict["nonce"]).version == 4


class TestVerifyApproval:
    def test_wrong_action_rejected(self, keys):
        priv, pub = keys
        token_dict, sig_hex = issue_approval(priv, "agent-1", ACTION)
        other = {"tool": "fs.delete", "params": {"path": "/etc/passwd"}}
        verdict = verify_approval(sig_hex, token_dict, pub, action=other)
        assert verdict.ok is False
        assert "action" in verdict.reason

    def test_expired_rejected(self, keys):
        priv, pub = keys
        token_dict, sig_hex = issue_approval(priv, "agent-1", ACTION, ttl_seconds=10)
        later = NOW + timedelta(seconds=11)
        verdict = verify_approval(sig_hex, token_dict, pub, action=ACTION, now=later)
        assert verdict.ok is False
        assert verdict.reason == "expired"

    def test_not_yet_expired_accepted_with_explicit_now(self, keys):
        priv, pub = keys
        token_dict, sig_hex = issue_approval(priv, "agent-1", ACTION, ttl_seconds=300)
        issued = datetime.fromisoformat(token_dict["issued_at"])
        verdict = verify_approval(
            sig_hex, token_dict, pub, action=ACTION, now=issued + timedelta(seconds=1)
        )
        assert verdict.ok is True
        assert verdict.ok is True

    def test_tampered_signature_rejected(self, keys):
        priv, pub = keys
        token_dict, sig_hex = issue_approval(priv, "agent-1", ACTION)
        raw = bytearray(bytes.fromhex(sig_hex))
        raw[0] ^= 0xFF
        verdict = verify_approval(raw.hex(), token_dict, pub, action=ACTION)
        assert verdict.ok is False
        assert verdict.reason == "bad signature"

    def test_tampered_token_rejected(self, keys):
        priv, pub = keys
        token_dict, sig_hex = issue_approval(priv, "agent-1", ACTION)
        forged = dict(token_dict, agent_id="agent-evil")
        verdict = verify_approval(sig_hex, forged, pub, action=ACTION)
        assert verdict.ok is False
        assert verdict.reason == "bad signature"

    def test_malformed_signature_never_raises(self, keys):
        _, pub = keys
        for bad in ("not-hex", "", "00"):
            v = verify_approval(bad, {"agent_id": "a"}, pub, action=ACTION)
            assert v.ok is False

    def test_malformed_token_never_raises(self, keys):
        priv, pub = keys
        _, sig_hex = issue_approval(priv, "a", ACTION)
        for bad in (None, "string", 42, {}, {"nonce": None}):
            v = verify_approval(sig_hex, bad, pub, action=ACTION)
            assert v.ok is False

    def test_bad_public_key_never_raises(self, keys):
        priv, _ = keys
        token_dict, sig_hex = issue_approval(priv, "a", ACTION)
        v = verify_approval(sig_hex, token_dict, "garbage pem", action=ACTION)
        assert v.ok is False


class TestOneShotSemantics:
    def test_same_token_different_action_fails_even_after_success(self, keys):
        """Replay of the same token against a different action must fail."""
        priv, pub = keys
        token_dict, sig_hex = issue_approval(priv, "agent-1", ACTION)
        assert verify_approval(sig_hex, token_dict, pub, action=ACTION).ok is True
        swapped = {"tool": "web.search", "params": {"query": "other", "limit": 99}}
        verdict = verify_approval(sig_hex, token_dict, pub, action=swapped)
        assert verdict.ok is False
