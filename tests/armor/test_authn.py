"""TDD Phase 6: signed agent identity (HMAC) + rate limiting."""

import json
import hashlib
import hmac as hmac_mod
import time

import pytest

from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.security.authn import (
    HmacVerifier,
    Verdict,
    generate_agent_secret,
    sign_request,
)
from archon_core.security.ratelimit import TokenBucketRateLimiter

from .test_app import BENIGN_BODY, FakeUpstream


def make_registry_with_agent(agent_id="agent-1", secret=None):
    secret = secret or generate_agent_secret()
    registry = InMemoryRegistry()
    registry.register(
        AgentCard(
            agent_id=agent_id,
            name="t",
            version="1",
            policy=SecurityPolicy(upstream_base_url="https://api.upstream.test/v1"),
            api_secret=secret,
        )
    )
    return registry, secret


class TestCredentials:
    def test_generated_secrets_are_unique_and_long(self):
        a, b = generate_agent_secret(), generate_agent_secret()
        assert a != b
        assert len(a) >= 32

    def test_sign_request_is_deterministic_given_same_inputs(self):
        ts = 1234567890
        s1 = sign_request("secret", "POST", "/v1/chat/completions", b"{}", ts)
        s2 = sign_request("secret", "POST", "/v1/chat/completions", b"{}", ts)
        assert s1 == s2
        assert len(s1) == 64  # sha256 hex

    def test_signature_binds_method_path_body_timestamp(self):
        base = ("secret", "POST", "/x", b"body")
        ts = int(time.time())
        sigs = {
            sign_request(*base[:3], base[3], ts),
            sign_request("other", *base[1:], ts),
            sign_request(base[0], "GET", base[2], base[3], ts),
            sign_request(base[0], base[1], "/y", base[3], ts),
            sign_request(base[0], base[1], base[2], b"other", ts),
            sign_request(*base, ts + 1),
        }
        assert len(sigs) == 6


class TestHmacVerifier:
    def _headers(self, secret, body=b"{}", agent_id="agent-1", ts=None, sig=None):
        ts = ts if ts is not None else int(time.time())
        return {
            "X-Agent-ID": agent_id,
            "X-Timestamp": str(ts),
            "X-Signature": sig or sign_request(secret, "POST", "/v1/chat/completions", body, ts),
        }

    def test_valid_signature_passes(self):
        registry, secret = make_registry_with_agent()
        verifier = HmacVerifier(registry)
        verdict = verifier.verify(self._headers(secret), b"{}", "POST", "/v1/chat/completions")
        assert verdict.ok
        assert verdict.agent_id == "agent-1"

    def test_missing_headers_fail(self):
        registry, _ = make_registry_with_agent()
        verdict = HmacVerifier(registry).verify({}, b"", "POST", "/p")
        assert not verdict.ok
        assert "missing" in verdict.reason.lower()

    def test_unknown_agent_fails(self):
        registry, secret = make_registry_with_agent()
        verdict = HmacVerifier(registry).verify(
            self._headers(secret, agent_id="ghost"), b"", "POST", "/p"
        )
        assert not verdict.ok

    def test_wrong_secret_fails(self):
        registry, _ = make_registry_with_agent()
        other = generate_agent_secret()
        verdict = HmacVerifier(registry).verify(
            self._headers(other), b"", "POST", "/v1/chat/completions"
        )
        assert not verdict.ok

    def test_tampered_body_fails(self):
        registry, secret = make_registry_with_agent()
        verdict = HmacVerifier(registry).verify(
            self._headers(secret), b"tampered", "POST", "/v1/chat/completions"
        )
        assert not verdict.ok

    def test_expired_timestamp_rejected_replay_window(self):
        registry, secret = make_registry_with_agent()
        stale_ts = int(time.time()) - 3600
        verdict = HmacVerifier(registry, tolerance_seconds=300).verify(
            self._headers(secret, ts=stale_ts), b"", "POST", "/v1/chat/completions"
        )
        assert not verdict.ok
        assert "replay" in verdict.reason.lower() or "expired" in verdict.reason.lower()

    def test_constant_time_comparison_used(self):
        # Sanity: verify() must not leak timing-dependent early string equality.
        # We assert hmac.compare_digest is the mechanism by checking source usage.
        import inspect
        src = inspect.getsource(HmacVerifier)
        assert "compare_digest" in src


class TestArmorIntegration:
    """End-to-end: signed requests through the armor app."""

    def _make_signed_client(self, capacity=100):
        from fastapi.testclient import TestClient
        from archon_armor.app import create_app

        registry, secret = make_registry_with_agent()
        verifier = HmacVerifier(registry)
        limiter = TokenBucketRateLimiter(capacity=capacity, refill_per_second=0.001)
        client = TestClient(
            create_app(
                registry=registry,
                upstream=FakeUpstream(),
                identity=verifier,
                rate_limiter=limiter,
            )
        )
        return client, secret

    def _signed_post(self, client, secret, body_bytes, path="/v1/chat/completions", **overrides):
        ts = int(time.time())
        headers = {
            "X-Agent-ID": "agent-1",
            "X-Timestamp": str(ts),
            "X-Signature": sign_request(secret, "POST", path, body_bytes, ts),
            "Content-Type": "application/json",
        }
        headers.update(overrides)
        return client.post(path, content=body_bytes, headers=headers)

    def test_unsigned_request_rejected_401(self):
        client, _ = self._make_signed_client()
        resp = client.post(
            "/v1/chat/completions",
            json=BENIGN_BODY,
            headers={"X-Agent-ID": "agent-1"},
        )
        assert resp.status_code == 401

    def test_validly_signed_request_accepted(self):
        client, secret = self._make_signed_client()
        body = json.dumps(BENIGN_BODY).encode()
        resp = self._signed_post(client, secret, body)
        assert resp.status_code == 200
        assert resp.json()["archon"]["blocked"] is False

    def test_body_tampering_rejected_401(self):
        client, secret = self._make_signed_client()
        signed = json.dumps(BENIGN_BODY).encode()
        tampered = json.dumps({**BENIGN_BODY, "messages": [{"role": "user", "content": "evil"}]}).encode()
        ts = int(time.time())
        headers = {
            "X-Agent-ID": "agent-1",
            "X-Timestamp": str(ts),
            "X-Signature": sign_request(secret, "POST", "/v1/chat/completions", signed, ts),
        }
        resp = client.post("/v1/chat/completions", content=tampered, headers=headers)
        assert resp.status_code == 401

    def test_rate_limit_returns_429(self):
        client, secret = self._make_signed_client(capacity=2)
        body = json.dumps(BENIGN_BODY).encode()
        assert self._signed_post(client, secret, body).status_code == 200
        assert self._signed_post(client, secret, body).status_code == 200
        assert self._signed_post(client, secret, body).status_code == 429


class TestTokenBucket:
    def test_allows_burst_then_blocks(self):
        bucket = TokenBucketRateLimiter(capacity=3, refill_per_second=0.01)
        assert all(bucket.allow("a") for _ in range(3))
        assert not bucket.allow("a")

    def test_buckets_are_per_agent(self):
        bucket = TokenBucketRateLimiter(capacity=1, refill_per_second=0.01)
        assert bucket.allow("a")
        assert bucket.allow("b")          # separate bucket
        assert not bucket.allow("a")

    def test_refills_over_time(self):
        bucket = TokenBucketRateLimiter(capacity=1, refill_per_second=1000)
        assert bucket.allow("a")
        time.sleep(0.01)
        assert bucket.allow("a")

    def test_verdict_type_exists_for_api_stability(self):
        v = Verdict(ok=True, agent_id="a", reason=None)
        assert v.ok and v.agent_id == "a"
