"""Request authentication for archon-armor.

Scheme: per-agent shared secret (generated server-side at registration,
stored on the AgentCard). Clients sign every request:

    signature = HMAC_SHA256(secret, "{method}:{path}:{timestamp}:{sha256(body)}")

Headers: X-Agent-ID, X-Timestamp (unix seconds), X-Signature (hex).

The timestamp window bounds replay exposure; the body hash binds the
signature to the exact payload, preventing tampering. Verification uses
constant-time comparison throughout.

Sprint IMP-7: an optional NonceStore closes the remaining within-window
replay gap. When HmacVerifier is constructed with nonce_store=NonceStore(),
requests must additionally carry an X-Nonce header and any reuse is rejected
("replay detected"). Verifiers built without a store keep the legacy
window-only semantics.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Mapping

from archon_core.registry.base import AgentNotFoundError, Registry


def generate_agent_secret() -> str:
    """Generate a per-agent signing secret."""
    return secrets.token_urlsafe(32)


def _body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign_request(
    secret: str, method: str, path: str, body: bytes, timestamp: int | None = None
) -> str:
    """Client-side helper producing the X-Signature value."""
    ts = timestamp if timestamp is not None else int(time.time())
    message = f"{method.upper()}:{path}:{ts}:{_body_digest(body)}"
    return hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()


@dataclass
class Verdict:
    ok: bool
    agent_id: str | None = None
    reason: str | None = None


class NonceStore:
    """In-memory single-use nonce cache closing the HMAC replay window.

    register() returns True exactly once per nonce within ttl_seconds
    (monotonic clock). Expired entries are pruned opportunistically on each
    insert; when max_entries is exceeded the oldest entries are evicted, so
    memory stays bounded under unbounded adversarial traffic.

    Per-process only: it resets on restart and is not shared across replicas
    (see SECURITY.md §2/§4).
    """

    def __init__(self, ttl_seconds: int = 600, max_entries: int = 100000):
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._nonces: dict[str, float] = {}  # insertion order == age order

    def register(self, nonce: str) -> bool:
        now = time.monotonic()
        self._prune_expired(now)
        if nonce in self._nonces:
            return False
        self._nonces[nonce] = now
        while len(self._nonces) > self._max_entries:
            oldest = next(iter(self._nonces))
            del self._nonces[oldest]
        return True

    def _prune_expired(self, now: float) -> None:
        cutoff = now - self._ttl
        expired = [nonce for nonce, ts in self._nonces.items() if ts < cutoff]
        for nonce in expired:
            del self._nonces[nonce]


class IdentityVerifier(ABC):
    @abstractmethod
    def verify(
        self, headers: Mapping[str, str], body: bytes, method: str, path: str
    ) -> Verdict: ...


class HmacVerifier(IdentityVerifier):
    """Verifies HMAC-signed requests against registered agent secrets.

    With nonce_store=None (default) only the timestamp window guards against
    replay. Passing nonce_store=NonceStore() additionally requires an
    X-Nonce header and rejects reuse of a previously seen nonce.
    """

    def __init__(
        self,
        registry: Registry,
        tolerance_seconds: int = 300,
        nonce_store: NonceStore | None = None,
    ):
        self._registry = registry
        self._tolerance = tolerance_seconds
        self._nonces = nonce_store

    def verify(
        self, headers: Mapping[str, str], body: bytes, method: str, path: str
    ) -> Verdict:
        agent_id = headers.get("X-Agent-ID")
        ts_raw = headers.get("X-Timestamp")
        signature = headers.get("X-Signature")
        if not agent_id or not ts_raw or not signature:
            return Verdict(ok=False, reason="missing identity headers")

        try:
            card = self._registry.get(agent_id)
        except AgentNotFoundError:
            return Verdict(ok=False, reason=f"unknown agent identity: {agent_id}")
        if not card.api_secret:
            return Verdict(ok=False, reason="agent has no signing secret registered")

        try:
            ts = int(ts_raw)
        except ValueError:
            return Verdict(ok=False, reason="invalid timestamp")
        skew = abs(int(time.time()) - ts)
        if skew > self._tolerance:
            return Verdict(
                ok=False,
                agent_id=agent_id,
                reason=f"replay/expired timestamp (skew={skew}s)",
            )

        expected = sign_request(card.api_secret, method, path, body, ts)
        if not hmac.compare_digest(expected, signature):
            return Verdict(ok=False, agent_id=agent_id, reason="invalid signature")

        if self._nonces is not None:
            # Nonce is consumed only after the signature proves authenticity,
            # so attackers cannot burn a legitimate agent's nonce with forged
            # requests (signature checked first, nonce last).
            nonce = headers.get("X-Nonce")
            if not nonce:
                return Verdict(
                    ok=False,
                    agent_id=agent_id,
                    reason="nonce required: missing X-Nonce header",
                )
            if not self._nonces.register(nonce):
                return Verdict(ok=False, agent_id=agent_id, reason="replay detected")
        return Verdict(ok=True, agent_id=agent_id)


class AllowAllVerifier(IdentityVerifier):
    """Legacy/dev mode: trust the plain X-Agent-ID header. Never use in prod."""

    def verify(
        self, headers: Mapping[str, str], body: bytes, method: str, path: str
    ) -> Verdict:
        agent_id = headers.get("X-Agent-ID")
        if not agent_id:
            return Verdict(ok=False, reason="missing X-Agent-ID header")
        return Verdict(ok=True, agent_id=agent_id)
