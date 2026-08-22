"""Request authentication for archon-armor.

Scheme: per-agent shared secret (generated server-side at registration,
stored on the AgentCard). Clients sign every request:

    signature = HMAC_SHA256(secret, "{method}:{path}:{timestamp}:{sha256(body)}")

Headers: X-Agent-ID, X-Timestamp (unix seconds), X-Signature (hex).

The timestamp window prevents replay; the body hash binds the signature to
the exact payload, preventing tampering. Verification uses constant-time
comparison throughout.
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


class IdentityVerifier(ABC):
    @abstractmethod
    def verify(
        self, headers: Mapping[str, str], body: bytes, method: str, path: str
    ) -> Verdict: ...


class HmacVerifier(IdentityVerifier):
    """Verifies HMAC-signed requests against registered agent secrets."""

    def __init__(self, registry: Registry, tolerance_seconds: int = 300):
        self._registry = registry
        self._tolerance = tolerance_seconds

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
