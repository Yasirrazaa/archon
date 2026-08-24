"""Sprint W7-B: ed25519-signed agent credentials (Identity v2).

Upgrades archon-armor's per-agent trust model from symmetric shared
secrets (authn.py HMAC scheme) to asymmetric ed25519 identities:

    signature = Ed25519_sign(privkey, "{METHOD}:{path}:{timestamp}:{sha256(body)}")

The canonical string is byte-for-byte identical to the HMAC boundary
documented in SECURITY.md §2, so request-signing tooling only swaps the
signature primitive and header name (X-Signature -> X-Signature-Ed25519,
base64 instead of hex).

CredentialStore is the sqlite-backed registration authority: issue() mints
an AgentCredential plus the private key PEM (returned exactly once, never
stored server-side), revoke() kills the credential immediately, and
public_key_for() feeds verification. Ed25519Verifier mirrors HmacVerifier's
Verdict interface, so create_app(identity=Ed25519Verifier(store)) is a
drop-in replacement.

Rejection reasons: 'unknown agent', 'expired', 'revoked', 'bad signature'.
Malformed input always yields ok=False -- verify never raises.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_TOLERANCE_SECONDS = 300


def generate_keypair() -> tuple[str, str]:
    """Generate an ed25519 keypair serialized as PEM strings.

    Returns (private_key_pem, public_key_pem). The private key uses PKCS8
    with no encryption; the public key uses SubjectPublicKeyInfo.
    """
    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def _canonical(method: str, path: str, ts: int, body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}:{path}:{ts}:{digest}".encode()


def sign_request_ed25519(
    private_key_pem: str, method: str, path: str, body: bytes, timestamp: int | None = None
) -> str:
    """Client-side helper producing the X-Signature-Ed25519 value (base64).

    Signs the same canonical string as the HMAC scheme:
    "{METHOD}:{path}:{timestamp}:{sha256(body)}".
    """
    ts = timestamp if timestamp is not None else int(time.time())
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key is not ed25519")
    return base64.b64encode(key.sign(_canonical(method, path, ts, body))).decode()


@dataclass
class AgentCredential:
    agent_id: str
    public_key_pem: str
    issued_at: str  # UTC ISO-8601
    expires_at: str | None = None  # UTC ISO-8601, None == non-expiring


_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    agent_id TEXT PRIMARY KEY,
    public_key_pem TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
)
"""


class CredentialStore:
    """sqlite-backed registration authority for ed25519 agent identities."""

    def __init__(self, path: str | None = None):
        # path=None keeps everything in-memory (tests / ephemeral mode).
        # check_same_thread=False: ASGI servers (and TestClient) may call
        # verify() from a different thread than the one that built the app.
        self._conn = sqlite3.connect(path or ":memory:", check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def _upsert(self, agent_id: str, pub_pem: str, issued_at: str, expires_at: str | None):
        self._conn.execute(
            "INSERT INTO credentials (agent_id, public_key_pem, issued_at, expires_at)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(agent_id) DO UPDATE SET public_key_pem=excluded.public_key_pem,"
            " issued_at=excluded.issued_at, expires_at=excluded.expires_at, revoked=0",
            (agent_id, pub_pem, issued_at, expires_at),
        )
        self._conn.commit()

    def issue(self, agent_id: str, ttl_days: int = 365) -> tuple[AgentCredential, str]:
        """Mint a new keypair and register the agent. The private key PEM is
        returned to the caller exactly once; it is never stored here."""
        priv_pem, pub_pem = generate_keypair()
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=ttl_days)).isoformat() if ttl_days is not None \
            else None
        self._upsert(agent_id, pub_pem, now.isoformat(), expires_at)
        cred = AgentCredential(
            agent_id=agent_id, public_key_pem=pub_pem,
            issued_at=now.isoformat(), expires_at=expires_at,
        )
        return cred, priv_pem

    def public_key_for(self, agent_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT public_key_pem FROM credentials"
            " WHERE agent_id = ? AND revoked = 0",
            (agent_id,),
        ).fetchone()
        return row[0] if row else None

    def revoke(self, agent_id: str) -> None:
        self._conn.execute(
            "UPDATE credentials SET revoked = 1 WHERE agent_id = ?", (agent_id,)
        )
        self._conn.commit()

    def list_credentials(self) -> list[AgentCredential]:
        rows = self._conn.execute(
            "SELECT agent_id, public_key_pem, issued_at, expires_at"
            " FROM credentials ORDER BY agent_id"
        ).fetchall()
        return [AgentCredential(*row) for row in rows]


class Ed25519Verifier:
    """Drop-in IdentityVerifier mirroring HmacVerifier's verdict interface.

    Headers: X-Agent-ID, X-Timestamp (unix seconds), X-Signature-Ed25519
    (base64). Timestamp window matches HmacVerifier's default +/-300s.
    """

    def __init__(self, credential_store: CredentialStore, tolerance_seconds: int = 300):
        self._store = credential_store
        self._tolerance = tolerance_seconds

    def verify(self, headers, body: bytes, method: str, path: str):
        from archon_core.security.authn import Verdict

        try:
            return self._verify_inner(headers, body, method, path)
        except Exception:
            return Verdict(ok=False, reason="bad signature")

    def _verify_inner(self, headers, body, method, path):
        from archon_core.security.authn import Verdict

        agent_id = headers.get("X-Agent-ID")
        ts_raw = headers.get("X-Timestamp")
        signature = headers.get("X-Signature-Ed25519")
        if not agent_id or not ts_raw or not signature:
            return Verdict(ok=False, reason="missing identity headers")

        if self._store_is_revoked(agent_id):
            return Verdict(ok=False, agent_id=agent_id, reason="revoked")
        if self._store_is_expired(agent_id):
            return Verdict(ok=False, agent_id=agent_id, reason="expired")
        pem = self._store.public_key_for(agent_id)
        if pem is None:
            return Verdict(ok=False, reason=f"unknown agent identity: {agent_id}")

        try:
            ts = int(ts_raw)
        except ValueError:
            return Verdict(ok=False, agent_id=agent_id, reason="invalid timestamp")
        skew = abs(int(time.time()) - ts)
        if skew > self._tolerance:
            return Verdict(
                ok=False,
                agent_id=agent_id,
                reason=f"replay/expired timestamp (skew={skew}s)",
            )

        key = serialization.load_pem_public_key(pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            return Verdict(ok=False, agent_id=agent_id, reason="bad signature")
        try:
            key.verify(base64.b64decode(signature), _canonical(method, path, ts, body))
        except Exception:
            return Verdict(ok=False, agent_id=agent_id, reason="bad signature")
        return Verdict(ok=True, agent_id=agent_id)

    def _store_is_revoked(self, agent_id: str) -> bool:
        row = self._store._conn.execute(
            "SELECT revoked FROM credentials WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        return bool(row and row[0])

    def _store_is_expired(self, agent_id: str) -> bool:
        row = self._store._conn.execute(
            "SELECT expires_at FROM credentials WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        if not row or not row[0]:
            return False
        expiry = datetime.fromisoformat(row[0])
        return datetime.now(timezone.utc) >= expiry
