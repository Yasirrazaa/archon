"""Sprint 91: APC C3 context-binding + C4 one-shot approval tokens.

C3 (context binding): a one-shot approval is only valid for the task
instance and policy version it was minted under. ContextBinding carries
those two fields, and binding_fields(envelope) renders them as the
'task:{id}:policy:{ver}' fragment that callers splice into their
sign_request_ed25519-style canonical strings, so signatures are
cryptographically bound to execution context.

C4 (approval tokens): issue_approval mints an ApprovalToken whose
action_hash = sha256(canonical json(action + params)) plus a uuid4 nonce,
signed with ed25519 exactly like security/identity.py. verify_approval
checks signature, expiry and action-hash match -- replaying a token
against a *different* action fails -- and never raises: every malformed
input yields TokenVerdict(ok=False).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class ContextBinding:
    """C3: binds an action to a specific task instance + policy version."""

    task_instance_id: str
    policy_version: str


def binding_fields(envelope: dict) -> str:
    """Render an envelope's context fields for inclusion in a canonical string.

    Returns 'task:{task_instance_id}:policy:{policy_version}'.
    """
    return f"task:{envelope['task_instance_id']}:policy:{envelope['policy_version']}"


@dataclass(frozen=True)
class ApprovalToken:
    """C4: one-shot ed25519-signed approval to perform a single action."""

    agent_id: str
    action_hash: str  # sha256 hex of canonical json of {action + params}
    issued_at: str  # UTC ISO-8601
    expires_at: str  # UTC ISO-8601
    nonce: str  # uuid4 hex


@dataclass(frozen=True)
class TokenVerdict:
    ok: bool
    reason: str


def _canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _action_hash(action: dict) -> str:
    return hashlib.sha256(_canonical_json_bytes(action)).hexdigest()


def issue_approval(
    signing_key_pem: str,
    agent_id: str,
    action: dict,
    ttl_seconds: int = 300,
    now: datetime | None = None,
) -> tuple[dict, str]:
    """Mint an approval token signed over its own canonical json.

    Returns (token_dict, signature_hex). Mirrors identity.py's ed25519
    usage; reuses generate_keypair from there on the caller side.
    ``now`` is injectable so tests and callers can control the clock.
    """
    key = serialization.load_pem_private_key(signing_key_pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("private key is not ed25519")
    now = now if now is not None else datetime.now(timezone.utc)
    token = ApprovalToken(
        agent_id=agent_id,
        action_hash=_action_hash(action),
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
        nonce=uuid.uuid4().hex,
    )
    token_dict = asdict(token)
    signature = key.sign(_canonical_json_bytes(token_dict))
    return token_dict, signature.hex()


def verify_approval(
    signature_hex: str,
    token_dict,
    public_key_pem: str,
    *,
    action: dict,
    now: datetime | None = None,
) -> TokenVerdict:
    """Verify signature, expiry and action-hash match. Never raises."""
    try:
        return _verify_inner(signature_hex, token_dict, public_key_pem, action, now)
    except Exception:
        return TokenVerdict(ok=False, reason="malformed approval")


def _verify_inner(signature_hex, token_dict, public_key_pem, action, now) -> TokenVerdict:
    if not isinstance(token_dict, dict):
        return TokenVerdict(ok=False, reason="malformed approval")
    required = {"agent_id", "action_hash", "issued_at", "expires_at", "nonce"}
    if set(token_dict) != required or not all(
        isinstance(token_dict[k], str) for k in required
    ):
        return TokenVerdict(ok=False, reason="malformed approval")

    key = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        return TokenVerdict(ok=False, reason="bad signature")
    try:
        key.verify(bytes.fromhex(signature_hex), _canonical_json_bytes(token_dict))
    except (InvalidSignature, ValueError):
        return TokenVerdict(ok=False, reason="bad signature")

    check_time = now if now is not None else datetime.now(timezone.utc)
    if datetime.fromisoformat(token_dict["expires_at"]) <= check_time:
        return TokenVerdict(ok=False, reason="expired")

    if token_dict["action_hash"] != _action_hash(action):
        return TokenVerdict(ok=False, reason="action mismatch")

    return TokenVerdict(ok=True, reason="ok")
