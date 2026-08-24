"""Macaroon-style attenuating delegation tokens for archon-armor.

Capability tokens that attenuate (only ever narrow) as they travel down a
delegation chain are the emerging IETF direction
(draft-niyikiza-oauth-attenuating-agent-tokens) and are legitimized for
agent ecosystems by DeepMind's analysis of agent delegation security
(arXiv:2602.11865). No incumbent security tool verifies attenuating
delegation chains, making this a white-space feature.

Design: an AttenuatingToken carries a capability plus an append-only tuple
of Caveats. Children minted via issue_child() inherit the parent caveat
tuple verbatim and may only append, so attenuation is monotone: a child can
never grant more than its parent.

Because child caveats must be a prefix-extended superset of the parent's,
verify_attenuation() checks subsumption structurally — no shared state, no
registry lookup — enabling fully OFFLINE verification at any depth of the
chain. check_authorization() is a pure function of (token, request, now):
deny_tool beats allow_tool; spend limits cap amounts; expires bounds time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Caveat kinds
ALLOW_TOOL = "allow_tool"
DENY_TOOL = "deny_tool"
MAX_SPEND = "max_spend"
EXPIRES = "expires"


@dataclass(frozen=True)
class Caveat:
    """A single restriction clause attached to a token."""

    kind: str
    value: str


@dataclass(frozen=True)
class AttenuatingToken:
    """A delegatable capability token with append-only caveats."""

    agent_id: str
    capability: str
    caveats: tuple[Caveat, ...] = field(default_factory=tuple)


def issue_child(
    parent: AttenuatingToken,
    extra_caveats: tuple[Caveat, ...],
    agent_id: str,
) -> AttenuatingToken:
    """Mint a child token: parent caveats preserved verbatim + extras appended."""
    return AttenuatingToken(
        agent_id=agent_id,
        capability=parent.capability,
        caveats=parent.caveats + tuple(extra_caveats),
    )


@dataclass(frozen=True)
class CaveatVerdict:
    """Result of structural attenuation verification between two tokens."""

    valid: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"valid": self.valid, "reasons": list(self.reasons)}


def verify_attenuation(parent: AttenuatingToken, child: AttenuatingToken) -> CaveatVerdict:
    """Verify child is a legitimate attenuation of parent (offline, structural).

    Valid iff:
      - child.caveats starts with parent.caveats (prefix/subsumption), and
      - both tokens carry the same capability lineage, and
      - child.agent_id != parent.agent_id (no self-issue).
    """
    reasons: list[str] = []
    if not child.caveats[: len(parent.caveats)] == parent.caveats:
        reasons.append("child caveats do not extend parent caveats")
    if child.capability != parent.capability:
        reasons.append("capability lineage mismatch")
    if child.agent_id == parent.agent_id:
        reasons.append("self-issue detected")
    return CaveatVerdict(valid=not reasons, reasons=reasons)


@dataclass(frozen=True)
class AuthorizationResult:
    """Result of pure-function authorization checking against caveats."""

    allowed: bool
    reasons: list[str] = field(default_factory=list)


def check_authorization(
    token: AttenuatingToken,
    *,
    tool: str,
    amount: float = 0.0,
    now: datetime | None = None,
) -> AuthorizationResult:
    """Check a tool invocation against all token caveats, reporting every violation."""
    reasons: list[str] = []

    allow_tools = [c.value for c in token.caveats if c.kind == ALLOW_TOOL]
    denied_tools = {c.value for c in token.caveats if c.kind == DENY_TOOL}

    if tool in denied_tools:
        reasons.append(f"tool '{tool}' denied by deny_tool caveat")
    if allow_tools and tool not in allow_tools:
        reasons.append(f"tool '{tool}' not in allow list")

    for c in token.caveats:
        if c.kind == MAX_SPEND:
            try:
                limit = float(c.value)
            except ValueError:
                reasons.append(f"malformed max_spend value: {c.value!r}")
                continue
            if amount > limit:
                reasons.append(f"amount {amount} exceeds max_spend {limit}")

        elif c.kind == EXPIRES:
            try:
                expiry = datetime.fromisoformat(c.value)
            except ValueError:
                reasons.append(f"malformed expires value: {c.value!r}")
                continue
            reference = now if now is not None else datetime.now(expiry.tzinfo)
            effective_now = (
                reference.replace(tzinfo=None)
                if reference.tzinfo is None and expiry.tzinfo is not None
                else reference
            )
            if effective_now > expiry:
                reasons.append(f"token expired at {expiry.isoformat()}")

    return AuthorizationResult(allowed=not reasons, reasons=reasons)
