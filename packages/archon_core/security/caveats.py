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
Multiple allow_tool clauses intersect (each appended clause narrows further),
so allowed-action-set(child) is always a subset of the parent's (Thm 4.6).

Composition closure (C2b, arXiv:2608.15888 — Bounded Agents / APC): an action
must create no prohibited combination with prior session actions. Tokens may
carry prohibit_pair / prohibit_tuple caveats checked against a
SessionActionRegistry of infrastructure-held prior actions; removing ONE
pairwise prohibition raised InjecAgent data-stealing ASR 0% -> 39.9% in the
source paper, so restrictions only ever accumulate down the chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Caveat kinds
ALLOW_TOOL = "allow_tool"
DENY_TOOL = "deny_tool"
MAX_SPEND = "max_spend"
EXPIRES = "expires"
PROHIBIT_PAIR = "prohibit_pair"
PROHIBIT_TUPLE = "prohibit_tuple"


@dataclass(frozen=True)
class Caveat:
    """A single restriction clause attached to a token.

    For PROHIBIT_PAIR / PROHIBIT_TUPLE the value is an ordered list of
    action-type strings (pair: exactly 2; tuple: >= 2).
    """

    kind: str
    value: str | list[str]


class SessionActionRegistry:
    """Infrastructure-held record of prior session actions (APC C2b).

    The registry is append-only via record(); the only way to reset it is an
    explicit new_session(). Not thread-safe by design: each agent session is
    expected to be owned by a single execution context.
    """

    def __init__(self) -> None:
        self._history: list[str] = []

    def record(self, action_type: str) -> None:
        """Append an executed action to the ordered session history."""
        self._history.append(action_type)

    @property
    def history(self) -> list[str]:
        """Ordered list of recorded actions (defensive copy)."""
        return list(self._history)

    @property
    def exercised(self) -> frozenset[str]:
        """Set of distinct action types recorded this session."""
        return frozenset(self._history)

    def new_session(self) -> None:
        """Explicitly start a new session, clearing all prior actions."""
        self._history.clear()


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
    registry: SessionActionRegistry | None = None,
) -> AuthorizationResult:
    """Check a tool invocation against all token caveats, reporting every violation.

    When a SessionActionRegistry is supplied, composition-closure caveats
    (prohibit_pair / prohibit_tuple) are also enforced against prior session
    actions.
    """
    reasons: list[str] = []

    # Each allow_tool clause independently narrows the permitted set (they
    # intersect, never union): appending clauses down the chain therefore
    # preserves Blast Radius Monotonicity (Thm 4.6, arXiv:2608.15888).
    allow_clauses = [c.value for c in token.caveats if c.kind == ALLOW_TOOL]
    denied_tools = {c.value for c in token.caveats if c.kind == DENY_TOOL}

    if tool in denied_tools:
        reasons.append(f"tool '{tool}' denied by deny_tool caveat")
    for allowed in allow_clauses:
        if tool != allowed:
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

    if registry is not None:
        reasons.extend(verify_composition(token, registry).reasons)

    return AuthorizationResult(allowed=not reasons, reasons=reasons)


def _is_subsequence(needle: list[str], haystack: list[str]) -> bool:
    """True iff needle appears in haystack as an ordered subsequence.

    Contiguous or scattered: [a, c, b] matches [a, x, c, b]; ordering is
    strict, so [b, a] does not match [a, b].
    """
    pos = 0
    for item in haystack:
        if pos < len(needle) and item == needle[pos]:
            pos += 1
    return pos == len(needle)


def _prohibited_actions(value: str | list[str]) -> list[str] | None:
    """Validate a prohibit caveat value; None if malformed."""
    if (
        isinstance(value, list)
        and len(value) >= 2
        and all(isinstance(a, str) for a in value)
    ):
        return list(value)
    return None


def verify_composition(
    token: AttenuatingToken, registry: SessionActionRegistry
) -> AuthorizationResult:
    """Enforce composition closure (APC C2b) against prior session actions.

    For every prohibit_pair caveat: deny if BOTH actions were exercised this
    session. For every prohibit_tuple: deny if its ordered sequence appears as
    an ordered (contiguous or scattered) subsequence of the session history.
    """
    reasons: list[str] = []
    for c in token.caveats:
        if c.kind == PROHIBIT_PAIR:
            actions = _prohibited_actions(c.value)
            if actions is None or len(actions) != 2:
                reasons.append(f"malformed {PROHIBIT_PAIR} value: {c.value!r}")
                continue
            first, second = actions
            if first in registry.exercised and second in registry.exercised:
                reasons.append(
                    f"prohibited combination performed: '{first}' + '{second}'"
                )
        elif c.kind == PROHIBIT_TUPLE:
            actions = _prohibited_actions(c.value)
            if actions is None:
                reasons.append(f"malformed {PROHIBIT_TUPLE} value: {c.value!r}")
                continue
            if _is_subsequence(actions, registry.history):
                reasons.append(
                    f"prohibited sequence performed: {'->'.join(actions)}"
                )
    return AuthorizationResult(allowed=not reasons, reasons=reasons)
