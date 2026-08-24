"""Sprint E2.7 #40: macaroon-style attenuating delegation tokens."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest
from archon_core.security.caveats import (
    AttenuatingToken,
    AuthorizationResult,
    Caveat,
    check_authorization,
    issue_child,
    verify_attenuation,
)

NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)


def iso(dt: datetime) -> str:
    return dt.isoformat()


class TestImmutability:
    def test_caveat_frozen(self):
        c = Caveat(kind="allow_tool", value="search")
        with pytest.raises(FrozenInstanceError):
            c.kind = "deny_tool"  # type: ignore[misc]

    def test_token_frozen(self):
        t = AttenuatingToken(agent_id="a", capability="web", caveats=())
        with pytest.raises(FrozenInstanceError):
            t.agent_id = "b"  # type: ignore[misc]


class TestIssueChild:
    def test_child_preserves_parent_prefix(self):
        parent = AttenuatingToken(
            agent_id="root",
            capability="web",
            caveats=(Caveat("allow_tool", "search"),),
        )
        child = issue_child(parent, (Caveat("max_spend", "10.0"),), "leaf")
        assert child.capability == parent.capability
        assert child.agent_id == "leaf"
        assert child.caveats[:1] == parent.caveats
        assert child.caveats[1] == Caveat("max_spend", "10.0")


class TestVerifyAttenuation:
    def _parent(self) -> AttenuatingToken:
        return AttenuatingToken(
            agent_id="root",
            capability="web",
            caveats=(
                Caveat("allow_tool", "search"),
                Caveat("max_spend", "100.0"),
            ),
        )

    def test_proper_child_valid(self):
        parent = self._parent()
        child = issue_child(parent, (Caveat("max_spend", "5.0"),), "leaf")
        v = verify_attenuation(parent, child)
        assert v.valid and v.reasons == []
        d = v.to_dict()
        assert d["valid"] is True and d["reasons"] == []

    def test_reordered_caveats_rejected(self):
        parent = self._parent()
        child = AttenuatingToken(
            agent_id="leaf",
            capability="web",
            caveats=(parent.caveats[1], parent.caveats[0]),
        )
        v = verify_attenuation(parent, child)
        assert not v.valid and v.reasons

    def test_dropped_caveat_rejected(self):
        parent = self._parent()
        child = AttenuatingToken(
            agent_id="leaf", capability="web", caveats=(parent.caveats[0],)
        )
        assert not verify_attenuation(parent, child).valid

    def test_capability_mismatch_rejected(self):
        parent = self._parent()
        child = AttenuatingToken(
            agent_id="leaf",
            capability="email",
            caveats=tuple(parent.caveats),
        )
        v = verify_attenuation(parent, child)
        assert not v.valid

    def test_self_issue_rejected(self):
        parent = self._parent()
        child = AttenuatingToken(
            agent_id="root", capability="web", caveats=tuple(parent.caveats)
        )
        v = verify_attenuation(parent, child)
        assert not v.valid


class TestCheckAuthorization:
    def test_empty_allow_unrestricted(self):
        t = AttenuatingToken(agent_id="a", capability="x", caveats=())
        r = check_authorization(t, tool="anything")
        assert r.allowed and r.reasons == []

    def test_allow_match(self):
        t = AttenuatingToken(
            agent_id="a", capability="x", caveats=(Caveat("allow_tool", "search"),)
        )
        assert check_authorization(t, tool="search").allowed

    def test_allow_mismatch_denied(self):
        t = AttenuatingToken(
            agent_id="a", capability="x", caveats=(Caveat("allow_tool", "search"),)
        )
        assert not check_authorization(t, tool="send_email").allowed

    def test_deny_overrides_allow(self):
        t = AttenuatingToken(
            agent_id="a",
            capability="x",
            caveats=(
                Caveat("allow_tool", "search"),
                Caveat("deny_tool", "search"),
            ),
        )
        r = check_authorization(t, tool="search")
        assert not r.allowed and any("deny" in x for x in r.reasons)

    def test_max_spend_boundary_equal_passes(self):
        t = AttenuatingToken(
            agent_id="a", capability="x", caveats=(Caveat("max_spend", "10.0"),)
        )
        assert check_authorization(t, tool="t", amount=10.0).allowed

    def test_max_spend_exceeded_denied(self):
        t = AttenuatingToken(
            agent_id="a", capability="x", caveats=(Caveat("max_spend", "10.0"),)
        )
        assert not check_authorization(t, tool="t", amount=10.01).allowed

    def test_valid_expires_passes(self):
        t = AttenuatingToken(
            agent_id="a",
            capability="x",
            caveats=(Caveat("expires", iso(NOW + timedelta(hours=1))),),
        )
        assert check_authorization(t, tool="t", now=NOW).allowed

    def test_expired_denied(self):
        t = AttenuatingToken(
            agent_id="a",
            capability="x",
            caveats=(Caveat("expires", iso(NOW - timedelta(hours=1))),),
        )
        assert not check_authorization(t, tool="t", now=NOW).allowed

    def test_malformed_expires_denied(self):
        t = AttenuatingToken(
            agent_id="a", capability="x", caveats=(Caveat("expires", "not-a-date"),)
        )
        r = check_authorization(t, tool="t", now=NOW)
        assert not r.allowed and r.reasons

    def test_all_violations_reported(self):
        t = AttenuatingToken(
            agent_id="a",
            capability="x",
            caveats=(
                Caveat("allow_tool", "search"),
                Caveat("deny_tool", "search"),
                Caveat("max_spend", "1.0"),
                Caveat("expires", "bad"),
            ),
        )
        r = check_authorization(t, tool="search", amount=99.0, now=NOW)
        assert not r.allowed
        assert len(r.reasons) == 3  # deny + spend + malformed expiry; allow matched


class TestDeepChains:
    def test_grandchild_verifies_offline(self):
        root = AttenuatingToken(
            agent_id="root",
            capability="web",
            caveats=(Caveat("allow_tool", "search"),),
        )
        mid = issue_child(root, (Caveat("max_spend", "50.0"),), "mid")
        leaf = issue_child(mid, (Caveat("max_spend", "5.0"),), "leaf")

        assert verify_attenuation(root, mid).valid
        assert verify_attenuation(mid, leaf).valid
        assert verify_attenuation(root, leaf).valid

        r = check_authorization(leaf, tool="search", amount=4.0)
        assert isinstance(r, AuthorizationResult)
        assert r.allowed

        assert not check_authorization(leaf, tool="search", amount=6.0).allowed
