"""Sprint E3-70 C2b: APC composition-closure caveats.

Source: arXiv:2608.15888 (Bounded Agents / APC). Composition closure means an
action must create no prohibited combination with prior session actions.
Removing ONE pairwise prohibition took InjecAgent data-stealing ASR 0% -> 39.9%
in the source paper, so coverage here matters.
"""

import random

from archon_core.security.caveats import (
    PROHIBIT_PAIR,
    PROHIBIT_TUPLE,
    AttenuatingToken,
    Caveat,
    SessionActionRegistry,
    _is_subsequence,
    check_authorization,
    issue_child,
    verify_attenuation,
    verify_composition,
)


def pair(a: str, b: str) -> Caveat:
    return Caveat(kind=PROHIBIT_PAIR, value=[a, b])


def tup(*actions: str) -> Caveat:
    return Caveat(kind=PROHIBIT_TUPLE, value=list(actions))


class TestProhibitPair:
    def test_no_violation_after_single_action(self):
        tok = AttenuatingToken(
            agent_id="a", capability="web", caveats=(pair("read_inbox", "send_secrets"),)
        )
        reg = SessionActionRegistry()
        reg.record("read_inbox")
        assert check_authorization(tok, tool="anything", registry=reg).allowed

    def test_violation_after_both_actions(self):
        tok = AttenuatingToken(
            agent_id="a", capability="web", caveats=(pair("read_inbox", "send_secrets"),)
        )
        reg = SessionActionRegistry()
        reg.record("read_inbox")
        reg.record("send_secrets")
        r = check_authorization(tok, tool="anything", registry=reg)
        assert not r.allowed
        assert any("prohibited combination" in x for x in r.reasons)

    def test_pair_order_of_recording_irrelevant(self):
        tok = AttenuatingToken(
            agent_id="a", capability="web", caveats=(pair("read_inbox", "send_secrets"),)
        )
        reg = SessionActionRegistry()
        reg.record("send_secrets")
        reg.record("read_inbox")
        assert not check_authorization(tok, tool="x", registry=reg).allowed

    def test_any_of_multiple_pairs_matching_denies(self):
        tok = AttenuatingToken(
            agent_id="a",
            capability="web",
            caveats=(
                pair("export", "upload"),
                pair("read", "exfiltrate"),
            ),
        )
        reg = SessionActionRegistry()
        reg.record("read")
        assert check_authorization(tok, tool="x", registry=reg).allowed
        reg.record("exfiltrate")
        r = check_authorization(tok, tool="x", registry=reg)
        assert not r.allowed
        assert len(r.reasons) == 1


class TestTupleSubsequence:
    def test_helper_contiguous_and_scattered(self):
        assert _is_subsequence(["a"], ["a"])
        assert _is_subsequence(["a", "b"], ["a", "b"])
        assert _is_subsequence(["a", "b"], ["a", "x", "y", "b"])
        assert not _is_subsequence(["a", "b"], ["b", "a"])

    def test_scattered_subsequence_detected(self):
        tok = AttenuatingToken(agent_id="a", capability="web", caveats=(tup("a", "c", "b"),))
        reg = SessionActionRegistry()
        for action in ["a", "x", "c", "b"]:
            reg.record(action)
        r = verify_composition(tok, reg)
        assert not r.allowed
        assert any("prohibited sequence" in x for x in r.reasons)

    def test_wrong_order_does_not_match(self):
        tok = AttenuatingToken(agent_id="a", capability="web", caveats=(tup("b", "a"),))
        reg = SessionActionRegistry()
        for action in ["a", "b"]:
            reg.record(action)
        assert verify_composition(tok, reg).allowed

    def test_partial_prefix_no_violation(self):
        tok = AttenuatingToken(agent_id="a", capability="web", caveats=(tup("a", "b", "c"),))
        reg = SessionActionRegistry()
        reg.record("a")
        reg.record("b")
        assert verify_composition(tok, reg).allowed


class TestSessionActionRegistry:
    def test_history_is_ordered_and_exercised_deduplicates(self):
        reg = SessionActionRegistry()
        reg.record("a")
        reg.record("b")
        reg.record("a")
        assert reg.history == ["a", "b", "a"]
        assert reg.exercised == {"a", "b"}

    def test_new_session_is_the_only_reset(self):
        reg = SessionActionRegistry()
        reg.record("a")
        reg.new_session()
        assert reg.history == [] and reg.exercised == set()

    def test_history_snapshot_is_defensive_copy(self):
        reg = SessionActionRegistry()
        reg.record("a")
        snapshot = reg.history
        snapshot.append("ghost")
        assert reg.history == ["a"]


class TestCheckAuthorizationIntegration:
    def test_existing_kinds_untouched_without_registry(self):
        tok = AttenuatingToken(
            agent_id="a",
            capability="x",
            caveats=(
                Caveat("allow_tool", "search"),
                Caveat("deny_tool", "search"),
            ),
        )
        r = check_authorization(tok, tool="search")
        assert not r.allowed and len(r.reasons) == 1

    def test_check_authorization_with_registry_reports_all_reasons(self):
        tok = AttenuatingToken(
            agent_id="a",
            capability="x",
            caveats=(
                Caveat("deny_tool", "search"),
                pair("p", "q"),
            ),
        )
        reg = SessionActionRegistry()
        reg.record("p")
        reg.record("q")
        r = check_authorization(tok, tool="search", registry=reg)
        assert not r.allowed and len(r.reasons) == 2

    def test_malformed_tuple_value_reported(self):
        tok = AttenuatingToken(
            agent_id="a",
            capability="x",
            caveats=(Caveat(kind=PROHIBIT_TUPLE, value=["solo"]),),
        )
        r = verify_composition(tok, SessionActionRegistry())
        assert not r.allowed and r.reasons


class TestMeetAccumulation:
    def test_child_cannot_drop_parent_prohibition(self):
        root = AttenuatingToken(
            agent_id="root", capability="web", caveats=(pair("read", "exfiltrate"),)
        )
        smuggled = AttenuatingToken(
            agent_id="leaf", capability="web", caveats=(Caveat("allow_tool", "read"),)
        )
        v = verify_attenuation(root, smuggled)
        assert not v.valid
        assert any("extend parent caveats" in x for x in v.reasons)

    def test_meet_union_enforces_parent_pair_downstream(self):
        root = AttenuatingToken(
            agent_id="root", capability="web", caveats=(pair("read", "exfiltrate"),)
        )
        child = issue_child(root, (Caveat("deny_tool", "upload"),), "leaf")
        reg = SessionActionRegistry()
        reg.record("read")
        reg.record("exfiltrate")
        assert not check_authorization(child, tool="read", registry=reg).allowed


class TestBlastRadiusMonotonicity:
    ACTIONS = ["read", "write", "send", "delete", "export", "login", "pay"]

    @staticmethod
    def _random_caveats(rng: random.Random) -> tuple[Caveat, ...]:
        caveats: list[Caveat] = []
        for _ in range(rng.randint(0, 3)):
            kind = rng.choice(["allow_tool", "deny_tool", "max_spend", PROHIBIT_PAIR])
            if kind == "allow_tool":
                caveats.append(Caveat(kind, rng.choice(TestBlastRadiusMonotonicity.ACTIONS)))
            elif kind == "deny_tool":
                caveats.append(Caveat(kind, rng.choice(TestBlastRadiusMonotonicity.ACTIONS)))
            elif kind == "max_spend":
                caveats.append(Caveat(kind, str(round(rng.uniform(0.5, 50.0), 2))))
            else:
                acts = rng.sample(TestBlastRadiusMonotonicity.ACTIONS, 2)
                caveats.append(Caveat(kind, acts))
        return tuple(caveats)

    def test_child_allowed_set_subset_of_parent_over_20_chains(self):
        rng = random.Random(42)
        checked = 0
        for chain_i in range(20):
            token = AttenuatingToken(
                agent_id=f"agent-root-{chain_i}",
                capability="web",
                caveats=self._random_caveats(rng),
            )
            chain = [token]
            for depth in range(rng.randint(1, 4)):
                chain.append(
                    issue_child(chain[-1], self._random_caveats(rng), f"agent-{chain_i}-{depth}")
                )
            for parent, child in zip(chain, chain[1:]):
                parent_allowed = {
                    t
                    for t in self.ACTIONS
                    if check_authorization(parent, tool=t, amount=1.0).allowed
                }
                child_allowed = {
                    t
                    for t in self.ACTIONS
                    if check_authorization(child, tool=t, amount=1.0).allowed
                }
                assert child_allowed <= parent_allowed, (
                    f"chain {chain_i}: child grants beyond parent "
                    f"{child_allowed - parent_allowed}"
                )
                checked += 1
        assert checked >= 20
