"""Sprint 88: battle summaries decompose findings by joint property."""

from archon_armor.battles import Battle, ProbeVerdict


def make_battle(*verdicts) -> Battle:
    battle = Battle(battle_id="b1", agent_id="a1", status="running")
    battle.results = list(verdicts)
    return battle


def test_properties_present_with_correct_counts():
    battle = make_battle(
        ProbeVerdict(probe_name="p1", blocked=False, category="indirect_injection"),
        ProbeVerdict(probe_name="p2", blocked=False, category="indirect_injection"),
        ProbeVerdict(probe_name="p3", blocked=False, category="jailbreak"),
    )
    battle.finalize()
    props = battle.summary["properties"]
    assert props["by_property"]["SA"] == 2
    assert props["by_property"]["TA"] == 1
    assert props["tagged"] == 3


def test_properties_absent_when_all_blocked():
    battle = make_battle(
        ProbeVerdict(probe_name="p1", blocked=True, category="indirect_injection",
                     block_reason="policy"),
        ProbeVerdict(probe_name="p2", blocked=True, category="jailbreak_persona",
                     block_reason="policy"),
    )
    battle.finalize()
    assert "properties" not in battle.summary


def test_properties_absent_for_empty_results():
    battle = make_battle()
    battle.finalize()
    assert "properties" not in battle.summary


def test_backward_compat_summary_keys_intact():
    battle = make_battle(ProbeVerdict(probe_name="p1", blocked=False,
                                      category="indirect_injection"))
    battle.finalize()
    for key in ("total_probes", "blocked", "block_rate", "control_passed",
                "coverage", "severity"):
        assert key in battle.summary


def test_benign_control_excluded_from_properties():
    battle = make_battle(
        ProbeVerdict(probe_name="benign_control", blocked=False, category="benign"),
        ProbeVerdict(probe_name="p1", blocked=False, category="data_exfiltration"),
    )
    battle.finalize()
    props = battle.summary["properties"]
    assert props["tagged"] == 1
    assert props["by_property"]["DI"] == 1


def test_unknown_category_counted_untagged():
    battle = make_battle(
        ProbeVerdict(probe_name="p1", blocked=False, category="mystery_category"),
    )
    battle.finalize()
    props = battle.summary["properties"]
    assert props["untagged"] == 1
    assert props["tagged"] == 0
    assert "SA" not in props["by_property"]


def test_all_four_properties_covered():
    battle = make_battle(
        ProbeVerdict(probe_name="p1", blocked=False, category="indirect_injection"),
        ProbeVerdict(probe_name="p2", blocked=False, category="jailbreak"),
        ProbeVerdict(probe_name="p3", blocked=False, category="sandbox_escape"),
        ProbeVerdict(probe_name="p4", blocked=False, category="data_exfiltration"),
    )
    battle.finalize()
    props = battle.summary["properties"]
    assert set(props["by_property"]) == {"SA", "TA", "AA", "DI"}
    assert all(n == 1 for n in props["by_property"].values())


def test_by_property_sorted_by_count_descending():
    battle = make_battle(
        ProbeVerdict(probe_name="p1", blocked=False, category="jailbreak"),
        ProbeVerdict(probe_name="p2", blocked=False, category="indirect_injection"),
        ProbeVerdict(probe_name="p3", blocked=False, category="indirect_injection"),
    )
    battle.finalize()
    keys = list(battle.summary["properties"]["by_property"])
    assert keys[0] == "SA"
