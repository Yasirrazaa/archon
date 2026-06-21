"""Tests for Surface/Family Strategy Router - attacker intelligence module.

Based on NeuralShield's attacker: routes attacks across surfaces and families
with diversity rules to avoid repetition.
"""
import pytest
from scenarios.security_arena.agents.attacker.strategy_router import (
    AttackSurface,
    StrategyFamily,
    StrategyRouter,
)
from scenarios.security_arena.agents.attacker.diagnosis import (
    DiagnosisResult,
    ResponseCategory,
    FailureMode,
)


@pytest.fixture
def router():
    return StrategyRouter()


@pytest.fixture
def diagnosis_hard_refusal():
    return DiagnosisResult(
        category=ResponseCategory.HARD_REFUSAL,
        failure_mode=FailureMode.EXPLICIT_REJECTION,
        tone_score=0,
        evidence=["hard_refusal_detected"],
        suggested_pivot="switch_to_indirect_surface",
    )


@pytest.fixture
def diagnosis_soft_refusal():
    return DiagnosisResult(
        category=ResponseCategory.SOFT_REFUSAL,
        failure_mode=FailureMode.GENERATION_REFUSAL,
        tone_score=1,
        evidence=["soft_refusal_detected"],
        suggested_pivot="continue_with_different_framing",
    )


@pytest.fixture
def diagnosis_compliance():
    return DiagnosisResult(
        category=ResponseCategory.PARTIAL_COMPLIANCE,
        failure_mode=FailureMode.TASK_MISALIGNMENT,
        tone_score=3,
        evidence=["compliance_detected"],
        suggested_pivot="align_with_defender_task",
    )


class TestAttackSurface:
    def test_all_surfaces(self):
        surfaces = [
            AttackSurface.EXTRACTION,
            AttackSurface.TRANSLATION,
            AttackSurface.TRANSFORMATION,
            AttackSurface.CLASSIFICATION,
            AttackSurface.SUMMARIZATION,
        ]
        assert len(surfaces) == 5

    def test_surface_values(self):
        assert AttackSurface.EXTRACTION.value == "extraction"
        assert AttackSurface.TRANSLATION.value == "translation"
        assert AttackSurface.TRANSFORMATION.value == "transformation"
        assert AttackSurface.CLASSIFICATION.value == "classification"
        assert AttackSurface.SUMMARIZATION.value == "summarization"


class TestStrategyFamily:
    def test_all_families(self):
        families = [
            StrategyFamily.PROMPT_INJECTION,
            StrategyFamily.JAILBREAK,
            StrategyFamily.DATA_EXFILTRATION,
            StrategyFamily.POLICY_AVOIDANCE,
        ]
        assert len(families) == 4

    def test_family_values(self):
        assert StrategyFamily.PROMPT_INJECTION.value == "prompt_injection"
        assert StrategyFamily.JAILBREAK.value == "jailbreak"
        assert StrategyFamily.DATA_EXFILTRATION.value == "data_exfiltration"
        assert StrategyFamily.POLICY_AVOIDANCE.value == "policy_avoidance"


class TestDefaultSelection:
    def test_first_round_returns_default(self, router):
        round_data = {"round": 1, "history": []}
        result = router.select(round_data, None)
        assert "surface" in result
        assert "family" in result
        assert isinstance(result["surface"], AttackSurface)
        assert isinstance(result["family"], StrategyFamily)

    def test_default_surface_is_extraction(self, router):
        round_data = {"round": 1, "history": []}
        result = router.select(round_data, None)
        assert result["surface"] == AttackSurface.EXTRACTION

    def test_default_family_is_injection(self, router):
        round_data = {"round": 1, "history": []}
        result = router.select(round_data, None)
        assert result["family"] == StrategyFamily.PROMPT_INJECTION


class TestSurfaceBanning:
    def test_hard_refusal_bans_surface(self, router, diagnosis_hard_refusal):
        round_data = {"round": 1, "history": []}
        first = router.select(round_data, None)
        banned_surface = first["surface"]

        round_data2 = {"round": 2, "history": [{"surface": banned_surface, "result": "hard_refusal"}]}
        second = router.select(round_data2, diagnosis_hard_refusal)
        assert second["surface"] != banned_surface

    def test_surface_failure_count_increments(self, router, diagnosis_hard_refusal):
        round_data = {"round": 1, "history": []}
        result = router.select(round_data, None)
        surface = result["surface"]

        router.record_failure(surface, diagnosis_hard_refusal)
        assert router.surface_failure_counts[surface] == 1

        router.record_failure(surface, diagnosis_hard_refusal)
        assert router.surface_failure_counts[surface] == 2


class TestFamilyBlacklisting:
    def test_multiple_failures_blacklists_family(self, router, diagnosis_hard_refusal):
        round_data = {"round": 1, "history": []}
        result = router.select(round_data, None)
        family = result["family"]

        for _ in range(3):
            router.record_family_failure(family, diagnosis_hard_refusal)

        assert family in router.family_blacklist

    def test_blacklisted_family_not_selected(self, router, diagnosis_hard_refusal):
        round_data = {"round": 1, "history": []}
        result = router.select(round_data, None)
        family = result["family"]

        for _ in range(3):
            router.record_family_failure(family, diagnosis_hard_refusal)

        round_data2 = {"round": 2, "history": []}
        second = router.select(round_data2, None)
        assert second["family"] != family


class TestDiversityRule:
    def test_same_surface_not_repeated_twice(self, router):
        round_data = {"round": 1, "history": []}
        first = router.select(round_data, None)

        round_data2 = {"round": 2, "history": [{"surface": first["surface"]}]}
        second = router.select(round_data2, None)
        assert second["surface"] != first["surface"]

    def test_rotation_across_rounds(self, router):
        surfaces_seen = []
        for i in range(5):
            round_data = {"round": i + 1, "history": [{"surface": s} for s in surfaces_seen]}
            result = router.select(round_data, None)
            surfaces_seen.append(result["surface"])

        assert len(set(surfaces_seen)) >= 3


class TestPivotSuggestion:
    def test_suggestion_used_when_available(self, router, diagnosis_hard_refusal):
        round_data = {"round": 2, "history": [{"surface": AttackSurface.EXTRACTION}]}
        result = router.select(round_data, diagnosis_hard_refusal)
        assert "suggested_surface" in result

    def test_pivot_changes_surface(self, router, diagnosis_hard_refusal):
        round_data = {"round": 2, "history": [{"surface": AttackSurface.EXTRACTION}]}
        result = router.select(round_data, diagnosis_hard_refusal)
        assert result["surface"] != AttackSurface.EXTRACTION

    def test_no_suggestion_when_none(self, router):
        round_data = {"round": 1, "history": []}
        result = router.select(round_data, None)
        assert "suggested_surface" not in result or result.get("suggested_surface") is None


class TestRoundHistory:
    def test_history_tracks_selections(self, router):
        round_data = {"round": 1, "history": []}
        router.select(round_data, None)
        assert len(router.selection_history) == 1

    def test_history_includes_metadata(self, router):
        round_data = {"round": 1, "history": []}
        router.select(round_data, None)
        entry = router.selection_history[0]
        assert "round" in entry
        assert "surface" in entry
        assert "family" in entry