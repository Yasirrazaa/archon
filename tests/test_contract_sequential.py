"""Tests for contract awareness and sequential chaining - attacker module.

Based on NeuralShield's attacker: parses output_format for attack surface
modeling and chains strategies with fallback.
"""
import pytest
from scenarios.security_arena.agents.attacker.contract_sequential import (
    ContractModel,
    ContractAnalyzer,
    SequentialAttacker,
)


class TestContractModel:
    def test_dataclass_fields(self):
        m = ContractModel(
            expected_fields=["risk_level", "score"],
            is_numeric=True,
            is_constrained=False,
            task_type="classification",
        )
        assert m.expected_fields == ["risk_level", "score"]
        assert m.is_numeric is True
        assert m.is_constrained is False
        assert m.task_type == "classification"

    def test_defaults(self):
        m = ContractModel(
            expected_fields=[],
            is_numeric=False,
            is_constrained=False,
            task_type="unknown",
        )
        assert m.expected_fields == []


class TestContractAnalyzerExtractFields:
    def test_json_field_names(self):
        a = ContractAnalyzer()
        fmt = '{"risk_level": "HIGH", "confidence": 0.95, "reasoning": "..."}'
        model = a.analyze(fmt)
        assert "risk_level" in model.expected_fields
        assert "confidence" in model.expected_fields
        assert "reasoning" in model.expected_fields

    def test_nested_json_fields(self):
        a = ContractAnalyzer()
        fmt = '{"result": {"category": "safe", "score": 10}}'
        model = a.analyze(fmt)
        assert "category" in model.expected_fields
        assert "score" in model.expected_fields

    def test_no_json_fields(self):
        a = ContractAnalyzer()
        fmt = "Please provide a textual analysis of the risk."
        model = a.analyze(fmt)
        assert model.expected_fields == []

    def test_multiple_json_keys(self):
        a = ContractAnalyzer()
        fmt = '{"status": "ok", "data": {"id": 1, "name": "test"}}'
        model = a.analyze(fmt)
        assert len(model.expected_fields) >= 4


class TestContractAnalyzerNumeric:
    def test_detects_score(self):
        a = ContractAnalyzer()
        model = a.analyze('{"score": 85}')
        assert model.is_numeric is True

    def test_detects_rating(self):
        a = ContractAnalyzer()
        model = a.analyze('{"rating": 4}')
        assert model.is_numeric is True

    def test_detects_count(self):
        a = ContractAnalyzer()
        model = a.analyze('{"count": 3}')
        assert model.is_numeric is True

    def test_no_numeric(self):
        a = ContractAnalyzer()
        model = a.analyze('{"status": "approved"}')
        assert model.is_numeric is False

    def test_detects_percentage(self):
        a = ContractAnalyzer()
        model = a.analyze('{"confidence": 85%}')
        assert model.is_numeric is True


class TestContractAnalyzerConstrained:
    def test_detects_high_medium_low(self):
        a = ContractAnalyzer()
        model = a.analyze('{"risk_level": "High|Medium|Low"}')
        assert model.is_constrained is True

    def test_detects_boolean_constraint(self):
        a = ContractAnalyzer()
        model = a.analyze('{"approved": true|false}')
        assert model.is_constrained is True

    def test_detects_yes_no(self):
        a = ContractAnalyzer()
        model = a.analyze('{"valid": "yes|no"}')
        assert model.is_constrained is True

    def test_unconstrained(self):
        a = ContractAnalyzer()
        model = a.analyze('{"description": "free text here"}')
        assert model.is_constrained is False


class TestContractAnalyzerTaskType:
    def test_classification_task(self):
        a = ContractAnalyzer()
        model = a.analyze('{"category": "safe", "risk_level": "LOW"}')
        assert model.task_type in ("classification", "extraction")

    def test_scoring_task(self):
        a = ContractAnalyzer()
        model = a.analyze('{"score": 85, "confidence": 0.9}')
        assert model.task_type in ("scoring", "extraction")

    def test_unknown_task(self):
        a = ContractAnalyzer()
        model = a.analyze('{"note": "some free text"}')
        assert model.task_type in ("unknown", "extraction")


class TestSequentialAttackerTryFirst:
    def test_first_strategy_succeeds(self):
        def succeed(ctx):
            return {"success": True, "data": "leaked info"}

        sa = SequentialAttacker()
        strategies = [("rapport", 2), ("injection", 2)]
        result = sa.execute(strategies, {"context": "test"}, strategy_fn=succeed)
        assert result["strategy"] == "rapport"
        assert result["result"]["success"] is True


class TestSequentialAttackerFallback:
    def test_falls_back_on_failure(self):
        call_count = {"n": 0}

        def fail_then_succeed(ctx):
            call_count["n"] += 1
            if call_count["n"] <= 2:
                return {"success": False, "reason": "blocked"}
            return {"success": True, "data": "partial"}

        sa = SequentialAttacker()
        strategies = [("rapport", 2), ("injection", 2)]
        result = sa.execute(strategies, {}, strategy_fn=fail_then_succeed)
        assert result["strategy"] == "injection"
        assert result["result"]["success"] is True

    def test_all_fail_returns_fallback(self):
        def always_fail(ctx):
            return {"success": False, "reason": "blocked"}

        sa = SequentialAttacker()
        strategies = [("rapport", 1), ("injection", 1)]
        result = sa.execute(strategies, {}, strategy_fn=always_fail)
        assert result["strategy"] == "fallback"
        assert result["result"]["success"] is False


class TestSequentialAttackerRecordsFailures:
    def test_failures_recorded(self):
        def always_fail(ctx):
            return {"success": False, "reason": "blocked"}

        sa = SequentialAttacker()
        strategies = [("rapport", 2), ("injection", 1)]
        sa.execute(strategies, {}, strategy_fn=always_fail)
        assert "rapport" in sa.failure_log
        assert sa.failure_log["rapport"] == 2
        assert "injection" in sa.failure_log
        assert sa.failure_log["injection"] == 1

    def test_success_resets_count(self):
        call_count = {"n": 0}

        def fail_once_then_succeed(ctx):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return {"success": False, "reason": "blocked"}
            return {"success": True, "data": "ok"}

        sa = SequentialAttacker()
        strategies = [("rapport", 3)]
        sa.execute(strategies, {}, strategy_fn=fail_once_then_succeed)
        assert sa.failure_log.get("rapport", 0) == 1


class TestSequentialAttackerStrategyChain:
    def test_max_attempts_respected(self):
        attempts = {"n": 0}

        def track_attempts(ctx):
            attempts["n"] += 1
            return {"success": False, "reason": "nope"}

        sa = SequentialAttacker()
        strategies = [("rapport", 3)]
        sa.execute(strategies, {}, strategy_fn=track_attempts)
        assert attempts["n"] == 3

    def test_stops_after_success(self):
        attempts = {"n": 0}

        def succeed_on_first(ctx):
            attempts["n"] += 1
            return {"success": True, "data": "leaked"}

        sa = SequentialAttacker()
        strategies = [("rapport", 5), ("injection", 5)]
        sa.execute(strategies, {}, strategy_fn=succeed_on_first)
        assert attempts["n"] == 1


class TestSequentialAttackerEmptyStrategies:
    def test_empty_strategies_returns_fallback(self):
        sa = SequentialAttacker()
        result = sa.execute([], {}, strategy_fn=lambda ctx: {"success": False})
        assert result["strategy"] == "fallback"


class TestSequentialAttackerContext:
    def test_context_passed_to_strategy(self):
        received_ctx = {}

        def capture_ctx(ctx):
            received_ctx.update(ctx)
            return {"success": True, "data": "ok"}

        sa = SequentialAttacker()
        strategies = [("rapport", 1)]
        sa.execute(strategies, {"attack_goal": "steal data", "round": 3}, strategy_fn=capture_ctx)
        assert received_ctx["attack_goal"] == "steal data"
        assert received_ctx["round"] == 3
