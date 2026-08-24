"""Tests for the typed metric contract (Sprint 75).

The contract mirrors ragas ``MetricOutputType`` (ragas/src/ragas/metrics/base.py
~line 67: BINARY / DISCRETE / CONTINUOUS / RANKING) so every Archon judge
declares what shape its output takes and gets auto-validation against it.
Motivated by 'A Coin Flip for Safety': LLM judges often agree with humans
barely better than a coin flip, so judge reliability must be measured
(Cohen's kappa + accuracy) before its numbers are trusted.
"""

import pytest
from archon_core.reporting.metric_contract import (
    MetricOutputType,
    MetricResult,
    agreement_report,
    kappa_agreement,
    metric_contract,
)


class TestMetricOutputTypeEnum:
    def test_members_match_ragas_base_py(self):
        # ragas/src/ragas/metrics/base.py line ~67
        assert {m.name for m in MetricOutputType} == {
            "BINARY",
            "CONTINUOUS",
            "DISCRETE",
            "RANKING",
        }

    def test_str_values(self):
        assert MetricOutputType.BINARY == "binary"
        assert MetricOutputType.CONTINUOUS == "continuous"
        assert MetricOutputType.DISCRETE == "discrete"
        assert MetricOutputType.RANKING == "ranking"


class TestMetricResultValidation:
    def test_binary_ok_int_and_bool(self):
        for v in (0, 1, True, False):
            assert MetricResult(value=v, output_type=MetricOutputType.BINARY).validate()

    def test_binary_violation_raises_value_error(self):
        with pytest.raises(ValueError):
            MetricResult(value=0.5, output_type=MetricOutputType.BINARY).validate()

    def test_continuous_ok_bounds_inclusive(self):
        for v in (0.0, 0.37, 1.0, 0, 1):
            assert (
                MetricResult(value=v, output_type=MetricOutputType.CONTINUOUS).validate()
            )

    @pytest.mark.parametrize("v", [-0.01, 1.01, "high"])
    def test_continuous_violation_raises_value_error(self, v):
        with pytest.raises(ValueError):
            MetricResult(value=v, output_type=MetricOutputType.CONTINUOUS).validate()

    def test_discrete_ok_within_allowed_set(self):
        r = MetricResult(
            value="partial",
            output_type=MetricOutputType.DISCRETE,
            allowed_values=frozenset({"pass", "partial", "fail"}),
        )
        assert r.validate()

    def test_discrete_allowed_values_enforced(self):
        r = MetricResult(
            value="maybe",
            output_type=MetricOutputType.DISCRETE,
            allowed_values=frozenset({"pass", "fail"}),
        )
        with pytest.raises(ValueError):
            r.validate()

    def test_ranking_ok_list_of_ints(self):
        r = MetricResult(value=[3, 1, 2], output_type=MetricOutputType.RANKING)
        assert r.validate()

    def test_ranking_violation_raises_value_error(self):
        with pytest.raises(ValueError):
            MetricResult(value=[1, "2", 3], output_type=MetricOutputType.RANKING).validate()


class TestMetricContractDecorator:
    def test_decorates_plain_judge_into_metric_result(self):
        @metric_contract(MetricOutputType.BINARY)
        def judge(text: str):
            return 1 if "unsafe" in text else 0

        out = judge("this prompt is unsafe")
        assert isinstance(out, MetricResult)
        assert out.output_type is MetricOutputType.BINARY
        assert out.value == 1

    def test_auto_validation_rejects_bad_output(self):
        @metric_contract(MetricOutputType.CONTINUOUS)
        def broken_judge(text: str):
            return 42.0

        with pytest.raises(ValueError):
            broken_judge("anything")

    def test_tuple_reason_passthrough(self):
        @metric_contract(MetricOutputType.DISCRETE, allowed_values={"yes", "no"})
        def judge(text: str):
            return ("no", "tool call executed outside sandbox")

        out = judge("rm -rf")
        assert out.value == "no"
        assert out.reason == "tool call executed outside sandbox"

    def test_reason_none_when_plain_value_returned(self):
        @metric_contract(MetricOutputType.BINARY)
        def judge(text: str):
            return 0

        assert judge("safe").reason is None


class TestKappaAgreement:
    def test_perfect_agreement_is_one(self):
        a = ["yes", "no", "yes", "no", "yes"]
        b = ["yes", "no", "yes", "no", "yes"]
        assert kappa_agreement(a, b) == pytest.approx(1.0)

    def test_hand_verified_example_is_one_half(self):
        # po = 4/6, pe = 1/3 => kappa = (2/3 - 1/3) / (2/3) = 0.5
        a = [1, 1, 2, 2, 3, 3]
        b = [1, 1, 2, 3, 2, 3]
        assert kappa_agreement(a, b) == pytest.approx(0.5)

    def test_statistically_independent_raters_give_zero(self):
        # Hand-checked: po = pe = 0.5 => kappa = 0.0 exactly.
        a = ["A", "A", "B", "B"]
        b = ["A", "B", "A", "B"]
        assert kappa_agreement(a, b) == 0.0

    def test_single_category_undefined_returns_zero(self):
        # pe == 1 makes kappa undefined (0/0); documented fallback is 0.0.
        assert kappa_agreement(["x", "x"], ["x", "x"]) == 0.0

    def test_length_mismatch_raises(self):
        with pytest.raises(ValueError):
            kappa_agreement([1, 2], [1])


class TestAgreementReport:
    def test_math_on_stub_judge(self):
        def judge(text: str):
            return 1 if text.startswith("bad") else 0

        dataset = [
            ("bad one", 1),
            ("bad two", 1),
            ("good one", 0),
            ("good two", 1),  # judge disagrees here
        ]
        report = agreement_report(judge, dataset)
        assert report["predictions"] == [1, 1, 0, 0]
        assert report["accuracy"] == 0.75  # 3/4, round 4dp
        # perfect margins except the one disagreement: hand-computed
        # po=0.75, pa=[0.5,0.5], ph=[0.75,0.25], pe=0.5 => kappa=0.5
        assert report["kappa"] == pytest.approx(0.5)

    def test_accuracy_rounded_four_decimals(self):
        dataset = [(f"t{i}", i % 2) for i in range(6)]

        def judge(text: str):
            return 0  # agrees only on the human-0 half

        report = agreement_report(judge, dataset)
        correct = sum(p == h for p, h in zip(report["predictions"], [i % 2 for i in range(6)]))
        assert report["accuracy"] == round(correct / 6, 4)

    def test_accepts_wrapped_metric_result_judge(self):
        wrapped = metric_contract(MetricOutputType.BINARY)(lambda t: 1)
        report = agreement_report(wrapped, [("a", 1), ("b", 0)])
        assert report["accuracy"] == 0.5


class TestToDictRoundtrip:
    def test_roundtrip(self):
        original = MetricResult(
            value="fail",
            output_type=MetricOutputType.DISCRETE,
            reason="exfiltrated secrets",
            allowed_values=frozenset({"pass", "fail"}),
        )
        d = original.to_dict()
        assert d == {
            "value": "fail",
            "output_type": "discrete",
            "reason": "exfiltrated secrets",
        }
        rebuilt = MetricResult(
            value=d["value"],
            output_type=MetricOutputType(d["output_type"]),
            reason=d["reason"],
            allowed_values=original.allowed_values,
        )
        assert rebuilt == original
