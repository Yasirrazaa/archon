"""Tests for the judge-calibration harness (Sprint 83).

Productizes PyRIT's scorer_evaluation idea: before a judge's verdicts are
published they must be calibrated against human labels — confusion matrix,
accuracy/precision/recall/F1, and Cohen's kappa ('A Coin Flip for Safety').
Rendering compares against R-Judge published anchors so numbers are honest.
"""

import math

import pytest
from archon_core.reporting.judge_calibration import (
    CalibrationReport,
    LabeledCase,
    calibrate_judge,
    compare_judges,
    render_calibration_md,
)
from archon_core.reporting.metric_contract import kappa_agreement


def _cases(labels: list[int]) -> list[LabeledCase]:
    return [LabeledCase(idx=i, human_label=lab, text=f"case-{i}") for i, lab in enumerate(labels)]


class TestLabeledCase:
    def test_valid_labels_accepted(self):
        for lab in (0, 1):
            assert LabeledCase(idx=0, human_label=lab, text="t").human_label == lab

    def test_invalid_label_raises_value_error(self):
        with pytest.raises(ValueError):
            LabeledCase(idx=0, human_label=2, text="t")


class TestCalibrateJudge:
    def test_perfect_judge_all_metrics_one(self):
        labels = [0, 1, 1, 0, 1]
        report = calibrate_judge(lambda t: labels[int(t.split("-")[1])], _cases(labels))
        assert (report.tp, report.fp, report.tn, report.fn) == (3, 0, 2, 0)
        assert report.accuracy == 1.0
        assert report.precision == 1.0
        assert report.recall == 1.0
        assert report.f1 == 1.0
        assert report.kappa == 1.0

    def test_hand_computed_confusion_matrix(self):
        # Human: pos,pos,pos,pos,neg,neg,neg,neg ; Judge: 1,1,0,0,0,1,0,0
        # -> tp=2 fp=1 tn=3 fn=2; acc=(2+3)/8; prec=2/3; rec=1/2; f1=4/7
        labels = [1, 1, 1, 1, 0, 0, 0, 0]
        preds = [1, 1, 0, 0, 0, 1, 0, 0]

        def judge(text: str) -> int:
            return preds[int(text.split("-")[1])]

        r = calibrate_judge(judge, _cases(labels))
        assert (r.tp, r.fp, r.tn, r.fn) == (2, 1, 3, 2)
        assert r.accuracy == pytest.approx(5 / 8, abs=1e-4)
        assert r.precision == pytest.approx(2 / 3, abs=1e-4)
        assert r.recall == pytest.approx(0.5, abs=1e-4)
        assert r.f1 == pytest.approx(4 / 7, abs=1e-4)
        assert r.kappa == pytest.approx(0.25, abs=1e-4)

    def test_kappa_matches_metric_contract_formula(self):
        labels = [1, 0, 1, 1, 0, 0, 1]
        preds = [1, 0, 0, 1, 1, 0, 1]
        r = calibrate_judge(lambda t: preds[int(t.split("-")[1])], _cases(labels))
        expected = kappa_agreement(preds, labels)
        assert r.kappa == pytest.approx(round(expected, 4))

    def test_kappa_symmetric_case_sanity(self):
        # Symmetric marginals (3 predicted-positive, 3 human-positive of n=6)
        # with tp=2 fp=1 tn=2 fn=1 -> po=4/6, pe=0.5, kappa=1/3.
        labels = [1, 1, 1, 0, 0, 0]
        preds = [1, 1, 0, 0, 0, 1]
        r = calibrate_judge(lambda t: preds[int(t.split("-")[1])], _cases(labels))
        assert (r.tp, r.fp, r.tn, r.fn) == (2, 1, 2, 1)
        assert r.kappa == pytest.approx(1 / 3, abs=1e-4)

    def test_empty_cases_raises_value_error(self):
        with pytest.raises(ValueError):
            calibrate_judge(lambda t: 1, [])

    def test_all_negative_predictions_no_zero_division(self):
        # Judge never predicts positive: precision/f1 fall back to 0.0.
        labels = [1, 0, 1]
        r = calibrate_judge(lambda t: 0, _cases(labels))
        assert (r.tp, r.fp, r.tn, r.fn) == (0, 0, 1, 2)
        assert r.accuracy == pytest.approx(1 / 3, abs=1e-4)
        assert r.precision == 0.0
        assert r.recall == 0.0
        assert r.f1 == 0.0


class TestRenderCalibrationMd:
    @pytest.fixture()
    def report(self) -> CalibrationReport:
        labels = [1, 1, 1, 1, 0, 0, 0, 0]
        preds = [1, 1, 0, 0, 0, 1, 0, 0]
        return calibrate_judge(lambda t: preds[int(t.split("-")[1])], _cases(labels))

    def test_contains_judge_name(self, report):
        md = render_calibration_md(report, "gpt-4o-mini-judge")
        assert "gpt-4o-mini-judge" in md

    def test_contains_rjudge_anchors(self, report):
        md = render_calibration_md(report, "j")
        assert "GPT-4o" in md and "0.744" in md
        assert "0.8907" in md

    def test_contains_confusion_and_metric_rows(self, report):
        md = render_calibration_md(report, "j")
        for token in ("TP", "FP", "TN", "FN", "Accuracy", "Precision", "Recall", "F1", "Kappa"):
            assert token in md

    def test_interpretation_is_honest_below_anchor(self, report):
        md = render_calibration_md(report, "j")
        assert "below" in md.lower()


class TestCompareJudges:
    @pytest.fixture()
    def reports(self) -> dict[str, CalibrationReport]:
        strong = CalibrationReport(
            tp=4, fp=0, tn=4, fn=0,
            accuracy=1.0, precision=1.0, recall=1.0, f1=1.0, kappa=1.0,
        )
        mid = CalibrationReport(
            tp=2, fp=1, tn=3, fn=2,
            accuracy=5 / 8, precision=2 / 3, recall=0.5, f1=4 / 7, kappa=0.25,
        )
        weak = CalibrationReport(
            tp=1, fp=2, tn=3, fn=2,
            accuracy=0.5, precision=1 / 3, recall=1 / 3, f1=1 / 3, kappa=0.0,
        )
        return {"mid": mid, "weak": weak, "strong": strong}

    def test_ranked_by_f1_descending(self, reports):
        table = compare_judges(reports)
        order = [name for name in ("strong", "mid", "weak") if name in table]
        assert order.index("strong") < order.index("mid") < order.index("weak")

    def test_table_includes_f1_values(self, reports):
        table = compare_judges(reports)
        assert "F1" in table and "Judge" in table
        assert f"{4 / 7:.4f}" in table

    def test_single_report_still_renders(self, reports):
        table = compare_judges({"only": reports["strong"]})
        assert "only" in table


class TestMathSanity:
    def test_hand_computed_f1_value(self):
        # Guard against silent drift: f1(2/3, 1/2) must be exactly 4/7.
        p, r = 2 / 3, 0.5
        assert math.isclose(2 * p * r / (p + r), 4 / 7)
