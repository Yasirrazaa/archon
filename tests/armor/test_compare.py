"""Tests for the battle comparison engine (`archon compare`)."""

from __future__ import annotations

import json

import pytest
from archon_armor.compare import compare_battles, render_compare_md


def _summary(
    total: int,
    blocked: int,
    *,
    control_passed: bool = True,
    coverage: dict | None = None,
    max_severity: float | None = None,
) -> dict:
    s = {
        "total_probes": total,
        "blocked": blocked,
        "block_rate": blocked / total if total else 0.0,
        "control_passed": control_passed,
        "coverage": coverage or {},
    }
    if max_severity is not None:
        s["severity"] = {"max_score": max_severity, "bands": {}, "findings": []}
    return s


def _report(
    results: list[dict],
    summary: dict,
    *,
    agent_id: str = "agent",
) -> dict:
    return {
        "battle_id": "b-" + agent_id,
        "agent_id": agent_id,
        "status": "completed",
        "results": results,
        "summary": summary,
    }


class TestCompareBattles:
    def test_block_rate_delta(self):
        a = _report([], _summary(100, 80))
        b = _report([], _summary(100, 90))
        out = compare_battles(a, b)
        assert out["block_rate"]["a"] == pytest.approx(0.8)
        assert out["block_rate"]["b"] == pytest.approx(0.9)
        assert out["block_rate"]["delta"] == pytest.approx(0.1)

    def test_verdict_improved_on_rate_gain(self):
        a = _report([], _summary(50, 25))
        b = _report([], _summary(50, 40))
        assert compare_battles(a, b)["verdict"] == "improved"

    def test_verdict_regressed_on_rate_drop(self):
        a = _report([], _summary(50, 40))
        b = _report([], _summary(50, 25))
        assert compare_battles(a, b)["verdict"] == "regressed"

    def test_control_failure_is_regression_even_with_rate_gain(self):
        a = _report([], _summary(50, 30, control_passed=True))
        b = _report([], _summary(50, 45, control_passed=False))
        out = compare_battles(a, b)
        assert out["verdict"] == "regressed"
        assert out["control"] == {"a": True, "b": False}

    def test_newly_unblocked_probe_listed(self):
        results_a = [{"probe_name": "p1", "blocked": True},
                     {"probe_name": "p2", "blocked": True}]
        results_b = [{"probe_name": "p1", "blocked": False},
                     {"probe_name": "p2", "blocked": True}]
        a = _report(results_a, _summary(2, 2))
        b = _report(results_b, _summary(2, 1))
        out = compare_battles(a, b)
        assert out["newly_unblocked"] == ["p1"]
        assert out["verdict"] == "regressed"

    def test_newly_blocked_probe_listed(self):
        results_a = [{"probe_name": "p1", "blocked": False}]
        results_b = [{"probe_name": "p1", "blocked": True}]
        out = compare_battles(
            _report(results_a, _summary(1, 0)), _report(results_b, _summary(1, 1))
        )
        assert out["newly_blocked"] == ["p1"]

    def test_per_category_table_from_coverage(self):
        cov_a = {
            "owasp_llm_01": {"probes": 10, "blocked": 5},
            "encoding_evasion": {"probes": 10, "blocked": 8},
        }
        cov_b = {
            "owasp_llm_01": {"probes": 10, "blocked": 7},
            "encoding_evasion": {"probes": 10, "blocked": 6},
        }
        out = compare_battles(_report([], _summary(20, 13, coverage=cov_a)),
                              _report([], _summary(20, 13, coverage=cov_b)))
        cats = {c["category"]: c for c in out["per_category"]}
        assert cats["owasp_llm_01"]["delta"] == pytest.approx(0.2)
        assert cats["encoding_evasion"]["delta"] == pytest.approx(-0.2)

    def test_severity_delta_when_present(self):
        a = _report([], _summary(10, 5, max_severity=9.2))
        b = _report([], _summary(10, 6, max_severity=7.0))
        out = compare_battles(a, b)
        assert out["severity"] == {"a": 9.2, "b": 7.0, "delta": pytest.approx(-2.2)}

    def test_severity_absent_is_none(self):
        out = compare_battles(_report([], _summary(10, 5)), _report([], _summary(10, 6)))
        assert out["severity"] is None

    def test_equal_summaries(self):
        out = compare_battles(_report([], _summary(10, 5)), _report([], _summary(10, 5)))
        assert out["verdict"] == "equal"
        assert out["newly_unblocked"] == []
        assert out["newly_blocked"] == []


class TestRenderCompareMd:
    def test_markdown_contains_key_sections(self):
        results_a = [{"probe_name": "p1", "blocked": True}]
        results_b = [{"probe_name": "p1", "blocked": False}]
        report = compare_battles(
            _report(results_a, _summary(1, 1)), _report(results_b, _summary(1, 0))
        )
        md = render_compare_md(report, label_a="policy-v1", label_b="policy-v2")
        assert "policy-v1" in md and "policy-v2" in md
        assert "regressed" in md.lower()
        assert "p1" in md
        assert "Block rate" in md

    def test_json_roundtrip(self, tmp_path):
        a = _report([], _summary(4, 3), agent_id="x")
        path = tmp_path / "a.json"
        path.write_text(json.dumps(a))
        loaded = json.loads(path.read_text())
        assert compare_battles(loaded, loaded)["verdict"] == "equal"
