"""Tests for the per-target ground-truth benchmark series (Sprint W7-A)."""

from __future__ import annotations

import pytest
from archon_benchmarks.target_series import (
    CRAFTED_PROBES,
    build_targets,
    render_series_md,
    run_target_series,
)
from archon_core.targets.base import TargetAdapter

EXPECTED_TARGET_NAMES = [
    "cascade_failure",
    "gap_config_tamper",
    "gap_recon",
    "gap_staged_payload",
    "mcp_tool_poisoning",
    "memory_poisoning",
    "rogue_agent",
    "sandbox_banking",
    "supply_chain_rugpull",
    "trust_boundary_swarm",
    "trust_exploitation_hitl",
]


# ------------------------------------------------------------ build_targets --


def test_build_targets_returns_at_least_nine():
    targets = build_targets()
    assert len(targets) >= 9


def test_build_targets_all_target_adapters():
    for name, target in build_targets().items():
        assert isinstance(target, TargetAdapter), name


@pytest.mark.parametrize("name", EXPECTED_TARGET_NAMES)
def test_build_targets_covers_expected_name(name):
    assert name in build_targets()


def test_build_targets_fresh_instances_each_call():
    first = build_targets()
    second = build_targets()
    for name in first:
        assert first[name] is not second[name]


# ------------------------------------------- vulnerable-target ground truth --
#
# Critical correctness property: every constructed instance IS the vulnerable
# variant and must report raw['attack_success']=True under at least one
# directly crafted probe.


@pytest.mark.parametrize("name", EXPECTED_TARGET_NAMES)
async def test_vulnerable_target_reports_attack_success(name):
    target = build_targets()[name]
    responses = [await target.send(p) for p in CRAFTED_PROBES[name]]
    assert any(
        bool(r.raw and r.raw.get("attack_success")) for r in responses
    ), f"{name}: no crafted probe achieved ground-truth attack_success"


async def test_sandbox_entry_reflects_env_diff_truth():
    target = build_targets()["sandbox_banking"]
    resp = await target.send(CRAFTED_PROBES["sandbox_banking"][0])
    assert resp.raw is not None
    assert resp.raw.get("attack_success") is True
    assert resp.raw.get("env_diff"), "expected a non-empty environment diff"


# ----------------------------------------------------------- series reports --


def test_series_report_shape():
    report = run_target_series()
    assert report["benchmark"] == "per_target_ground_truth_series"
    assert report["attempt_budget"] == 3
    for name in build_targets():
        entry = report["targets"][name]
        assert set(entry) >= {
            "attacks_attempted",
            "successes",
            "asr",
            "evidence_excerpt",
        }


def test_series_asr_bounds_and_budget():
    report = run_target_series(budget=3)
    for name, entry in report["targets"].items():
        assert 0.0 <= entry["asr"] <= 1.0, name
        assert 1 <= entry["attacks_attempted"] <= 3, name
        assert 0 <= entry["successes"] <= entry["attacks_attempted"], name


def test_series_every_vulnerable_target_succeeds():
    """The whole point of the series: vulnerable variants must score > 0."""
    report = run_target_series()
    for name, entry in report["targets"].items():
        assert entry["successes"] >= 1, f"{name}: vulnerable variant never succeeded"


def test_series_respects_smaller_budget():
    report = run_target_series(budget=1)
    for entry in report["targets"].values():
        assert entry["attacks_attempted"] == 1


def test_series_is_deterministic():
    assert run_target_series() == run_target_series()


def test_series_accepts_alternate_seed():
    report = run_target_series(seed=7)
    for entry in report["targets"].values():
        assert 0.0 <= entry["asr"] <= 1.0
        assert 1 <= entry["attacks_attempted"] <= 3


def test_series_evidence_excerpt_present_for_successes():
    report = run_target_series()
    for name, entry in report["targets"].items():
        if entry["successes"] >= 1:
            assert entry["evidence_excerpt"], name


def test_series_measurement_metadata():
    report = run_target_series()
    m = report["measurement"]
    assert m["adaptivity"] == "multi-attempt-5-variant-rotation"
    assert "ground truth" in m["judge"]
    assert m["llm_calls"] == 0


# ---------------------------------------------------------------- rendering --


def test_render_contains_table_header_and_all_targets():
    report = run_target_series()
    md = render_series_md(report)
    assert "| Target | Attempts | ASR | Notes |" in md
    for name in EXPECTED_TARGET_NAMES:
        assert name in md


def test_render_contains_methodology_keywords():
    md = render_series_md(run_target_series())
    lowered = md.lower()
    assert "attempt budget" in lowered
    assert "ground truth" in lowered
