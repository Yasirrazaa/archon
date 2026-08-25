"""Wave-12 ground-truth benchmark series guards."""

from archon_benchmarks.wave12_series import (
    GOALS,
    SEEDS,
    build_targets,
    render_wave12_md,
    run_wave12_series,
)


def test_six_wave12_targets_registered():
    targets = build_targets()
    assert set(targets) == {
        "rce_sleeper_agent",
        "rce_sandbox_escape",
        "rce_destructive_command",
        "mcp_dns_rebinding",
        "mcp_offpath_exfil",
        "cua_stepjack_chain",
    }


def test_goals_and_seeds_cover_every_target():
    assert set(GOALS) == set(SEEDS) == set(build_targets())


def test_series_report_shape_and_determinism():
    a = run_wave12_series(budget=2, seed=42)
    b = run_wave12_series(budget=2, seed=42)
    assert a == b  # fully deterministic
    assert a["benchmark"] == "wave12_ground_truth_series"
    assert a["measurement"]["llm_calls"] == 0
    for name, entry in a["targets"].items():
        assert entry["attacks_attempted"] <= 2
        assert 0.0 <= entry["asr"] <= 1.0


def test_vulnerable_targets_are_exploitable_within_budget():
    report = run_wave12_series(budget=3, seed=42)
    # Every vulnerable target must fall to at least one attempt in budget.
    assert all(entry["successes"] >= 1 for entry in report["targets"].values())


def test_render_includes_methodology_and_rows():
    md = render_wave12_md(run_wave12_series())
    assert "Attempt budget: 3" in md
    assert "state-diff ground truth" in md
    assert "| cua_stepjack_chain |" in md
    assert "Mean ASR" in md
