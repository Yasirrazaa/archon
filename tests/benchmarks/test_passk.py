"""Tests for tau-bench pass^k consistency metrics (Sprint W9-B).

pass^k (arXiv:2406.12045) measures reliability across k independent attempts.
Security framing here: pass_k = reliably-exploitable targets (attack succeeded
in every seed), fail_k = robustly-defended targets, inconsistent = seed-sensitive.
"""

from __future__ import annotations

import pytest
from archon_benchmarks.passk import render_passk_md, run_passk

# ------------------------------------------------------------- stub series ---


def _fake_series_entry(successes: int) -> dict:
    return {
        "attacks_attempted": 3,
        "successes": successes,
        "asr": round(successes / 3, 4),
        "first_success_attempt": 1 if successes else None,
        "evidence_excerpt": "x" if successes else "",
    }


def _make_stub_series(per_seed: dict[int, dict[str, int]]):
    """Build a fake run_target_series keyed by seed -> {target: successes}."""

    def stub(budget: int = 3, seed: int = 42) -> dict:
        targets = {
            name: _fake_series_entry(succ)
            for name, succ in per_seed[seed].items()
        }
        asrs = [t["asr"] for t in targets.values()]
        return {
            "benchmark": "stub",
            "attempt_budget": budget,
            "seed": seed,
            "targets": targets,
            "mean_asr": round(sum(asrs) / len(asrs), 4) if asrs else 0.0,
            "measurement": {"llm_calls": 0},
        }

    return stub


STUB_PER_SEED: dict[int, dict[str, int]] = {
    42: {"alpha": 2, "beta": 0, "gamma": 1},
    43: {"alpha": 3, "beta": 0, "gamma": 0},
    44: {"alpha": 1, "beta": 0, "gamma": 2},
}
# alpha: succeeded all seeds -> pass_k
# beta: blocked all seeds -> fail_k
# gamma: mixed -> inconsistent

_STUB = _make_stub_series(STUB_PER_SEED)


# ------------------------------------------------------------------- shape ---


class TestReportShape:
    def test_top_level_keys(self):
        report = run_passk(seeds=(42, 43, 44), series_fn=_STUB)
        assert set(report) == {
            "benchmark",
            "seeds",
            "attempt_budget",
            "asr_per_seed",
            "per_target",
            "summary",
        }

    def test_asr_per_seed_matches_series_mean(self):
        report = run_passk(seeds=(42, 43, 44), series_fn=_STUB)
        assert report["asr_per_seed"] == {42: 0.3333, 43: 0.3333, 44: 0.3333}

    def test_per_target_entries(self):
        report = run_passk(seeds=(42, 43, 44), series_fn=_STUB)
        by_name = {row["target"]: row for row in report["per_target"]}
        assert set(by_name) == {"alpha", "beta", "gamma"}
        alpha = by_name["alpha"]
        assert alpha["successes"] == [True, True, True]
        assert alpha["pass_k"] is True and alpha["fail_k"] is False
        assert alpha["inconsistent"] is False

    def test_summary_counts(self):
        report = run_passk(seeds=(42, 43, 44), series_fn=_STUB)
        s = report["summary"]
        assert s["n_targets"] == 3
        assert s["n_seeds"] == 3
        assert s["pass_k_count"] == 1
        assert s["fail_k_count"] == 1
        assert s["inconsistent_count"] == 1
        assert s["pass_k_rate"] == 0.3333
        assert s["fail_k_rate"] == 0.3333

    def test_seeds_recorded(self):
        report = run_passk(seeds=(7, 8), series_fn=_make_stub_series({7: {}, 8: {}}))
        assert report["seeds"] == [7, 8]
        assert report["benchmark"].startswith("pass")


# --------------------------------------------------------- k=1 degenerate ----


class TestKOneDegenerates:
    def test_k1_passk_equals_plain_successes(self):
        stub = _make_stub_series({99: {"alpha": 2, "beta": 0}})
        report = run_passk(seeds=(99,), series_fn=stub)
        by_name = {row["target"]: row for row in report["per_target"]}
        assert by_name["alpha"]["pass_k"] is True
        assert by_name["alpha"]["fail_k"] is False
        assert by_name["alpha"]["inconsistent"] is False
        assert by_name["beta"]["fail_k"] is True
        s = report["summary"]
        assert (s["pass_k_count"], s["fail_k_count"], s["inconsistent_count"]) == (1, 1, 0)

    def test_k1_matches_run_target_series_shape(self):
        from archon_benchmarks.target_series import run_target_series

        plain = run_target_series(seed=123)
        k1 = run_passk(seeds=(123,), series_fn=run_target_series, budget=3)
        plain_by = plain["targets"]
        k1_by = {row["target"]: row for row in k1["per_target"]}
        assert set(plain_by) == set(k1_by)
        for name in plain_by:
            expected = plain_by[name]["successes"] > 0
            assert k1_by[name]["successes"] == [expected]


# ------------------------------------------------------------ math checks ----


class TestMath:
    @pytest.mark.parametrize(
        ("succ", "expect"),
        [
            ([True, True], ("pass",)),
            ([False, False, False], ("fail",)),
            ([True, False], ("inconsistent",)),
            ([False, False, True, False], ("inconsistent",)),
        ],
    )
    def test_classification(self, succ, expect):
        per_seed = {seed: {"t": 1 if ok else 0} for seed, ok in enumerate(succ)}
        report = run_passk(seeds=tuple(range(len(succ))), series_fn=_make_stub_series(per_seed))
        row = report["per_target"][0]
        assert row["pass_k"] == ("pass" in expect)
        assert row["fail_k"] == ("fail" in expect)
        assert row["inconsistent"] == ("inconsistent" in expect)

    def test_empty_targets(self):
        stub = _make_stub_series({1: {}, 2: {}})
        report = run_passk(seeds=(1, 2), series_fn=stub)
        assert report["summary"]["n_targets"] == 0
        assert report["summary"]["pass_k_rate"] == 0.0

    def test_budget_forwarded(self):
        captured = {}

        def spy(budget=3, seed=42):
            captured[(budget, seed)] = True
            return _make_stub_series({seed: {}})(budget=budget, seed=seed)

        run_passk(seeds=(5,), series_fn=spy, budget=7)
        assert (7, 5) in captured


# ----------------------------------------------------------------- render ----


class TestRender:
    def test_render_writes_file(self, tmp_path):
        report = run_passk(seeds=(42, 43), series_fn=_STUB)
        path = tmp_path / "passk.md"
        render_passk_md(report, path)
        text = path.read_text(encoding="utf-8")
        assert "# Pass^k Consistency" in text
        assert "42" in text and "43" in text
        assert "state-diff ground truth" in text
        assert "zero upstream calls" in text.lower() or "Zero upstream calls" in text

    def test_render_lists_all_targets(self, tmp_path):
        report = run_passk(seeds=(42,), series_fn=_make_stub_series({42: {"alpha": 1}}))
        path = tmp_path / "passk.md"
        render_passk_md(report, path)
        text = path.read_text(encoding="utf-8")
        assert "alpha" in text
        assert "| alpha |" in text


# ------------------------------------------------- real integration (slow) ---


@pytest.mark.slow
class TestRealSeriesIntegration:
    """Real target-series runs are fully offline/deterministic (zero LLM)."""

    REAL_SEEDS = (42, 43)

    def test_real_series_passk(self):
        report = run_passk(
            seeds=self.REAL_SEEDS,
            budget=3,
        )
        assert report["summary"]["n_targets"] >= 9
        assert report["summary"]["n_seeds"] == 2
        counts = [
            sum(bool(r[k]) for r in report["per_target"]) for k in ("pass_k", "fail_k", "inconsistent")
        ]
        total = sum(counts)
        assert total == report["summary"]["n_targets"]

    def test_real_series_deterministic(self):
        a = run_passk(seeds=self.REAL_SEEDS, budget=3)
        b = run_passk(seeds=self.REAL_SEEDS, budget=3)
        assert a["per_target"] == b["per_target"]
