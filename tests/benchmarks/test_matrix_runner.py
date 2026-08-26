"""Tests for the multi-provider benchmark matrix runner (SPRINT 96).

Offline only: every phase execution goes through an injectable fake
runner_fn — no network access, no real provider calls.
"""

from __future__ import annotations

import json

import pytest
from archon_benchmarks import matrix_runner as mr

PROVIDERS = [
    {
        "name": "prov-a",
        "base_url": "https://a.test/v1",
        "model": "model-a",
        "api_key_env": "MATRIX_KEY_A",
    },
    {
        "name": "prov-b",
        "base_url": "https://b.test/v1",
        "model": "model-b",
        "api_key_env": "MATRIX_KEY_B",
    },
]

STRONGREJECT_REPORT = {
    "benchmark": "strongreject",
    "total_cases": 10,
    "mean_strongreject_score": 0.42,
}

AGENTHARM_REPORT = {
    "benchmark": "agentharm",
    "total_cases": 8,
    "compliance_rate": 0.25,
    "refusal_rate": 0.75,
}


@pytest.fixture(autouse=True)
def _keys(monkeypatch):
    monkeypatch.setenv("MATRIX_KEY_A", "key-a")
    monkeypatch.setenv("MATRIX_KEY_B", "key-b")


def make_fake_runner(reports=None, fail=None):
    """Fake runner_fn(suite, cfg, out_dir, concurrency) -> report."""
    reports = reports or {}
    fail = fail or set()
    calls: list[dict] = []

    def runner(suite, cfg, out_dir, concurrency):
        calls.append(
            {
                "suite": suite,
                "cfg": dict(cfg),
                "out_dir": str(out_dir),
                "concurrency": concurrency,
            }
        )
        if (suite,) in {(f,) for f in fail} or suite in fail:
            raise RuntimeError(f"boom in {suite}")
        return reports.get(suite, {})

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


class TestMatrixShape:
    def test_one_row_per_provider_suite_pair(self):
        runner = make_fake_runner(
            {
                "strongreject": STRONGREJECT_REPORT,
                "agentharm": AGENTHARM_REPORT,
            }
        )
        result = mr.run_matrix(PROVIDERS, runner_fn=runner)
        assert len(result["matrix"]) == 4

    def test_rows_carry_provider_model_suite_and_value(self):
        runner = make_fake_runner({"strongreject": STRONGREJECT_REPORT})
        result = mr.run_matrix(
            [PROVIDERS[0]], suites=["strongreject"], runner_fn=runner
        )
        row = result["matrix"][0]
        assert row["provider"] == "prov-a"
        assert row["model"] == "model-a"
        assert row["suite"] == "strongreject"
        assert row["value"] == 0.42
        assert "error" not in row

    def test_default_suites_are_strongreject_and_agentharm(self):
        runner = make_fake_runner()
        mr.run_matrix([PROVIDERS[0]], runner_fn=runner)
        suites = {c["suite"] for c in runner.calls}
        assert suites == {"strongreject", "agentharm"}

    def test_result_contains_markdown_table(self):
        result = mr.run_matrix(PROVIDERS, runner_fn=make_fake_runner())
        assert isinstance(result["markdown"], str)
        assert result["markdown"].strip().startswith("|")


class TestErrorHandling:
    def test_error_cell_recorded_not_raised(self):
        runner = make_fake_runner(fail={"agentharm"})
        result = mr.run_matrix(
            [PROVIDERS[0]], runner_fn=runner
        )  # must not raise
        sr_row = next(
            r for r in result["matrix"] if r["suite"] == "strongreject"
        )
        ah_row = next(r for r in result["matrix"] if r["suite"] == "agentharm")
        assert "error" not in sr_row
        assert "boom in agentharm" in ah_row["error"]
        assert ah_row["value"] is None

    def test_missing_api_key_env_records_error_per_cell(self, monkeypatch):
        monkeypatch.delenv("MATRIX_KEY_A", raising=False)
        runner = make_fake_runner()
        result = mr.run_matrix(
            PROVIDERS, suites=["strongreject"], runner_fn=runner
        )
        row_a = next(r for r in result["matrix"] if r["provider"] == "prov-a")
        row_b = next(r for r in result["matrix"] if r["provider"] == "prov-b")
        assert "MATRIX_KEY_A" in row_a["error"]
        assert "error" not in row_b
        # failing provider never reached the runner
        assert all(c["cfg"]["api_key"] != "" for c in runner.calls)


class TestInjectableRunner:
    def test_injectable_fake_runner_used_for_every_cell(self):
        runner = make_fake_runner()
        mr.run_matrix(PROVIDERS, runner_fn=runner)
        assert len(runner.calls) == 4

    def test_cfg_built_like_live_runner_resolve_config(self):
        runner = make_fake_runner()
        mr.run_matrix(
            [PROVIDERS[0]], suites=["strongreject"], runner_fn=runner
        )
        cfg = runner.calls[0]["cfg"]
        assert cfg == {
            "base_url": "https://a.test/v1",
            "api_key": "key-a",
            "model": "model-a",
        }

    def test_concurrency_passed_through(self):
        runner = make_fake_runner()
        mr.run_matrix(PROVIDERS, concurrency=7, runner_fn=runner)
        assert all(c["concurrency"] == 7 for c in runner.calls)

    def test_out_dir_respected_per_provider(self, tmp_path):
        runner = make_fake_runner()
        out = tmp_path / "matrix_out"
        mr.run_matrix(PROVIDERS, out_dir=str(out), runner_fn=runner)
        outs = {c["out_dir"] for c in runner.calls}
        assert outs == {
            str(out / "prov-a"),
            str(out / "prov-b"),
        }


class TestMetricsAndRendering:
    def test_strongreject_metric_is_mean_strongreject_score(self):
        runner = make_fake_runner(
            {"strongreject": STRONGREJECT_REPORT, "agentharm": {}}
        )
        result = mr.run_matrix(PROVIDERS, runner_fn=runner)
        sr_rows = [r for r in result["matrix"] if r["suite"] == "strongreject"]
        assert all(
            r["metric_name"] == "mean_strongreject_score" for r in sr_rows
        )

    def test_agentharm_metric_is_compliance_rate(self):
        runner = make_fake_runner(
            {
                "strongreject": {},
                "agentharm": AGENTHARM_REPORT,
            }
        )
        result = mr.run_matrix(PROVIDERS, runner_fn=runner)
        ah_rows = [r for r in result["matrix"] if r["suite"] == "agentharm"]
        assert all(
            r["metric_name"] == "compliance_rate"
            and r["value"] == 0.25
            for r in ah_rows
        )

    def test_md_table_renders_all_rows(self):
        runner = make_fake_runner(fail={"agentharm"})
        result = mr.run_matrix(PROVIDERS, runner_fn=runner)
        lines = [
            line
            for line in result["markdown"].splitlines()
            if line.startswith("|")
        ]
        # header + separator + 4 data rows
        assert len(lines) == 2 + len(result["matrix"])
        joined = "\n".join(lines)
        assert "prov-a" in joined and "prov-b" in joined
        assert "strongreject" in joined and "agentharm" in joined
        assert "boom in agentharm" in joined

    def test_json_roundtrip_of_result(self, tmp_path):
        runner = make_fake_runner(fail={"agentharm"})
        result = mr.run_matrix(PROVIDERS, runner_fn=runner)
        text = json.dumps(result)
        loaded = json.loads(text)
        assert len(loaded["matrix"]) == len(result["matrix"])
