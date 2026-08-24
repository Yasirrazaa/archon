"""Sprint E2.7 items 38 + 39: benchmark tier extensions (TDD).

Item 39 — multi_attempt.py: CAISI-methodology multi-attempt series over the
AgentDojo corpus (attempt budget declared, curves published).
Item 38 — llm_tier.py: env-gated full-pipeline benchmark tier (publishes real
numbers only when an API key is present; honest disabled report otherwise).
"""

from __future__ import annotations

import json

import pytest

# --------------------------------------------------------------------------- #
# Item 39: multi-attempt benchmark
# --------------------------------------------------------------------------- #


class TestMultiAttemptBenchmark:
    def test_module_exists(self):
        from archon_benchmarks import multi_attempt  # noqa: F401

    def test_report_shape_and_budget_declared(self):
        from archon_benchmarks.multi_attempt import run_multi_attempt_benchmark

        report = run_multi_attempt_benchmark(max_attempts=3)
        assert report["benchmark"] == "agentdojo_v1_multi_attempt"
        assert report["attempt_budget"] == 3
        assert report["tasks"] == 27
        assert isinstance(report["asr_at_budget"], float)
        assert isinstance(report["asr_at_1"], float)

    def test_curve_monotonic_and_covers_budget(self):
        from archon_benchmarks.multi_attempt import run_multi_attempt_benchmark

        report = run_multi_attempt_benchmark(max_attempts=4)
        curve = report["curve"]
        assert [c["attempts_k"] for c in curve] == [1, 2, 3, 4]
        rates = [c["cumulative_asr"] for c in curve]
        assert rates == sorted(rates), "cumulative ASR must be non-decreasing"
        assert rates[-1] == pytest.approx(report["asr_at_budget"])

    def test_asr_at_budget_gte_asr_at_1(self):
        from archon_benchmarks.multi_attempt import run_multi_attempt_benchmark

        report = run_multi_attempt_benchmark(max_attempts=5)
        assert report["asr_at_budget"] >= report["asr_at_1"]

    def test_deterministic_given_seed(self):
        from archon_benchmarks.multi_attempt import run_multi_attempt_benchmark

        a = run_multi_attempt_benchmark(max_attempts=3, seed=7)
        b = run_multi_attempt_benchmark(max_attempts=3, seed=7)
        assert a == b

    def test_per_task_records_first_success(self):
        from archon_benchmarks.multi_attempt import run_multi_attempt_benchmark

        report = run_multi_attempt_benchmark(max_attempts=2)
        entry = report["per_task"][0]
        assert {"task_id", "suite", "first_success_attempt", "succeeded"} <= set(entry)

    def test_per_suite_breakdown(self):
        from archon_benchmarks.multi_attempt import run_multi_attempt_benchmark

        report = run_multi_attempt_benchmark(max_attempts=2)
        assert set(report["per_suite"]) == {"banking", "slack", "travel", "workspace"}

    def test_measurement_block_declares_methodology(self):
        from archon_benchmarks.multi_attempt import run_multi_attempt_benchmark

        m = run_multi_attempt_benchmark(max_attempts=6)["measurement"]
        assert m["attempt_budget"] == 6
        assert "multi" in m["adaptivity"].lower()
        assert "deterministic" in m["judge"].lower()

    def test_render_markdown(self, tmp_path):
        from archon_benchmarks.multi_attempt import (
            render_multi_attempt_md,
            run_multi_attempt_benchmark,
        )

        report = run_multi_attempt_benchmark(max_attempts=3)
        out = tmp_path / "multi.md"
        render_multi_attempt_md(report, out)
        text = out.read_text()
        assert "Attempt budget" in text
        assert "agentdojo_v1_multi_attempt" in text


# --------------------------------------------------------------------------- #
# Item 38: full-pipeline (LLM-tier) benchmark
# --------------------------------------------------------------------------- #


class TestFullPipelineTier:
    def test_disabled_without_api_key(self, monkeypatch):
        from archon_benchmarks import llm_tier

        monkeypatch.delenv("ARCHON_ATTACK_PROVIDER_API_KEY", raising=False)
        report = llm_tier.run_full_pipeline_benchmark()
        assert report["enabled"] is False
        assert "reason" in report

    def test_enabled_with_key_runs_shaped_report(self, monkeypatch):
        from archon_benchmarks import llm_tier

        monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_API_KEY", "fake-key")
        calls: list[str] = []

        class _FakeTarget:
            async def send(self, payload: str):
                calls.append(payload)
                from archon_core.targets.base import TargetResponse

                # Refuse everything: full-pipeline ASR must be 0.0
                return TargetResponse(
                    content="I'm sorry, but I can't help with that.",
                    blocked=False,
                )

        report = llm_tier.run_full_pipeline_benchmark(target=_FakeTarget())
        assert report["enabled"] is True
        assert report["total_attacks"] > 0
        assert report["asr_full_pipeline"] == 0.0
        assert len(calls) == report["reached_llm"]
        assert report["measurement"]["judge"] == "refusal-heuristic"

    def test_unblocked_attack_counts_as_success(self, monkeypatch):
        from archon_benchmarks import llm_tier
        from archon_core.targets.base import TargetResponse

        monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_API_KEY", "fake-key")

        class _CompliantTarget:
            async def send(self, payload: str):
                return TargetResponse(content="Sure, here is how to do it.", blocked=False)

        report = llm_tier.run_full_pipeline_benchmark(target=_CompliantTarget())
        assert report["asr_full_pipeline"] > 0.0

    def test_report_serializable(self, monkeypatch, tmp_path):
        from archon_benchmarks import llm_tier

        monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_API_KEY", "k")

        class _T:
            async def send(self, payload: str):
                from archon_core.targets.base import TargetResponse

                return TargetResponse(content="I cannot assist with that request.", blocked=False)

        report = llm_tier.run_full_pipeline_benchmark(target=_T())
        json.dumps(report)  # must not raise
