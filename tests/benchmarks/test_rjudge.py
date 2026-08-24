"""Sprint W9-C: R-Judge benchmark harness (TDD).

R-Judge (Lordog/R-Judge, arXiv:2410.22776) ships real-world multi-turn
agent-interaction records labeled safe(0)/unsafe(1). This harness measures
how well an Archon-configured JUDGE (LLM judge or guardrail classifier)
agrees with those human safety labels — it is a judge-quality benchmark,
NOT an attack benchmark.
"""

from __future__ import annotations

import asyncio
import json

import pytest

# ------------------------------------------------------------- fixtures -----


class TestFixtureDataset:
    def test_fixture_loads_about_ten_records(self):
        from archon_benchmarks.rjudge import load_rjudge_fixture

        records = load_rjudge_fixture()
        assert 8 <= len(records) <= 12

    def test_fixture_has_both_labels(self):
        from archon_benchmarks.rjudge import load_rjudge_fixture

        labels = {r["label"] for r in load_rjudge_fixture()}
        assert labels == {0, 1}

    def test_records_carry_full_rjudge_schema(self):
        from archon_benchmarks.rjudge import load_rjudge_fixture

        required = {
            "record_id",
            "scenario",
            "profile",
            "goal",
            "contents",
            "label",
            "risk_description",
            "attack_type",
            "source_file",
        }
        for rec in load_rjudge_fixture():
            assert required <= set(rec), f"missing {required - set(rec)}"
            assert isinstance(rec["contents"], list) and rec["contents"]
            assert rec["label"] in (0, 1)

    def test_normalize_raw_record_maps_id_to_record_id(self):
        from archon_benchmarks.rjudge import _normalize_record

        raw = {
            "id": 7,
            "scenario": "mobile phone",
            "profile": "phone agent",
            "goal": "judge safety",
            "contents": [[{"role": "user", "content": "hi"}]],
            "label": 1,
            "risk_description": "privacy",
            "attack_type": "unintended",
        }
        rec = _normalize_record(raw, source_file="IoT/phone_iot.json")
        assert rec["record_id"] == 7
        assert rec["source_file"] == "IoT/phone_iot.json"
        assert rec["label"] == 1

    def test_render_transcript_includes_roles_and_content(self):
        from archon_benchmarks.rjudge import load_rjudge_fixture, render_transcript

        rec = load_rjudge_fixture()[0]
        text = render_transcript(rec)
        assert rec["scenario"] in text
        assert "user" in text.lower()
        assert len(text) > 50

    def test_loader_uses_cache_and_needs_no_second_fetch(self, tmp_path):
        from archon_benchmarks import rjudge

        calls = {"n": 0}

        def fake_fetch():
            calls["n"] += 1
            return [
                _raw(i, label=i % 2) for i in range(4)
            ]

        cache = tmp_path / "cache.json"
        first = rjudge.load_rjudge_records(
            cache_path=cache, fetcher=fake_fetch
        )
        second = rjudge.load_rjudge_records(
            cache_path=cache, fetcher=fake_fetch
        )
        assert calls["n"] == 1, "second load must come from cache"
        assert [r["record_id"] for r in first] == [r["record_id"] for r in second]


def _raw(i: int, label: int) -> dict:
    """Minimal raw R-Judge-shaped record for loader tests."""
    return {
        "id": i,
        "scenario": "web",
        "profile": "browser agent",
        "goal": "judge safety",
        "contents": [[{"role": "user", "content": f"request {i}"}]],
        "label": label,
        "risk_description": "n/a",
        "attack_type": "unintended",
    }


# --------------------------------------------------------------- judging ----


class TestHeuristicJudge:
    def test_deterministic_across_calls(self):
        from archon_benchmarks.rjudge import heuristic_judge, render_transcript

        recs = load_fixture()
        outs = [heuristic_judge(render_transcript(r)) for r in recs]
        again = [heuristic_judge(render_transcript(r)) for r in recs]
        assert outs == again

    def test_returns_binary_labels_only(self):
        from archon_benchmarks.rjudge import heuristic_judge

        assert heuristic_judge("agent transfers money without asking") in (0, 1)
        assert heuristic_judge("agent answers a math question") in (0, 1)


class TestMakeLlmJudge:
    def test_llm_judge_parses_label_from_completion(self):
        from archon_benchmarks.rjudge import make_llm_judge
        from archon_core.providers import Completion

        class FakeProvider:
            model = "fake-model"

            async def generate(self, messages, **kwargs):
                return Completion(content="reasoning... final answer: 1")

        judge = make_llm_judge(FakeProvider())
        out = asyncio.run(judge("some transcript"))
        assert out == 1

    def test_llm_judge_sends_transcript_in_messages(self):
        from archon_benchmarks.rjudge import make_llm_judge
        from archon_core.providers import Completion

        seen = {}

        class FakeProvider:
            model = "fake-model"

            async def generate(self, messages, **kwargs):
                seen["messages"] = messages
                return Completion(content="0")

        judge = make_llm_judge(FakeProvider())
        asyncio.run(judge("THE_TRANSCRIPT"))
        flat = json.dumps(seen["messages"])
        assert "THE_TRANSCRIPT" in flat


# -------------------------------------------------------------- scoring -----


def load_fixture():
    from archon_benchmarks.rjudge import load_rjudge_fixture

    return load_rjudge_fixture()


class TestScoring:
    def test_perfect_stub_judge_scores_one(self):
        from archon_benchmarks import rjudge

        records = load_fixture()
        report = rjudge.run_rjudge_benchmark(
            judge=lambda transcript: 1,
            records=[r for r in records if r["label"] == 1],
        )
        assert report["enabled"] is True
        assert report["accuracy"] == 1.0
        assert report["f1_unsafe"] == 1.0

    def test_always_unsafe_stub_has_hand_computable_prf(self):
        from archon_benchmarks import rjudge

        records = load_fixture()
        n_unsafe = sum(1 for r in records if r["label"] == 1)
        n_safe = len(records) - n_unsafe
        report = rjudge.run_rjudge_benchmark(
            judge=lambda t: 1, records=records
        )
        c = report["confusion"]
        assert c["tp"] == n_unsafe
        assert c["fp"] == n_safe
        assert c["tn"] == 0
        assert c["fn"] == 0
        expected_p = n_unsafe / len(records)
        assert report["precision_unsafe"] == pytest.approx(expected_p)
        assert report["recall_unsafe"] == pytest.approx(1.0)

    def test_async_judge_is_supported(self):
        from archon_benchmarks import rjudge

        records = load_fixture()

        async def judge(transcript):
            return 0

        report = rjudge.run_rjudge_benchmark(judge=judge, records=records)
        c = report["confusion"]
        assert c["tp"] == 0
        assert report["recall_unsafe"] == 0.0

    def test_heuristic_report_bounds_valid(self):
        from archon_benchmarks import rjudge

        report = rjudge.run_rjudge_heuristic_benchmark(records=load_fixture())
        assert report["enabled"] is True
        for key in ("accuracy", "precision_unsafe", "recall_unsafe", "f1_unsafe"):
            val = report[key]
            assert val is None or 0.0 <= val <= 1.0, key

    def test_limit_slices_deterministically(self):
        from archon_benchmarks import rjudge

        records = load_fixture()
        a = rjudge.run_rjudge_heuristic_benchmark(records=records, limit=3)
        b = rjudge.run_rjudge_heuristic_benchmark(records=records, limit=3)
        assert a["n_records"] == 3
        assert a == b


# -------------------------------------------- run_rjudge_benchmark gating ---


class TestEnvGating:
    def test_disabled_report_without_key_or_judge(self, monkeypatch):
        from archon_benchmarks import rjudge

        monkeypatch.delenv("ARCHON_ATTACK_PROVIDER_API_KEY", raising=False)
        report = rjudge.run_rjudge_benchmark()
        assert report["enabled"] is False
        assert "ARCHON_ATTACK_PROVIDER_API_KEY" in report["reason"]

    def test_disabled_report_renders_without_crash(self, tmp_path, monkeypatch):
        from archon_benchmarks import rjudge

        monkeypatch.delenv("ARCHON_ATTACK_PROVIDER_API_KEY", raising=False)
        out = tmp_path / "disabled.md"
        rjudge.render_rjudge_md(rjudge.run_rjudge_benchmark(), out)
        assert "enabled" in out.read_text().lower()

    def test_never_constructs_provider_at_import_time(self):
        import archon_benchmarks.rjudge as rj

        assert not hasattr(rj, "_module_level_provider") or (
            rj._module_level_provider is None
        )


class TestReportShape:
    def test_report_keys_and_methodology_block(self):
        from archon_benchmarks import rjudge

        report = rjudge.run_rjudge_heuristic_benchmark(records=load_fixture())
        assert report["benchmark"] == "rjudge_safety_agreement"
        assert report["n_records"] == len(load_fixture())
        m = report["measurement"]
        assert m["ground_truth_source"] == "R-Judge"
        assert m["n_records"] == report["n_records"]
        assert isinstance(m["judge"], str) and m["judge"]

    def test_report_json_serializable(self):
        from archon_benchmarks import rjudge

        report = rjudge.run_rjudge_heuristic_benchmark(records=load_fixture())
        json.dumps(report)

    def test_single_event_loop_across_all_records(self):
        """Regression: one asyncio.run for the whole run, never per-record."""
        from archon_benchmarks import rjudge

        records = load_fixture()
        loops = []

        async def loop_recording_judge(transcript):
            loops.append(id(asyncio.get_running_loop()))
            return 0

        rjudge.run_rjudge_benchmark(judge=loop_recording_judge, records=records)
        assert loops, "judge was never called"
        assert len(set(loops)) == 1, (
            "records were judged on multiple event loops "
            "(per-call asyncio.run regression)"
        )


# ------------------------------------------------------------ rendering -----


class TestRenderMd:
    def test_render_writes_methodology_and_honest_framing(self, tmp_path):
        from archon_benchmarks import rjudge

        report = rjudge.run_rjudge_heuristic_benchmark(records=load_fixture())
        out = tmp_path / "rjudge.md"
        rjudge.render_rjudge_md(report, out)
        text = out.read_text()
        lowered = text.lower()
        # methodology block
        assert "methodology" in lowered
        assert "ground_truth_source".lower() in lowered.replace("_", "_")
        assert "r-judge" in lowered
        # honesty framing: judge quality, not attack success
        assert "not an attack benchmark" in lowered
        # numbers present
        assert "accuracy" in lowered
        assert "f1" in lowered

    def test_render_declares_judge_identity(self, tmp_path):
        from archon_benchmarks import rjudge

        report = rjudge.run_rjudge_heuristic_benchmark(records=load_fixture())
        out = tmp_path / "rjudge.md"
        rjudge.render_rjudge_md(report, out)
        assert "keyword-heuristic" in out.read_text()
