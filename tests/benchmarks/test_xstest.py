"""Sprint BENCH-XSTEST: XSTest over-refusal benchmark — offline fixture tests."""

import pytest
from archon_benchmarks.xstest import (
    FIXTURE_PATH,
    XSTestCase,
    build_probes,
    detect_refusal,
    load_xstest,
    load_xstest_fixture,
    render_xstest_md,
    run_xstest_benchmark,
)


class TestFixture:
    def test_fixture_file_is_committed_and_offline(self):
        assert FIXTURE_PATH.exists()

    def test_fixture_loads_without_network(self):
        cases = load_xstest_fixture()
        assert len(cases) >= 40

    def test_fixture_balanced_types(self):
        cases = load_xstest_fixture()
        by_type = {c.prompt_type for c in cases}
        assert by_type == {"full_compliance", "full_refusal"}
        for wanted in ("full_compliance", "full_refusal"):
            n = sum(1 for c in cases if c.prompt_type == wanted)
            assert n >= 10, f"too few {wanted} rows in fixture"

    def test_every_case_has_prompt(self):
        for case in load_xstest_fixture():
            assert isinstance(case, XSTestCase)
            assert case.prompt.strip()

    def test_unique_prompts(self):
        prompts = [c.prompt for c in load_xstest_fixture()]
        assert len(prompts) == len(set(prompts))

    def test_load_xstest_offline_falls_back_to_fixture(self, monkeypatch):
        import archon_benchmarks.xstest as mod

        monkeypatch.setattr(mod, "_download", lambda *_a, **_k: (_ for _ in ()).throw(OSError))
        monkeypatch.setattr(
            mod, "CACHE_DIR", mod.CACHE_DIR.__class__(mod.FIXTURE_PATH.parent / "no-cache-here")
        )
        cases = load_xstest()
        assert len(cases) >= 40


class TestRefusalDetector:
    @pytest.mark.parametrize("text", [
        "I can't help with that.",
        "I'm sorry, but I cannot comply with this request.",
        "As an AI language model, I must refuse.",
        "I cannot assist with this.",
    ])
    def test_refusal_markers_detected(self, text):
        assert detect_refusal(text) is True

    @pytest.mark.parametrize("text", [
        "Sure! Here is how you kill a Python process: use `kill -9 <pid>`.",
        "To terminate a contract, review the termination clause first.",
        "The capital of France is Paris.",
    ])
    def test_compliant_answers_not_flagged(self, text):
        assert detect_refusal(text) is False


class TestBuildProbes:
    def test_categories_and_unique_names(self):
        probes = build_probes(load_xstest_fixture())
        names = [p.name for p in probes]
        assert len(names) == len(set(names))
        assert all(p.payload.strip() for p in probes)

    def test_categories_split_by_prompt_type(self):
        probes = build_probes(load_xstest_fixture())
        categories = {p.category for p in probes}
        assert categories == {"xstest_full_compliance", "xstest_full_refusal"}


class TestBenchmarkRun:
    def test_report_shape_and_bounds(self):
        report = run_xstest_benchmark(records=load_xstest_fixture())
        assert report["benchmark"] == "xstest"
        assert report["total_cases"] == len(load_xstest_fixture())
        assert 0.0 <= report["over_refusal_rate"] <= 1.0
        assert 0.0 <= report["under_refusal_rate"] <= 1.0
        per_type = report["per_type"]
        assert set(per_type) == {"full_compliance", "full_refusal"}
        assert per_type["full_compliance"]["cases"] + \
            per_type["full_refusal"]["cases"] == report["total_cases"]

    def test_reference_run_over_refusal_is_zero(self):
        """Benign-canary property: the deterministic reference pipeline never
        blocks XSTest safe prompts (they contain no injection markers)."""
        report = run_xstest_benchmark(records=load_xstest_fixture())
        assert report["over_refusal_rate"] == 0.0

    def test_methodology_block_present(self):
        report = run_xstest_benchmark(records=load_xstest_fixture())
        m = report["measurement"]
        assert m["attempt_budget"] == 1
        assert m["adaptivity"] == "static"
        assert m["judge"].startswith("deterministic")
        assert m["upstream_model"] is None

    def test_render_writes_markdown(self, tmp_path):
        report = run_xstest_benchmark(records=load_xstest_fixture())
        out = tmp_path / "XSTEST.md"
        render_xstest_md(report, out)
        text = out.read_text()
        assert "XSTest" in text and "over-refusal" in text.lower()
        assert "Attempt budget" in text
        assert "full_compliance" in text and "full_refusal" in text


class TestTargetPath:
    def test_target_grading_uses_refusal_keywords(self):
        class _StubTarget:
            async def send(self, payload: str):
                from archon_core.targets.base import TargetResponse

                if "kill a Python process" in payload:
                    return TargetResponse(content="I'm sorry, I cannot help with that.")
                return TargetResponse(content="Here are the steps you asked for.")

        report = run_xstest_benchmark(
            records=load_xstest_fixture(), target=_StubTarget())
        # the stub refuses exactly one benign prompt -> measurable over-refusal
        assert 0.0 < report["over_refusal_rate"] < 1.0
        assert report["under_refusal_rate"] == 0.0
