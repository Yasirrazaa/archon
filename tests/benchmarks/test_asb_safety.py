"""Sprint BENCH-ASB-SAFETY: Agent-SafetyBench harness — offline fixture tests + network-gated corpus."""

import json

import pytest
from archon_benchmarks.asb_safety import (
    FIXTURE_PATH,
    RISK_CATEGORY_SLUGS,
    build_attack_prompts,
    load_asb,
    load_asb_fixture,
    render_asb_md,
    run_asb_benchmark,
)

EXPECTED_CATEGORIES = {
    "Leak sensitive data / information",
    "Lead to property loss",
    "Spread unsafe information / misinformation",
    "Lead to physical harm",
    "Violate law or ethics / damage society",
    "Compromise availability",
    "Contribute to harmful / vulnerable code",
    "Produce unsafe information / misinformation",
}
EXPECTED_SLUGS = {
    "leak_sensitive_data",
    "property_loss",
    "spread_misinformation",
    "physical_harm",
    "violate_law_ethics",
    "compromise_availability",
    "harmful_code",
    "produce_unsafe_info",
}


class TestFixture:
    def test_fixture_file_is_committed_and_offline(self):
        assert FIXTURE_PATH.exists()

    def test_fixture_loads_at_least_30_cases(self):
        cases = load_asb_fixture()
        assert len(cases) >= 30

    def test_fixture_covers_all_published_risk_categories(self):
        cases = load_asb_fixture()
        assert {c.category for c in cases} == EXPECTED_CATEGORIES

    def test_slug_map_is_bijective_with_published_categories(self):
        assert set(RISK_CATEGORY_SLUGS) == EXPECTED_CATEGORIES
        assert set(RISK_CATEGORY_SLUGS.values()) == EXPECTED_SLUGS

    def test_every_case_has_content(self):
        for case in load_asb_fixture():
            assert isinstance(case.case_id, int)
            assert case.prompt.strip()
            assert case.failure_modes.strip()


class TestLoadAsb:
    def test_load_asb_offline_falls_back_to_fixture(self, monkeypatch):
        def _boom():
            raise OSError("offline")

        monkeypatch.setattr("archon_benchmarks.asb_safety._download", lambda: _boom())
        monkeypatch.delenv("http_proxy", raising=False)
        # ensure no cache file short-circuits: point CACHE_DIR at tmp
        from archon_benchmarks import asb_safety as mod

        cache = mod.CACHE_DIR / mod.CORPUS_FILENAME
        if cache.exists():
            backup = cache.with_suffix(".bak")
            cache.rename(backup)
            try:
                cases = load_asb(force_refresh=False)
            finally:
                backup.rename(cache)
        else:
            cases = load_asb(force_refresh=False)
        fixture = load_asb_fixture()
        assert [c.case_id for c in cases] == [c.case_id for c in fixture]

    def test_category_filter(self):
        cases = load_asb("Lead to physical harm")
        assert cases and all(c.category == "Lead to physical harm" for c in cases)

    def test_category_filter_by_slug(self):
        cases = load_asb("physical_harm")
        assert cases and all(c.category == "Lead to physical harm" for c in cases)


class TestAttackPrompts:
    def test_prompts_embed_instruction_and_environment_context(self):
        cases = load_asb_fixture()
        prompts = build_attack_prompts(cases)
        assert len(prompts) == len(cases)
        by_name = {p.name: p for p in prompts}
        for case in cases:
            probe = by_name[f"asb_{RISK_CATEGORY_SLUGS[case.category]}_{case.case_id:04d}"]
            assert case.prompt[:80] in probe.payload

    def test_unique_probe_names_and_categories(self):
        prompts = build_attack_prompts(load_asb_fixture())
        names = [p.name for p in prompts]
        assert len(names) == len(set(names))
        cats = {p.category for p in prompts}
        assert cats == {f"asb_{s}" for s in EXPECTED_SLUGS}


class TestBenchmarkRun:
    def test_report_shape_bounds_and_per_category(self):
        report = run_asb_benchmark(records=load_asb_fixture())
        assert report["benchmark"] == "agent-safetybench"
        assert report["total_cases"] == 40
        assert 0.0 <= report["block_rate"] <= 1.0
        assert 0.0 <= report["asr"] <= 1.0
        per_cat = report["per_category"]
        assert set(per_cat) == EXPECTED_SLUGS
        for stats in per_cat.values():
            assert stats["cases"] == 5
            assert 0 <= stats["blocked"] <= stats["cases"]
            assert 0.0 <= stats["block_rate"] <= 1.0

    def test_methodology_block(self):
        report = run_asb_benchmark(records=load_asb_fixture())
        m = report["measurement"]
        assert m["attempt_budget"] == 1
        assert m["adaptivity"] == "static"
        assert m["judge"] == "deterministic-rules"
        assert m["upstream_model"] is None

    def test_fpr_guard_reports_absence_of_benign_samples_honestly(self):
        report = run_asb_benchmark(records=load_asb_fixture())
        fpr = report["false_positive_rate"]
        assert fpr["benign_cases"] == 0
        assert fpr["false_positive_rate"] is None
        assert "not included" in fpr["note"]

    def test_fpr_guard_computes_rate_when_benign_present(self):
        benign = [
            {"case_id": 9001, "category": "benign", "prompt":
             "What is the weather forecast for today?", "failure_modes": ""},
        ] * 3 + list(load_asb_fixture())
        report = run_asb_benchmark(records=benign)
        fpr = report["false_positive_rate"]
        assert fpr["benign_cases"] == 3
        assert 0.0 <= fpr["false_positive_rate"] <= 1.0

    def test_deterministic_reproducibility(self):
        a = run_asb_benchmark(records=load_asb_fixture())
        b = run_asb_benchmark(records=load_asb_fixture())
        assert a == b

    def test_artifact_status_is_honest(self):
        report = run_asb_benchmark(records=load_asb_fixture())
        status = report["artifact_status"]
        assert status["fixture_only_run"] is True
        assert status["published_risk_categories"] == 8
        assert "8 risk categories" in status["note"]

    def test_render_writes_markdown(self, tmp_path):
        report = run_asb_benchmark(records=load_asb_fixture())
        out = tmp_path / "ASB_SAFETY.md"
        render_asb_md(report, out)
        text = out.read_text()
        assert "Agent-SafetyBench" in text
        assert "Block rate" in text or "block rate" in text.lower()
        assert "attempt budget" in text.lower() or "Attempt budget" in text
        assert "leak_sensitive_data" in text


def _network_available() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(
            "https://raw.githubusercontent.com/thu-coai/Agent-SafetyBench/main/"
            "data/released_data.json", timeout=10)
        return True
    except OSError:
        return False


@pytest.mark.slow
@pytest.mark.skipif(not _network_available(), reason="network unavailable")
class TestFullCorpusNetwork:
    def test_full_corpus_loads_2000_cases_across_8_categories(self):
        raw = json.loads(json.dumps([c.__dict__ for c in load_asb(force_refresh=True)]))
        assert len(raw) == 2000
        assert {c["category"] for c in raw} == EXPECTED_CATEGORIES
