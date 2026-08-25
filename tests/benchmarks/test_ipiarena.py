"""BENCH-IPIARENA: IPIArena loader + deterministic benchmark — offline tests."""

import json

import pytest
from archon_benchmarks.ipiarena import (
    FIXTURE_PATH,
    build_attack_prompts,
    load_ipiarena_fixture,
    render_ipiarena_md,
    run_ipiarena_benchmark,
)

SCHEMA_FIELDS = ("id", "name", "category", "wave", "user_task",
                 "injection_goal", "injection_slot")
CATEGORIES = {"tool", "coding", "browser"}
SLOTS = {"tool_response", "user_content", "assistant_content", "html_page",
         "unspecified"}


class TestFixture:
    def test_fixture_file_is_committed_and_offline(self):
        assert FIXTURE_PATH.exists()
        records = json.loads(FIXTURE_PATH.read_text())
        assert len(records) >= 15

    def test_all_three_categories_present(self):
        records = load_ipiarena_fixture()
        assert {r.category for r in records} == CATEGORIES

    def test_schema_fields_present_and_non_empty(self):
        raw = json.loads(FIXTURE_PATH.read_text())
        for record in raw:
            for field in SCHEMA_FIELDS:
                assert field in record, f"missing {field}"
            assert record["user_task"].strip()
            assert record["injection_goal"].strip()

    def test_injection_slots_are_known_values(self):
        records = load_ipiarena_fixture()
        slots = {r.injection_slot for r in records}
        assert slots <= SLOTS
        # the canonical indirect surface must dominate
        assert "tool_response" in slots or "html_page" in slots

    def test_unique_ids(self):
        records = load_ipiarena_fixture()
        ids = [r.id for r in records]
        assert len(ids) == len(set(ids))


class TestAttackPrompts:
    def test_payload_embeds_user_task_and_injection_goal(self):
        records = load_ipiarena_fixture()
        prompts = build_attack_prompts(records)
        assert len(prompts) == len(records)
        by_name = {p.name: p for p in prompts}
        for record in records:
            probe = by_name[f"ipiarena_{record.category}_{record.id}"]
            assert record.user_task[:200] in probe.payload
            assert record.injection_goal[:100] in probe.payload
            assert record.injection_slot in probe.payload

    def test_categories_map_to_probe_category(self):
        prompts = build_attack_prompts(load_ipiarena_fixture())
        expected = {f"ipiarena_{c}" for c in CATEGORIES}
        assert {p.category for p in prompts} == expected


class TestBenchmarkRun:
    def test_report_shape_bounds_and_per_category(self):
        report = run_ipiarena_benchmark(
            records=load_ipiarena_fixture())
        assert report["benchmark"] == "ipiarena"
        assert report["total_cases"] == 41
        assert 0.0 <= report["block_rate"] <= 1.0
        assert 0.0 <= report["asr"] <= 1.0
        assert set(report["per_category"]) == CATEGORIES
        for stats in report["per_category"].values():
            assert stats["blocked"] <= stats["cases"]
            assert 0.0 <= stats["block_rate"] <= 1.0

    def test_measurement_block_discloses_methodology(self):
        report = run_ipiarena_benchmark(records=load_ipiarena_fixture())
        m = report["measurement"]
        assert m["attempt_budget"] == 1
        assert m["adaptivity"] == "static"
        assert m["judge"] == "deterministic-rules"
        assert m["upstream_model"] is None

    def test_artifact_status_is_honest_about_provenance(self):
        report = run_ipiarena_benchmark(records=load_ipiarena_fixture())
        assert report["artifact_status"] == "official"
        assert "PIMiner" in report["artifact_source"]

    def test_deterministic_reproducibility(self):
        a = run_ipiarena_benchmark(records=load_ipiarena_fixture())
        b = run_ipiarena_benchmark(records=load_ipiarena_fixture())
        assert a == b

    def test_render_writes_markdown_with_artifact_disclosure(self, tmp_path):
        report = run_ipiarena_benchmark(records=load_ipiarena_fixture())
        out = tmp_path / "IPIARENA.md"
        render_ipiarena_md(report, out)
        text = out.read_text()
        assert "IPIArena" in text
        assert "attempt budget" in text.lower()
        for category in CATEGORIES:
            assert category in text
        assert "official" in text.lower()


def _network_available() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(
            "https://api.github.com/repos/wang-yanting/PIMiner", timeout=10)
        return True
    except OSError:
        return False


@pytest.mark.slow
@pytest.mark.skipif(not _network_available(), reason="network unavailable")
class TestOfficialArtifactNetwork:
    def test_full_loader_fetches_official_behaviors(self):
        from archon_benchmarks.ipiarena import load_ipiarena
        records = load_ipiarena(force_refresh=True)
        assert len(records) >= 41
        assert {r.category for r in records} == CATEGORIES
