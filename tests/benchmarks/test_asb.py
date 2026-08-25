"""BENCH-ASB: Agent Security Bench (ASB, agiresearch/ASB, arXiv:2410.02644)
direct-injection harness — offline fixture tests + network-gated full corpus.

NOTE: this is the *Agent Security Bench* used by the AgentFlow/APC papers
(ICLR 2025), NOT Agent-SafetyBench (covered by test_asb_safety.py).
"""

import json

import pytest
from archon_benchmarks.asb import (
    CACHE_DIR,
    FIXTURE_PATH,
    build_attack_prompts,
    load_asb,
    load_asb_fixture,
    render_asb_md,
    run_asb_benchmark,
)

ATTACK_TYPES = {"Stealthy Attack", "Disruptive Attack"}


class TestFixture:
    def test_fixture_file_is_committed_and_offline(self):
        assert FIXTURE_PATH.exists()
        assert "asb_security_fixture" in FIXTURE_PATH.name  # not asb_safety's

    def test_fixture_has_at_least_20_cases_with_task_and_attack(self):
        raw = json.loads(FIXTURE_PATH.read_text())
        assert len(raw) >= 20
        for record in raw:
            assert record["user_task"].strip()
            assert record["attacker_instruction"].strip()
            assert record["attacker_tool"].strip()

    def test_fixture_attack_types_are_official_taxonomy(self):
        cases = load_asb_fixture()
        assert {c.attack_type for c in cases} <= ATTACK_TYPES
        assert len({c.agent for c in cases}) >= 5  # multi-domain coverage

    def test_load_asb_mode_validation(self):
        with pytest.raises(ValueError):
            load_asb(mode="memory_poisoning")


class TestAttackPrompts:
    def test_prompts_embed_user_task_and_direct_injection(self):
        cases = load_asb_fixture()
        probes = build_attack_prompts(cases)
        assert len(probes) == len(cases)
        for case, probe in zip(cases, probes):
            assert case.user_task in probe.payload
            assert case.attacker_instruction in probe.payload

    def test_unique_names_and_dpi_categories(self):
        probes = build_attack_prompts(load_asb_fixture())
        names = [p.name for p in probes]
        assert len(names) == len(set(names))
        assert all(p.category.startswith("asb_dpi") for p in probes)


class TestBenchmarkRun:
    def test_report_shape_and_bounds(self):
        report = run_asb_benchmark(cases=load_asb_fixture())
        assert report["benchmark"] == "asb"
        n = len(load_asb_fixture())
        assert report["total_cases"] == n
        assert 0.0 <= report["block_rate"] <= 1.0
        assert report["block_rate"] == pytest.approx(1.0 - report["asr"])
        per_type = report["per_attack_type"]
        assert set(per_type) == {"stealthy", "disruptive"}
        for stats in per_type.values():
            assert stats["cases"] > 0
            assert stats["blocked"] <= stats["cases"]

    def test_measurement_block_discloses_methodology(self):
        report = run_asb_benchmark(cases=load_asb_fixture())
        m = report["measurement"]
        assert m["attempt_budget"] == 1
        assert m["adaptivity"] == "static"
        assert m["judge"] == "deterministic-rules"
        assert m["upstream_model"] is None

    def test_artifact_status_honest_disclosure(self):
        report = run_asb_benchmark(
            cases=load_asb_fixture(), fixture_only=True)
        status = report["artifact_status"]
        assert status["fixture_only_run"] is True
        assert status["official_repo"] == "https://github.com/agiresearch/ASB"
        assert "surrogate" not in status["provenance"].lower() or \
            "official" in status["provenance"].lower()

    def test_render_writes_markdown(self, tmp_path):
        report = run_asb_benchmark(cases=load_asb_fixture())
        out = tmp_path / "ASB.md"
        render_asb_md(report, out)
        text = out.read_text()
        assert "Security Bench" in text and "ASR" in text
        assert "stealthy" in text and "disruptive" in text


def _network_available() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(
            "https://raw.githubusercontent.com/agiresearch/ASB/main/"
            "data/all_attack_tools.jsonl", timeout=10)
        return True
    except OSError:
        return False


@pytest.mark.slow
@pytest.mark.skipif(not _network_available(), reason="network unavailable")
class TestFullCorpusNetwork:
    def test_full_corpus_loads_400_attacks(self):
        cases = load_asb(force_refresh=True)
        assert len(cases) == 400
        assert {c.attack_type for c in cases} == ATTACK_TYPES
        assert CACHE_DIR.exists()
