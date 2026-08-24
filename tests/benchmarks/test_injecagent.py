"""W9-A: InjecAgent benchmark harness — offline fixture tests + network-gated corpus."""

import json

import pytest
from archon_benchmarks.injecagent import (
    FIXTURE_PATH,
    build_attack_prompts,
    load_injecagent_fixture,
    render_injecagent_md,
    run_injecagent_benchmark,
)

SCHEMA_FIELDS = (
    "Attacker Tools",
    "Attacker Instruction",
    "Attack Type",
    "User Tool",
    "User Instruction",
    "Tool Parameters",
    "Tool Response Template",
    "Tool Response",
)


class TestFixture:
    def test_fixture_file_is_committed_and_offline(self):
        assert FIXTURE_PATH.exists()

    def test_fixture_loads_without_network(self):
        cases = load_injecagent_fixture()
        assert len(cases) >= 10
        settings = {c.setting for c in cases}
        assert settings == {"direct_harm", "data_stealing"}

    def test_schema_fields_present(self):
        raw = json.loads(FIXTURE_PATH.read_text())
        for record in raw:
            for field in SCHEMA_FIELDS:
                assert field in record, f"missing {field}"

    def test_every_case_has_content(self):
        for case in load_injecagent_fixture():
            assert case.user_instruction.strip()
            assert case.attacker_instruction.strip()
            assert case.tool_response.strip()
            assert case.user_tool.strip()


class TestAttackPrompts:
    def test_prompts_contain_attacker_instruction_and_tool_knowledge(self):
        prompts = build_attack_prompts(load_injecagent_fixture())
        assert prompts
        cases = load_injecagent_fixture()
        for probe in prompts:
            assert probe.payload.strip()
            matching = [c for c in cases
                        if c.attacker_instruction in probe.payload]
            assert matching, "attacker instruction missing from payload"
            # tool knowledge: the user tool's response context is embedded
            assert any(c.tool_response[:80] in probe.payload or
                       c.user_tool in probe.payload for c in matching)

    def test_unique_names(self):
        prompts = build_attack_prompts(load_injecagent_fixture())
        names = [p.name for p in prompts]
        assert len(names) == len(set(names))

    def test_category_split(self):
        prompts = build_attack_prompts(load_injecagent_fixture())
        categories = {p.category for p in prompts}
        assert categories == {"injecagent_direct", "injecagent_indirect"}


class TestBenchmarkRun:
    def test_report_shape_and_bounds(self):
        report = run_injecagent_benchmark(cases=load_injecagent_fixture())
        assert report["benchmark"] == "injecagent"
        assert report["total_cases"] == 12
        assert 0.0 <= report["block_rate"] <= 1.0
        assert 0.0 <= report["asr"] <= 1.0
        assert report["blocked"] + int(report["asr"] * 12) >= 0
        per_setting = report["per_setting"]
        assert set(per_setting) == {"direct", "indirect"}
        direct = per_setting["direct"]
        indirect = per_setting["indirect"]
        assert direct["cases"] == 6 and indirect["cases"] == 6
        for stats in (direct, indirect):
            assert stats["blocked"] <= stats["cases"]
            assert 0.0 <= stats["block_rate"] <= 1.0
            assert 0.0 <= stats["asr"] <= 1.0

    def test_methodology_block_present(self):
        report = run_injecagent_benchmark(cases=load_injecagent_fixture())
        m = report["measurement"]
        assert m["attempt_budget"] == 1
        assert m["adaptivity"] == "static"
        assert m["judge"] == "deterministic-rules"

    def test_render_writes_markdown(self, tmp_path):
        report = run_injecagent_benchmark(cases=load_injecagent_fixture())
        out = tmp_path / "INJECAGENT.md"
        render_injecagent_md(report, out)
        text = out.read_text()
        assert "InjecAgent" in text and "ASR" in text
        assert "attempt_budget" in text or "Attempt budget" in text
        assert "direct" in text and "indirect" in text


def _network_available() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(
            "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/"
            "data/test_cases_dh_base.json", timeout=10)
        return True
    except OSError:
        return False


@pytest.mark.slow
@pytest.mark.skipif(not _network_available(), reason="network unavailable")
class TestFullCorpusNetwork:
    def test_full_corpus_loads_1054_cases(self):
        from archon_benchmarks.injecagent import load_injecagent_cases
        cases = load_injecagent_cases(force_refresh=True)
        assert len(cases) == 1054
        dh = sum(1 for c in cases if c.setting == "direct_harm")
        ds = sum(1 for c in cases if c.setting == "data_stealing")
        assert (dh, ds) == (510, 544)
