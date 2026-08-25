"""Sprint BENCH-TAUBENCH: tau-bench task loader + deterministic policy-probe tier.

Offline tests only — the committed fixture is the single source of truth.
Full tau-bench pass^k needs its LLM user-simulator + tool env and is
deliberately NOT stubbed here (see module docstring of taubench.py).
"""

import json

import pytest
from archon_benchmarks.taubench import (
    FIXTURE_PATH,
    TaubenchTask,
    build_policy_probes,
    extract_policy_rules,
    load_taubench,
    load_taubench_fixture,
    parse_tasks_source,
    render_taubench_md,
    run_taubench_policy_probe,
)


class TestFixture:
    def test_fixture_file_is_committed_and_offline(self):
        assert FIXTURE_PATH.exists()
        raw = json.loads(FIXTURE_PATH.read_text())
        assert raw["domain"] == "retail"
        assert len(raw["tasks"]) >= 15

    def test_fixture_loads_without_network(self):
        records = load_taubench_fixture()
        assert len(records) >= 15
        assert all(isinstance(r, TaubenchTask) for r in records)

    def test_records_have_required_fields(self):
        for r in load_taubench_fixture():
            assert r.task_id.startswith("retail_")
            assert r.user_instruction.strip()
            assert isinstance(r.policies, tuple) and len(r.policies) >= 10
            assert isinstance(r.actions, list)

    def test_unique_task_ids(self):
        ids = [r.task_id for r in load_taubench_fixture()]
        assert len(ids) == len(set(ids))

    def test_policies_are_domain_level_shared_rules(self):
        records = load_taubench_fixture()
        first = records[0].policies
        assert all(r.policies == first for r in records)
        assert any("authenticate" in p.lower() for p in first)


class TestParsing:
    def test_parse_tasks_source_extracts_literal_list(self):
        src = 'tasks = [{"instruction": "hi", "actions": [], "annotator": 1}]'
        tasks = parse_tasks_source(src)
        assert tasks == [{"instruction": "hi", "actions": [], "annotator": 1}]

    def test_extract_policy_rules_from_wiki_md(self):
        wiki = (
            "# Retail agent policy\n\n"
            "- Rule one about authentication.\n"
            "## Section\n"
            "- Rule two about cancellations.\n"
            "Not a rule line.\n"
        )
        rules = extract_policy_rules(wiki)
        assert rules == [
            "- Rule one about authentication.",
            "- Rule two about cancellations.",
        ]


class TestLoader:
    def test_load_taubench_offline_falls_back_to_fixture(
self, monkeypatch):
        import archon_benchmarks.taubench as mod

        def _boom(*_a, **_k):
            raise OSError("no network")

        monkeypatch.setattr(mod, "_fetch", _boom)
        monkeypatch.setattr(
            mod, "CACHE_DIR", mod.CACHE_DIR.__class__(
mod.FIXTURE_PATH.parent / "no-cache-here")
        )
        records = load_taubench(domain="retail")
        assert len(records) >= 15

    def test_load_unknown_domain_offline_raises(self, monkeypatch):
        import archon_benchmarks.taubench as mod

        monkeypatch.setattr(mod, "CACHE_DIR", mod.CACHE_DIR.__class__(
mod.FIXTURE_PATH.parent / "no-cache-here"))
        with pytest.raises(FileNotFoundError):
            load_taubench(domain="telecom")


class TestProbeBuilding:
    def test_names_unique_and_categories_tagged(self):
        probes = build_policy_probes(load_taubench_fixture())
        names = [p.name for p in probes]
        assert len(names) == len(set(names))
        assert {p.category for p in probes} == {"taubench_retail_policy_violation"}

    def test_payload_embeds_instruction_and_violation(self):
        probes = build_policy_probes(load_taubench_fixture())
        assert all(p.payload.strip() for p in probes)
        assert all("policy violation probe" in p.payload.lower() for p in probes)

    def test_violation_templates_keyed_by_intent(self):
        base = {
            "task_id": "retail_x",
            "user_instruction": "",
            "actions": [],
            "outputs": [],
        }
        cancel = dict(base, user_instruction="Please cancel my order #W1.")
        ret = dict(base, user_instruction="I want to return the headphones.")
        pc = build_policy_probes([TaubenchTask(**cancel, policies=())])
        pr = build_policy_probes([TaubenchTask(**ret, policies=())])
        assert "cancel" in pc[0].payload.lower()
        assert "refund" in pr[0].payload.lower()
        assert pc[0].payload != pr[0].payload


class TestPolicyProbeRun:
    def test_report_shape_and_bounds(self):
        report = run_taubench_policy_probe(records=load_taubench_fixture())
        assert report["benchmark"] == "taubench_policy_probe"
        assert report["domain"] == "retail"
        assert report["total_tasks"] == len(load_taubench_fixture())
        assert report["probes_sent"] == len(load_taubench_fixture())
        assert 0.0 <= report["block_rate"] <= 1.0
        assert 0.0 <= report["asr"] <= 1.0
        assert report["policies_parsed"] >= 10

    def test_measurement_block_conventions(self):
        report = run_taubench_policy_probe(records=load_taubench_fixture())
        m = report["measurement"]
        assert m["attempt_budget"] == 1
        assert m["adaptivity"] == "static"
        assert m["judge"].startswith("deterministic")
        assert m["upstream_model"] is None

    def test_deterministic_reruns_identical(self):
        a = run_taubench_policy_probe(records=load_taubench_fixture())
        b = run_taubench_policy_probe(records=load_taubench_fixture())
        assert a == b


class TestRenderer:
    def test_render_writes_markdown(self, tmp_path):
        report = run_taubench_policy_probe(records=load_taubench_fixture())
        out = tmp_path / "TAUBENCH.md"
        text = render_taubench_md(report, out)
        assert out.exists()
        assert "tau-bench" in text.lower()
        assert "policy" in text.lower()
        assert "user-simulator" in text.lower() or "user simulator" in text.lower()
        assert f"{report['total_tasks']}" in text
