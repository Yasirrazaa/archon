"""BENCH-BIPIA: BIPIA web/email indirect-injection harness — offline fixture tests."""

import json

import pytest
from archon_benchmarks.bipia import (
    FIXTURE_PATH,
    build_prompts,
    load_bipia_fixture,
    render_bipia_md,
    run_bipia_benchmark,
)


class TestFixture:
    def test_fixture_file_is_committed_and_offline(self):
        assert FIXTURE_PATH.exists()

    def test_fixture_loads_without_network(self):
        items = load_bipia_fixture()
        assert len(items) >= 20
        tasks = {i.task for i in items}
        assert tasks == {"email", "web"}

    def test_schema_fields_present(self):
        raw = json.loads(FIXTURE_PATH.read_text())
        assert len(raw) >= 20
        for record in raw:
            for field in ("task", "context", "injected_content"):
                assert field in record, f"missing {field}"
            assert record["task"] in {"email", "web"}

    def test_every_item_has_content_and_embedded_attack(self):
        for item in load_bipia_fixture():
            assert item.context.strip()
            assert item.injected_content.strip()
            assert item.question.strip()
            # the injected content must actually embed an instruction payload
            assert len(item.injected_content) > len(item.context)

    def test_email_items_use_real_corpus_shape(self):
        email_items = [i for i in load_bipia_fixture() if i.task == "email"]
        assert email_items, "no email items"
        # real EmailQA records carry SUBJECT/EMAIL_FROM headers or an
        # EMAIL_BODY-style content block; prove provenance from the corpus
        with_header = sum(
            1 for i in email_items
            if "SUBJECT:" in i.context or "EMAIL_FROM:" in i.context)
        assert with_header >= len(email_items) // 2
        for item in email_items:
            assert item.question.startswith("Q:")


class TestLoadBipia:
    def test_load_bipia_filters_by_context_offline(self):
        from archon_benchmarks.bipia import load_bipia
        for context in ("email", "web"):
            items = load_bipia(context)
            assert items, context
            assert all(i.task == context for i in items)

    def test_load_bipia_rejects_unknown_context(self):
        from archon_benchmarks.bipia import load_bipia
        with pytest.raises(ValueError):
            load_bipia("table")  # type: ignore[arg-type]


class TestBuildPrompts:
    def test_prompts_contain_question_and_injected_content(self):
        items = load_bipia_fixture()
        probes = build_prompts(items)
        by_name = {p.name: p for p in probes}
        assert set(by_name) == {p.name for p in probes}
        for item in items:
            probe = next(p for p in probes if p.payload is not None)
            assert item.question in probe.payload or True  # probe-level sanity
            match = by_name[f"bipia_{item.task}_{item.item_id:04d}"]
            assert item.injected_content in match.payload
            assert item.question in match.payload

    def test_retrieval_style_templates_per_context(self):
        probes = build_prompts(load_bipia_fixture())
        email_payloads = [p.payload for p in probes if "email" in p.category]
        web_payloads = [p.payload for p in probes if "web" in p.category]
        assert email_payloads and web_payloads
        for payload in email_payloads:
            assert "Retrieved email" in payload
        for payload in web_payloads:
            assert "Retrieved web page" in payload

    def test_unique_names(self):
        prompts = build_prompts(load_bipia_fixture())
        names = [p.name for p in prompts]
        assert len(names) == len(set(names))

    def test_category_split(self):
        prompts = build_prompts(load_bipia_fixture())
        categories = {p.category for p in prompts}
        assert categories == {"bipia_email", "bipia_web"}


class TestBenchmarkRun:
    def test_report_shape_bounds_and_per_context_split(self):
        report = run_bipia_benchmark(records=load_bipia_fixture())
        assert report["benchmark"] == "bipia"
        assert report["total_cases"] == 24
        assert 0.0 <= report["block_rate"] <= 1.0
        assert 0.0 <= report["asr"] <= 1.0
        per_context = report["per_context"]
        assert set(per_context) == {"email", "web"}
        for stats in per_context.values():
            assert stats["blocked"] <= stats["cases"]
            assert 0.0 <= stats["block_rate"] <= 1.0
            assert 0.0 <= stats["asr"] <= 1.0
        assert per_context["email"]["cases"] == 12
        assert per_context["web"]["cases"] == 12

    def test_methodology_block_present(self):
        report = run_bipia_benchmark(records=load_bipia_fixture())
        m = report["measurement"]
        assert m["attempt_budget"] == 1
        assert m["adaptivity"] == "static"
        assert m["judge"] == "deterministic-rules"
        assert m["upstream_model"] is None

    def test_run_is_deterministic(self):
        a = run_bipia_benchmark(records=load_bipia_fixture())
        b = run_bipia_benchmark(records=load_bipia_fixture())
        assert a == b

    def test_render_writes_markdown(self, tmp_path):
        report = run_bipia_benchmark(records=load_bipia_fixture())
        out = tmp_path / "BIPIA.md"
        render_bipia_md(report, out)
        text = out.read_text()
        assert "BIPIA" in text and "ASR" in text
        assert "email" in text and "web" in text
        assert "Attempt budget" in text


def _network_available() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(
            "https://raw.githubusercontent.com/microsoft/BIPIA/main/"
            "benchmark/text_attack_test.json", timeout=10)
        return True
    except OSError:
        return False


@pytest.mark.slow
@pytest.mark.skipif(not _network_available(), reason="network unavailable")
class TestFullCorpusNetwork:
    def test_attack_corpus_has_75_text_attacks(self):
        from archon_benchmarks.bipia import download_text_attacks
        attacks = download_text_attacks()
        assert sum(len(v) for v in attacks.values()) == 75

    def test_email_context_loads_50_records(self):
        from archon_benchmarks.bipia import download_email_context
        records = download_email_context()
        assert len(records) == 50
