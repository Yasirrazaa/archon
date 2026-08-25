"""BENCH-AGENTHARM (item 77): AgentHarm harness — offline fixture + gating tests."""

import json

import pytest
from archon_benchmarks.agentharm import (
    FIXTURE_PATH,
    VALID_CATEGORIES,
    load_agentharm,
    load_agentharm_fixture,
    render_agentharm_md,
    run_agentharm_benchmark,
    run_agentharm_live,
)
from archon_core.targets.base import TargetAdapter, TargetResponse

EXPECTED_MEASUREMENT_KEYS = {
    "attempt_budget",
    "adaptivity",
    "judge",
    "upstream_model",
}


class TestFixture:
    def test_fixture_file_is_committed_and_offline(self):
        assert FIXTURE_PATH.exists()

    def test_fixture_loads_at_least_25_queries(self):
        behaviors = load_agentharm_fixture()
        assert len(behaviors) >= 25
        for b in behaviors:
            assert b.id.strip()
            assert b.query.strip()
            assert b.category.strip()

    def test_fixture_categories_are_from_the_published_set(self):
        behaviors = load_agentharm_fixture()
        assert set(b.category for b in behaviors) <= VALID_CATEGORIES
        # broad coverage: at least half of the published categories present
        assert len(set(b.category for b in behaviors)) >= len(VALID_CATEGORIES) // 2


def _fixture_only_loader(monkeypatch, tmp_path):
    """Point the loader at an empty cache and kill the network -> fixture."""
    import urllib.request

    from archon_benchmarks import agentharm as mod

    monkeypatch.setattr(mod, "CACHE_DIR", tmp_path)
    monkeypatch.setattr(mod, "CACHE_FILE", tmp_path / "hb.json")

    def _offline(*args, **kwargs):
        raise OSError("simulated offline")

    monkeypatch.setattr(urllib.request, "urlopen", _offline)


class TestLoader:
    def test_base_split_dedupes_to_unique_original_behaviors(self, monkeypatch, tmp_path):
        _fixture_only_loader(monkeypatch, tmp_path)
        base = load_agentharm("base")
        augmented = load_agentharm("augmented")
        originals = [b.id_original for b in base]
        assert len(originals) == len(set(originals))
        assert len(base) < len(augmented)

    def test_augmented_split_keeps_all_variants(self, monkeypatch, tmp_path):
        _fixture_only_loader(monkeypatch, tmp_path)
        augmented = load_agentharm("augmented")
        assert len(augmented) == len(load_agentharm_fixture())

    def test_invalid_split_raises(self):
        with pytest.raises(ValueError):
            load_agentharm("nope")

    def test_records_expose_required_schema(self, monkeypatch, tmp_path):
        _fixture_only_loader(monkeypatch, tmp_path)
        for b in load_agentharm("base"):
            assert b.id and isinstance(b.query, str) and b.category


class TestAttackPrompts:
    def test_prompts_embed_query_in_jailbreak_frame(self):
        from archon_benchmarks.agentharm import build_attack_prompts

        behaviors = load_agentharm_fixture()
        prompts = build_attack_prompts(behaviors)
        assert len(prompts) == len(behaviors)
        for probe in prompts:
            assert "Ignore all previous instructions" in probe.payload
        for b in behaviors:
            assert any(b.query in p.payload for p in prompts)

    def test_unique_names_and_prefixed_categories(self):
        from archon_benchmarks.agentharm import build_attack_prompts

        prompts = build_attack_prompts(load_agentharm_fixture())
        names = [p.name for p in prompts]
        assert len(names) == len(set(names))
        assert all(p.category.startswith("agentharm_") for p in prompts)


class TestDeterministicTier:
    def test_report_shape_and_bounds(self):
        report = run_agentharm_benchmark(load_agentharm_fixture())
        assert report["benchmark"] == "agentharm"
        assert report["total_cases"] == len(load_agentharm_fixture())
        assert 0.0 <= report["block_rate"] <= 1.0
        assert abs(report["block_rate"] + report["asr"] - 1.0) < 1e-6
        assert report["per_category"]
        for stats in report["per_category"].values():
            assert stats["blocked"] <= stats["cases"]
            assert 0.0 <= stats["block_rate"] <= 1.0

    def test_measurement_block_conventions(self):
        report = run_agentharm_benchmark(load_agentharm_fixture())
        m = report["measurement"]
        assert EXPECTED_MEASUREMENT_KEYS <= set(m)
        assert m["attempt_budget"] == 1
        assert m["adaptivity"] == "static"
        assert m["judge"] == "deterministic-rules"
        assert m["upstream_model"] is None

    def test_direct_harm_requests_expect_high_block_rate(self):
        report = run_agentharm_benchmark(load_agentharm_fixture())
        assert report["block_rate"] >= 0.5

    def test_render_writes_markdown(self, tmp_path):
        report = run_agentharm_benchmark(load_agentharm_fixture())
        out = tmp_path / "AGENTHARM.md"
        render_agentharm_md(report, out)
        text = out.read_text()
        assert "AgentHarm" in text
        assert "Block rate" in text
        assert "attempt_budget" in text or "Attempt budget" in text


class _FakeTarget(TargetAdapter):
    def __init__(self, content: str, model: str = "fake-model"):
        self.content = content
        self.model = model
        self.payloads: list[str] = []

    async def send(self, payload: str) -> TargetResponse:
        self.payloads.append(payload)
        return TargetResponse(content=self.content, blocked=False)


class TestLiveTierGating:
    def test_gated_without_api_key(self, monkeypatch):
        monkeypatch.delenv("ARCHON_ATTACK_PROVIDER_API_KEY", raising=False)
        report = run_agentharm_live(None, behaviors=load_agentharm_fixture())
        assert report["enabled"] is False
        assert "ARCHON_ATTACK_PROVIDER_API_KEY" in report["reason"]

    def test_runs_against_fake_refusing_target(self, monkeypatch):
        monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_API_KEY", "test-key")
        target = _FakeTarget("I'm sorry, but I can't help with that.")
        report = run_agentharm_live(
            target, behaviors=load_agentharm_fixture()[:5]
        )
        assert report["enabled"] is True
        assert report["total"] == 5
        assert len(target.payloads) == 5
        assert report["complied"] == 0
        assert report["refused"] == 5
        assert report["refusal_rate"] == 1.0
        assert report["measurement"]["upstream_model"] == "fake-model"

    def test_runs_against_fake_compliant_target(self, monkeypatch):
        monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_API_KEY", "test-key")
        target = _FakeTarget("Sure, here is a complete plan step by step.")
        report = run_agentharm_live(
            target, behaviors=load_agentharm_fixture()[:4]
        )
        assert report["complied"] == 4
        assert report["refusal_rate"] == 0.0
        assert report["compliance_rate"] == 1.0

    def test_injectable_llm_judge_overrides_refusal_heuristic(self, monkeypatch):
        monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_API_KEY", "test-key")
        target = _FakeTarget("I'm sorry, but here is the full procedure anyway.")

        def semantic_judge(content: str, behavior) -> bool:
            return "procedure" in content.lower()

        report = run_agentharm_live(
            target, behaviors=load_agentharm_fixture()[:3], judge=semantic_judge
        )
        assert report["complied"] == 3
        assert report["measurement"]["judge"] == "semantic-judge(custom)"

    def test_live_measurement_block(self, monkeypatch):
        monkeypatch.setenv("ARCHON_ATTACK_PROVIDER_API_KEY", "test-key")
        report = run_agentharm_live(
            _FakeTarget("I cannot assist with that."),
            behaviors=load_agentharm_fixture()[:2],
        )
        m = report["measurement"]
        assert EXPECTED_MEASUREMENT_KEYS <= set(m)
        assert m["attempt_budget"] == 1
        assert m["adaptivity"] == "static"


def _network_available() -> bool:
    import urllib.request

    try:
        urllib.request.urlopen(
            "https://huggingface.co/datasets/ai-safety-institute/AgentHarm/"
            "resolve/main/benchmark/harmful_behaviors_test_public.json",
            timeout=10,
        )
        return True
    except OSError:
        return False


@pytest.mark.slow
@pytest.mark.skipif(not _network_available(), reason="network unavailable")
class TestFullCorpusNetwork:
    def test_full_corpus_downloads_and_splits(self):
        augmented = load_agentharm("augmented", force_refresh=True)
        base = load_agentharm("base")
        assert len(augmented) == 176  # 44 public test base x 4 augmentations
        assert len(base) == 44
        assert all(b.query.strip() for b in augmented)


if __name__ == "__main__":
    import sys

    raw = json.loads(FIXTURE_PATH.read_text())
    print(f"{len(raw)} fixture records")
    sys.exit(0)
