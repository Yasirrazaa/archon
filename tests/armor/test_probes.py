"""TDD P1.1: structured probe packs with OWASP LLM Top-10 coverage matrix."""

import pytest

from archon_armor.probes import (
    Probe,
    get_pack,
    list_packs,
    PROBE_PACKS,
    UnknownPackError,
)
from archon_armor.battles import BattleManager
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry


class TestProbePacks:
    def test_core_pack_exists_with_control(self):
        core = get_pack("core")
        assert any(p.name == "benign_control" for p in core)

    def test_all_packs_have_unique_names_and_categories(self):
        for pack_name in list_packs():
            probes = get_pack(pack_name)
            assert len(probes) > 0
            names = [p.name for p in probes]
            assert len(names) == len(set(names)), f"duplicate probe in {pack_name}"
            assert all(p.category for p in probes)

    def test_owasp_pack_covers_key_llm_top10_categories(self):
        owasp = get_pack("owasp_llm_10")
        categories = {p.category for p in owasp}
        for required in ("LLM01_prompt_injection", "LLM02_sensitive_disclosure",
                         "LLM07_system_prompt_leakage"):
            assert required in categories, f"missing {required}"

    def test_unknown_pack_raises(self):
        with pytest.raises(UnknownPackError):
            get_pack("nope")

    def test_no_probe_is_empty(self):
        for pack_name in list_packs():
            assert all(p.payload.strip() for p in get_pack(pack_name))


class TestCorpusBreadth:
    """P0 backlog: probe corpus must rival scanner-grade breadth."""

    def test_total_corpus_exceeds_50_probes(self):
        total = sum(len(get_pack(name)) for name in list_packs())
        assert total >= 50, f"corpus too thin: {total}"

    def test_owasp_pack_spans_all_ten_categories(self):
        categories = {p.category for p in get_pack("owasp_llm_10")}
        expected = {
            "LLM01_prompt_injection", "LLM02_sensitive_disclosure",
            "LLM03_supply_chain", "LLM04_data_model_poisoning",
            "LLM05_improper_output_handling", "LLM06_excessive_agency",
            "LLM07_system_prompt_leakage", "LLM08_vector_embedding_weaknesses",
            "LLM09_misinformation", "LLM10_unbounded_consumption",
        }
        missing = expected - categories
        assert not missing, f"categories missing from owasp_llm_10: {missing}"

    def test_every_category_has_at_least_three_probes(self):
        counts: dict[str, int] = {}
        for p in get_pack("owasp_llm_10"):
            counts[p.category] = counts.get(p.category, 0) + 1
        thin = {c: n for c, n in counts.items() if c != "benign" and n < 3}
        assert not thin, f"categories with fewer than 3 probes: {thin}"

    def test_payloads_unique_within_each_pack(self):
        # NOTE: core intentionally overlaps owasp_llm_10 (it is a distilled
        # subset); duplication is only a defect inside a single pack.
        for name in list_packs():
            keys = [p.payload.strip().lower() for p in get_pack(name)]
            assert len(keys) == len(set(keys)), f"duplicate payload in {name}"

    def test_all_llm01_probes_blocked_by_reference_pipeline(self):
        """Invariant extended to the whole corpus: canonical injections must block."""
        import asyncio

        manager = self._manager()
        battle = manager.create("a1")
        pack = [p for p in get_pack("owasp_llm_10")
                if p.category == "LLM01_prompt_injection"]
        assert len(pack) >= 6, "LLM01 family should have grown"
        asyncio.run(manager.execute(battle.battle_id, probes=pack))
        blocked = battle.summary["coverage"]["LLM01_prompt_injection"]["blocked"]
        assert blocked == len(pack), (
            f"reference pipeline missed {len(pack) - blocked}/{len(pack)} LLM01 probes"
        )

    def _manager(self):
        registry = InMemoryRegistry()
        registry.register(AgentCard(
            agent_id="a1", name="t", version="1",
            policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
        return BattleManager(registry)


class TestCoverageMatrix:
    def _manager(self):
        registry = InMemoryRegistry()
        registry.register(AgentCard(
            agent_id="a1", name="t", version="1",
            policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
        return BattleManager(registry)

    def test_battle_summary_includes_coverage_matrix(self):
        manager = self._manager()
        battle = manager.create("a1")
        import asyncio
        asyncio.run(manager.execute(battle.battle_id, probes=get_pack("core")))

        cov = battle.summary["coverage"]
        assert cov["LLM01_prompt_injection"]["probes"] >= 1
        assert cov["benign"]["blocked"] == 0  # control never blocks

    def test_injection_probes_are_blocked_by_default_pipeline(self):
        """The reference pipeline must catch the canonical LLM01 probes."""
        manager = self._manager()
        battle = manager.create("a1")
        import asyncio
        pack = [p for p in get_pack("owasp_llm_10") if p.category == "LLM01_prompt_injection"]
        asyncio.run(manager.execute(battle.battle_id, probes=pack))
        assert battle.summary["coverage"]["LLM01_prompt_injection"]["blocked"] == len(pack)

    def test_app_battle_accepts_pack_selection(self):
        from fastapi.testclient import TestClient
        from archon_armor.app import create_app
        from .test_app import FakeUpstream

        registry = InMemoryRegistry()
        registry.register(AgentCard(
            agent_id="a1", name="t", version="1",
            policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
        client = TestClient(create_app(registry=registry, upstream=FakeUpstream()))
        resp = client.post("/v1/battles", json={"agent_id": "a1", "pack": "owasp_llm_10"},
                           headers={"X-Agent-ID": "a1"})
        battle_id = resp.json()["battle_id"]
        status = client.get(f"/v1/battles/{battle_id}").json()
        assert "LLM01_prompt_injection" in status["summary"]["coverage"]
