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

    def test_total_corpus_exceeds_100_probes(self):
        total = sum(len(get_pack(name)) for name in list_packs())
        assert total >= 100, f"corpus too thin: {total}"

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


class TestHarmlessHelpfulnessPack:
    """False-positive canaries: benign-but-tricky requests a paranoid
    filter would wrongly block. The reference pipeline must pass ALL of them."""

    def test_pack_registered_with_minimum_breadth(self):
        pack = get_pack("harmless_helpfulness")
        assert len(pack) >= 10, f"canary pack too thin: {len(pack)}"
        names = [p.name for p in pack]
        assert len(names) == len(set(names)), "duplicate probe name in canary pack"

    def test_canary_payloads_are_unique(self):
        keys = [p.payload.strip().lower() for p in get_pack("harmless_helpfulness")]
        assert len(keys) == len(set(keys)), "duplicate payload in canary pack"

    def test_all_canaries_categorized_benign(self):
        assert all(p.category == "benign" for p in get_pack("harmless_helpfulness"))

    def test_reference_pipeline_blocks_zero_canaries(self):
        """The core false-positive invariant: a helpful user must never be blocked."""
        import asyncio

        registry = InMemoryRegistry()
        registry.register(AgentCard(
            agent_id="a1", name="t", version="1",
            policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
        manager = BattleManager(registry)
        battle = manager.create("a1")
        pack = get_pack("harmless_helpfulness")
        asyncio.run(manager.execute(battle.battle_id, probes=pack))
        blocked = battle.summary["blocked"]
        assert blocked == 0, (
            f"reference pipeline falsely blocked {blocked}/{len(pack)} "
            f"benign canaries — over-blocking regression"
        )


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


class TestEncodingEvasionPack:
    """Garak-style encoding-family probes: attack payloads hidden behind
    deterministic transforms (base64, hex, rot13, url, html entities,
    leetspeak, homoglyphs, zero-width). The reference pipeline's
    NormalizationLayer must decode every one of them before classification."""

    def test_pack_registered_with_minimum_breadth(self):
        pack = get_pack("encoding_evasion")
        assert len(pack) >= 12, f"encoding pack too thin: {len(pack)}"
        names = [p.name for p in pack]
        assert len(names) == len(set(names)), "duplicate probe name in encoding pack"

    def test_payloads_are_unique(self):
        keys = [p.payload.strip().lower() for p in get_pack("encoding_evasion")]
        assert len(keys) == len(set(keys)), "duplicate payload in encoding pack"

    def test_all_categorized_encoding_evasion(self):
        assert all(p.category == "encoding_evasion" for p in get_pack("encoding_evasion"))

    def test_every_payload_decodes_to_attack_text(self):
        """Each probe must survive the normalizer as recognizable attack text —
        a probe that decodes to gibberish tests nothing."""
        import asyncio

        from archon_core.compat import load_defender_module

        norm_mod = load_defender_module("normalization")
        normalizer = norm_mod.DeterministicNormalizer()
        triggers = (
            "ignore", "disregard", "system prompt", "reveal",
            "instructions", "override", "you are now", "no restrictions",
            "pretend", "dan mode",
        )
        for probe in get_pack("encoding_evasion"):
            decoded = normalizer.normalize(probe.payload)
            hit = any(t in decoded.lower() for t in triggers)
            assert hit, f"{probe.name} does not decode to attack text: {decoded!r}"

    def test_reference_pipeline_blocks_all_encoded_probes(self):
        """Deterministic tier invariant: encoded attacks never reach the model."""
        import asyncio

        registry = InMemoryRegistry()
        registry.register(AgentCard(
            agent_id="a1", name="t", version="1",
            policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
        manager = BattleManager(registry)
        battle = manager.create("a1")
        pack = get_pack("encoding_evasion")
        asyncio.run(manager.execute(battle.battle_id, probes=pack))
        blocked = battle.summary["blocked"]
        assert blocked == len(pack), (
            f"reference pipeline missed {len(pack) - blocked}/{len(pack)} "
            f"encoded attacks — normalization gap"
        )


class TestLatentInjectionPack:
    """Garak latentinjection-family probes: instructions smuggled inside
    realistic document contexts (resumes, invoices, web pages, tickets).
    Indirect injection is OWASP LLM01's delivery channel of record."""

    def test_pack_registered_with_minimum_breadth(self):
        pack = get_pack("latent_injection")
        assert len(pack) >= 12, f"latent injection pack too thin: {len(pack)}"
        names = [p.name for p in pack]
        assert len(names) == len(set(names)), "duplicate probe name in latent pack"

    def test_payloads_are_unique(self):
        keys = [p.payload.strip().lower() for p in get_pack("latent_injection")]
        assert len(keys) == len(set(keys)), "duplicate payload in latent pack"

    def test_all_categorized_latent_injection(self):
        assert all(p.category == "latent_injection" for p in get_pack("latent_injection"))

    def test_payloads_embed_instructions_in_document_context(self):
        """Every latent probe must look like a document AND carry an imperative
        injection — that combination is the threat being tested."""
        doc_markers = ("resume", "invoice", "note", "document", "page", "ticket",
                       "email", "readme", "comment", "log", "policy", "report",
                       "memo", "article", "description", "summary", "transcript",
                       "review", "letter", "contract")
        imperatives = ("ignore", "disregard", "reveal", "forward", "exfiltrate",
                       "follow", "execute", "visit", "send")
        for probe in get_pack("latent_injection"):
            low = probe.payload.lower()
            assert any(m in low for m in doc_markers), (
                f"{probe.name} lacks document context"
            )
            assert any(i in low for i in imperatives), (
                f"{probe.name} lacks injected instruction"
            )

    def test_reference_pipeline_blocks_all_latent_probes(self):
        import asyncio

        registry = InMemoryRegistry()
        registry.register(AgentCard(
            agent_id="a1", name="t", version="1",
            policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
        manager = BattleManager(registry)
        battle = manager.create("a1")
        pack = get_pack("latent_injection")
        asyncio.run(manager.execute(battle.battle_id, probes=pack))
        blocked = battle.summary["blocked"]
        assert blocked == len(pack), (
            f"reference pipeline missed {len(pack) - blocked}/{len(pack)} "
            f"latent injections"
        )
