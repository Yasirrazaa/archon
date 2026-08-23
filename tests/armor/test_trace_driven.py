"""Tests for trace-driven attack generation (ROADMAP N2 item: nobody covers this).

Spans recorded by the defense pipeline / armor proxy are mined into a
TraceProfile; targeted attacks are synthesized from what the traces reveal
(weak layers, live tools, leaked error internals).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from archon_core.attacks.trace_driven import (
    TraceAttack,
    TraceProfile,
    analyze_spans,
    generate_attacks,
    load_spans_jsonl,
)


def _span(name: str, **attrs) -> dict:
    return {"name": name, "span_id": name, "parent_span_id": None,
            "duration_ms": 1.0, "attributes": attrs, "started_at_unix": 0}


class TestAnalyzeSpans:
    def test_extracts_layers_in_order(self):
        spans = [
            _span("normalization", layer="normalization", llm_budget=0),
            _span("threat_classification", layer="threat_classification", blocked=False),
        ]
        profile = analyze_spans(spans)
        assert profile.layers_seen == ["normalization", "threat_classification"]

    def test_layers_deduplicated(self):
        spans = [
            _span("normalization", layer="normalization"),
            _span("normalization", layer="normalization"),
        ]
        assert analyze_spans(spans).layers_seen == ["normalization"]

    def test_blocked_layers_collected(self):
        spans = [
            _span("threat_classification", layer="threat_classification", blocked=True),
            _span("spotlighting", layer="spotlighting", blocked=False),
        ]
        profile = analyze_spans(spans)
        assert profile.blocked_by == ["threat_classification"]
        assert "spotlighting" in profile.layers_seen

    def test_errors_and_agents_and_tools(self):
        spans = [
            _span("armor.request", agent_id="banker", route="/v1/chat/completions"),
            _span("threat_classification", layer="threat_classification",
                  error="boom: /app/secrets.py"),
            _span("tool.transfer_money", tool_name="transfer_money"),
        ]
        profile = analyze_spans(spans)
        assert profile.agent_ids == ["banker"]
        assert profile.routes == ["/v1/chat/completions"]
        assert any("/app/secrets.py" in e for e in profile.errors)
        assert profile.tool_names == ["transfer_money"]


class TestLoadSpansJsonl:
    def test_roundtrip(self, tmp_path: Path):
        p = tmp_path / "spans.jsonl"
        records = [_span("normalization", layer="normalization")]
        p.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
        assert load_spans_jsonl(p) == records


class TestGenerateAttacks:
    def test_empty_profile_yields_no_attacks(self):
        assert generate_attacks(TraceProfile()) == []

    def test_every_unblocked_layer_gets_evasion_probe(self):
        profile = TraceProfile(
            layers_seen=["normalization", "threat_classification", "spotlighting"],
            blocked_by=["threat_classification"],
        )
        attacks = generate_attacks(profile)
        names = {p.probe_name for p in attacks}
        assert "trace_evade_normalization" in names
        assert "trace_evade_spotlighting" in names
        assert "trace_evade_threat_classification" not in names

    def test_unknown_layer_gets_generic_probe(self):
        profile = TraceProfile(layers_seen=["mystery_layer"], blocked_by=[])
        attacks = generate_attacks(profile)
        assert len(attacks) == 1
        assert attacks[0].probe_name == "trace_evade_mystery_layer"

    def test_tools_produce_targeted_probes(self):
        profile = TraceProfile(tool_names=["transfer_money", "read_file"])
        attacks = generate_attacks(profile)
        names = {p.probe_name for p in attacks}
        assert "trace_tool_transfer_money" in names
        assert "trace_tool_read_file" in names
        tool_probe = next(p for p in attacks if p.probe_name == "trace_tool_transfer_money")
        assert "transfer_money" in tool_probe.payload

    def test_errors_produce_exploit_probe(self):
        profile = TraceProfile(errors=["boom: /app/secrets.py line 42"])
        attacks = generate_attacks(profile)
        exploit = [p for p in attacks if p.probe_name == "trace_error_exploit"]
        assert len(exploit) == 1
        assert "/app/secrets.py" in exploit[0].payload

    def test_all_probes_are_valid_unique_trace_driven(self):
        profile = TraceProfile(
            layers_seen=["normalization", "output_guardrails"],
            tool_names=["send_email"],
            errors=["err one"],
        )
        attacks = generate_attacks(profile)
        assert attacks
        names = [p.probe_name for p in attacks]
        assert len(names) == len(set(names))
        for probe in attacks:
            assert isinstance(probe, TraceAttack)
            assert probe.category == "trace_driven"
            assert probe.payload.strip()

    def test_combined_profile_covers_all_sources(self):
        profile = TraceProfile(
            layers_seen=["normalization"],
            blocked_by=[],
            tool_names=["wire_transfer"],
            errors=["internal path leak"],
        )
        attacks = generate_attacks(profile)
        kinds = {p.probe_name.split("__")[0] for p in attacks}
        assert any(n.startswith("trace_evade_") for n in kinds)
        assert any(n.startswith("trace_tool_") for n in kinds)
        assert "trace_error_exploit" in kinds


@pytest.mark.slow
class TestIntegration:
    def test_generated_probes_run_through_battle_manager(self, tmp_path):
        """End-to-end: mine a real JsonlTracer file, generate attacks, battle them."""
        from archon_armor.battles import BattleManager
        from archon_core.defenses.base import DefensePipeline
        from archon_core.defenses.layers import (
            NormalizationLayer,
            ThreatClassificationLayer,
        )
        from archon_core.models import Exchange
        from archon_core.observability.jsonl import JsonlTracer
        from archon_core.registry.base import AgentCard, SecurityPolicy
        from archon_core.registry.memory import InMemoryRegistry

        # produce a genuine span file via a traced pipeline
        tracer = JsonlTracer(tmp_path / "spans.jsonl")

        async def _produce():
            pipe = DefensePipeline(
                [NormalizationLayer(), ThreatClassificationLayer()], tracer=tracer
            )
            await pipe.run(Exchange(content="hello world"))

        import asyncio

        asyncio.run(_produce())

        profile = analyze_spans(load_spans_jsonl(tmp_path / "spans.jsonl"))
        attacks = generate_attacks(profile)
        assert attacks  # normalization ran unblocked -> evasion probe expected

        registry = InMemoryRegistry()
        registry.register(AgentCard(
            agent_id="t", name="T", version="1",
            policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
        manager = BattleManager(registry)
        battle = manager.create("t")
        import asyncio as aio

        aio.run(manager.execute(battle.battle_id, attacks))
        done = manager.get(battle.battle_id)
        assert done.summary["total_probes"] == len(attacks)
