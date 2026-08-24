"""Tests for purple runs: battle A vs battle B over the same probe pack."""

from __future__ import annotations

import pytest
from archon_armor.probes import UnknownPackError
from archon_armor.purple import render_purple_md, run_purple, run_purple_sync
from archon_core.registry.base import AgentCard, AgentNotFoundError, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.registry.sqlite import SqliteRegistry


def _registry() -> InMemoryRegistry:
    reg = InMemoryRegistry()
    reg.register(AgentCard(
        agent_id="agent-a", name="Agent A", version="1.0.0",
        policy=SecurityPolicy(),
    ))
    return reg


def _two_agent_registry(policy_a: SecurityPolicy | None = None,
                        policy_b: SecurityPolicy | None = None) -> InMemoryRegistry:
    reg = InMemoryRegistry()
    reg.register(AgentCard(
        agent_id="agent-a", name="Agent A", version="1.0.0",
        policy=policy_a or SecurityPolicy(),
    ))
    reg.register(AgentCard(
        agent_id="agent-b", name="Agent B", version="1.0.0",
        policy=policy_b or SecurityPolicy(),
    ))
    return reg


class TestRunPurple:
    async def test_identical_policies_verdict_equal(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        assert report["verdict"] == "equal"
        assert report["delta"]["newly_unblocked"] == []
        assert report["delta"]["newly_blocked"] == []

    async def test_weakened_policy_b_regressed_with_newly_unblocked(self):
        # min_confidence 0.9 lets every core attack probe (confidence < 0.9) pass.
        weakened = SecurityPolicy(min_confidence=0.9)
        reg = _two_agent_registry(policy_b=weakened)
        report = await run_purple(reg, "agent-a", "agent-b")
        assert report["verdict"] == "regressed"
        assert report["delta"]["newly_unblocked"]
        assert report["delta"]["block_rate"]["b"] < report["delta"]["block_rate"]["a"]

    async def test_hardened_policy_b_improved_with_newly_blocked(self):
        # A blocks nothing (min_confidence 1.0); default B blocks all three attacks.
        permissive = SecurityPolicy(min_confidence=1.0)
        reg = _two_agent_registry(policy_a=permissive)
        report = await run_purple(reg, "agent-a", "agent-b")
        assert report["verdict"] == "improved"
        assert report["delta"]["newly_blocked"]
        assert report["delta"]["block_rate"]["b"] > report["delta"]["block_rate"]["a"]

    async def test_pack_name_recorded(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        assert report["pack"] == "core"

    async def test_core_pack_shape_default_policy_blocks_three_of_four(self):
        reg = _two_agent_registry()
        report = await run_purple(reg, "agent-a", "agent-b")
        assert report["a"]["total_probes"] == 4
        assert report["a"]["blocked"] == 3
        assert report["a"]["block_rate"] == pytest.approx(0.75)
        assert report["a"]["control_passed"] is True
        blocked_names = {v["probe_name"] for v in report["a"]["results"] if v["blocked"]}
        assert blocked_names == {"direct_injection", "encoded_injection", "authority_claim"}

    async def test_summaries_carry_agent_and_battle_ids(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        assert report["labels"] == {"a": "agent-a", "b": "agent-b"}
        assert report["a"]["agent_id"] == "agent-a"
        assert report["b"]["agent_id"] == "agent-b"
        assert report["a"]["battle_id"] != report["b"]["battle_id"]

    async def test_delta_block_rate_is_b_minus_a(self):
        reg = _two_agent_registry(policy_b=SecurityPolicy(min_confidence=0.9))
        report = await run_purple(reg, "agent-a", "agent-b")
        delta = report["delta"]["block_rate"]["delta"]
        assert delta == pytest.approx(
            report["delta"]["block_rate"]["b"] - report["delta"]["block_rate"]["a"], abs=1e-4
        )

    async def test_severity_comparison_present_when_both_scored(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        assert isinstance(report["delta"]["severity"], dict)
        assert report["delta"]["control"] == {"a": True, "b": True}

    async def test_unknown_pack_raises(self):
        with pytest.raises(UnknownPackError):
            await run_purple(_two_agent_registry(), "agent-a", "agent-b", pack="does_not_exist")

    async def test_unregistered_agent_raises(self):
        with pytest.raises(AgentNotFoundError):
            await run_purple(_registry(), "agent-a", "missing-agent")

    async def test_accepts_sqlite_registry_path_string(self, tmp_path):
        path = str(tmp_path / "registry.db")
        reg = SqliteRegistry(path)
        reg.register(AgentCard(
            agent_id="agent-a", name="A", version="1", policy=SecurityPolicy(),
        ))
        reg.register(AgentCard(
            agent_id="agent-b", name="B", version="1",
            policy=SecurityPolicy(min_confidence=0.9),
        ))
        report = await run_purple(path, "agent-a", "agent-b")
        assert report["verdict"] == "regressed"

    def test_sync_wrapper_matches_async(self):
        report = run_purple_sync(_two_agent_registry(), "agent-a", "agent-b")
        assert report["verdict"] == "equal"


class TestRenderPurpleMd:
    async def test_markdown_contains_verdict_and_block_rates(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        md = render_purple_md(report)
        assert "`equal`" in md
        assert "75.0%" in md

    async def test_markdown_lists_regressions_for_weakened_policy(self):
        reg = _two_agent_registry(policy_b=SecurityPolicy(min_confidence=0.9))
        md = render_purple_md(await run_purple(reg, "agent-a", "agent-b"))
        assert "`regressed`" in md
        assert "- `direct_injection`" in md

    async def test_markdown_mentions_pack(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        md = render_purple_md(report)
        assert "core" in md
