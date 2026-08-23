"""Async battle/scan engine: run probe suites against a registered agent's policy.

A battle is a batch of security probes executed through the same guard
pipeline that armor uses in production, producing per-probe verdicts and a
summary (block rate). This is the "measure your defense" primitive.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field

from archon_core.defenses.base import DefensePipeline
from archon_core.defenses.layers import (
    ExecutionModeLayer,
    NormalizationLayer,
    SegmentationLayer,
    SpotlightingLayer,
    ThreatClassificationLayer,
)
from archon_core.models import Exchange
from archon_core.observability.base import Tracer
from archon_core.registry.base import Registry, SecurityPolicy
from archon_core.targets.base import TargetAdapter
from .probes import Probe, get_pack

# Backward-compatible default: the core pack.
DEFAULT_PROBES: list[Probe] = get_pack("core")


@dataclass
class ProbeVerdict:
    probe_name: str
    blocked: bool
    category: str = "uncategorized"
    block_reason: str | None = None
    execution_mode: str | None = None


@dataclass
class Battle:
    battle_id: str
    agent_id: str
    status: str  # queued | running | completed
    results: list[ProbeVerdict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def finalize(self) -> None:
        from archon_core.reporting.severity import Finding, summarize_severity

        total = len(self.results)
        blocked = sum(1 for r in self.results if r.blocked)
        control = next((r for r in self.results if r.probe_name == "benign_control"), None)
        coverage: dict[str, dict] = {}
        for r in self.results:
            slot = coverage.setdefault(r.category, {"probes": 0, "blocked": 0})
            slot["probes"] += 1
            slot["blocked"] += 1 if r.blocked else 0
        findings = [
            Finding(
                probe_name=r.probe_name,
                category=r.category,
                execution_mode=r.execution_mode,
            )
            for r in self.results
            if not r.blocked and r.probe_name != "benign_control"
        ]
        self.summary = {
            "total_probes": total,
            "blocked": blocked,
            "block_rate": round(blocked / total, 3) if total else 0.0,
            # No control probe in pack => cannot fail on helpfulness
            "control_passed": True if control is None else not control.blocked,
            "coverage": coverage,
            "severity": summarize_severity(findings),
        }
        self.status = "completed"


class BattleManager:
    """Creates and executes battles against registered agent policies."""

    def __init__(self, registry: Registry, tracer: Tracer | None = None):
        self._registry = registry
        self._tracer = tracer
        self._battles: dict[str, Battle] = {}

    def create(self, agent_id: str) -> Battle:
        battle = Battle(
            battle_id=uuid.uuid4().hex[:12], agent_id=agent_id, status="queued"
        )
        self._battles[battle.battle_id] = battle
        return battle

    def get(self, battle_id: str) -> Battle | None:
        return self._battles.get(battle_id)

    async def execute(self, battle_id: str, probes: list[Probe] | None = None,
                      target: TargetAdapter | None = None, mode: str = "probes",
                      goal: str = "", seeds: list[str] | None = None,
                      provider=None, width: int = 2, max_rounds: int = 3) -> Battle:
        """Run probes. Default path exercises the agent's registered policy;
        when `target` is given, probes go to that remote endpoint instead —
        this is how Archon validates THIRD-PARTY guardrails.

        mode="multi_turn" runs the BranchingAttacker (fan-out/pivot/prune)
        against a remote target instead of a static probe batch."""
        battle = self._battles[battle_id]
        if mode == "multi_turn":
            return await self._execute_multi_turn(
                battle, target, goal, seeds or [], provider, width, max_rounds
            )
        if target is not None:
            return await self._execute_remote(battle, probes, target)
        card = self._registry.get(battle.agent_id)
        policy: SecurityPolicy = card.policy
        pipeline = DefensePipeline(
            [
                NormalizationLayer(),
                ThreatClassificationLayer(
                    block_categories=tuple(policy.block_categories),
                    min_confidence=policy.min_confidence,
                ),
                SegmentationLayer(),
                SpotlightingLayer(task_id=f"battle-{battle.battle_id}", conversational=True),
                ExecutionModeLayer(),
            ],
            tracer=self._tracer,
        )

        battle.status = "running"
        verdicts: list[ProbeVerdict] = []
        for probe in probes or DEFAULT_PROBES:
            ex = await pipeline.run(Exchange(content=probe.payload, metadata={"agent_id": battle.agent_id}))
            verdicts.append(
                ProbeVerdict(
                    probe_name=probe.name,
                    blocked=ex.blocked,
                    category=probe.category,
                    block_reason=ex.block_reason if ex.blocked else None,
                    execution_mode=ex.metadata.get("execution_mode"),
                )
            )
        battle.results = verdicts
        battle.finalize()
        return battle

    def execute_sync(self, battle_id: str, **kwargs) -> Battle:
        """Synchronous convenience for CLI/scripts (asyncio.run)."""
        import asyncio

        return asyncio.run(self.execute(battle_id, **kwargs))

    async def _execute_multi_turn(self, battle: Battle,
                                  target: TargetAdapter | None,
                                  goal: str, seeds: list[str],
                                  provider, width: int, max_rounds: int) -> Battle:
        if target is None or provider is None:
            raise ValueError(
                "multi_turn battles require both a remote target and an attack provider"
            )
        from archon_core.attacks.branching import BranchingAttacker

        battle.status = "running"
        attacker = BranchingAttacker(provider, width=width, max_rounds=max_rounds)
        tree = await attacker.run(target, goal=goal, seeds=seeds)

        verdicts = []
        for branch in tree.branches:
            verdicts.append(ProbeVerdict(
                probe_name=f"turn{branch.depth}:{branch.payload[:40]}",
                blocked=not branch.success,
                category="multi_turn_adaptive",
                block_reason=(None if branch.success else "no leak evidence in response"),
            ))
        battle.results = verdicts
        battle.finalize()
        battle.summary["mode"] = "multi_turn"
        battle.summary["attack_tree"] = {
            "goal": tree.goal,
            "success": tree.success,
            "rounds_run": tree.rounds_run,
            "branches": len(tree.branches),
            "errors": list(tree.errors),
        }
        return battle

    async def _execute_remote(self, battle: Battle, probes: list[Probe] | None,
                              target: TargetAdapter) -> Battle:
        """Probe a remote endpoint; verdicts come from the target adapter's
        own blocked/allowed classification (deterministic signals)."""
        battle.status = "running"
        verdicts: list[ProbeVerdict] = []
        for probe in probes or DEFAULT_PROBES:
            resp = await target.send(probe.payload)
            verdicts.append(ProbeVerdict(
                probe_name=probe.name,
                blocked=resp.blocked,
                category=probe.category,
                block_reason=resp.block_reason if resp.blocked else None,
            ))
        battle.results = verdicts
        battle.finalize()
        return battle


async def execute_async(manager: BattleManager, battle_id: str) -> Battle:
    """Convenience wrapper for scheduling via asyncio.create_task."""
    return await manager.execute(battle_id)


# Re-export for typing convenience in app wiring
_ = asyncio
