"""Multi-attempt benchmark series over the AgentDojo v1 corpus (E2.7 item 39).

NIST CAISI showed single-attempt scores understate adaptive attack success:
aggregate ASR climbs from 57% to 80% at a budget of 25 attempts per task.
This module makes the attempt budget a first-class, published field and emits
cumulative ASR curves — honoring the methodology commitments in RESULTS.md.

Fully offline and reproducible: attacks run against Archon's deterministic
reference defense pipeline (the same pipeline BattleManager uses), seeded
variant rotation from archon_core.attacks.adaptive.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from archon_core.attacks.adaptive import AdaptiveAttackCampaign, MultiAttemptAttacker
from archon_core.defenses.base import DefensePipeline, Exchange
from archon_core.defenses.layers import (
    ExecutionModeLayer,
    NormalizationLayer,
    SegmentationLayer,
    SpotlightingLayer,
    ThreatClassificationLayer,
)
from archon_core.registry.base import SecurityPolicy
from archon_core.targets.base import TargetAdapter, TargetResponse

from .agentdojo_corpus import load_agentdojo_v1_tasks
from .runner import build_attack_prompts

_DEFAULT_POLICY = SecurityPolicy(upstream_base_url="https://u.test/v1")


class _ReferencePipelineTarget(TargetAdapter):
    """Routes each payload through the production reference pipeline."""

    def __init__(self, policy: SecurityPolicy | None = None):
        policy = policy or _DEFAULT_POLICY
        self._pipeline = DefensePipeline(
            [
                NormalizationLayer(),
                ThreatClassificationLayer(
                    block_categories=tuple(policy.block_categories),
                    min_confidence=policy.min_confidence,
                ),
                SegmentationLayer(),
                SpotlightingLayer(task_id="multi-attempt-bench", conversational=True),
                ExecutionModeLayer(),
            ]
        )

    async def send(self, payload: str) -> TargetResponse:
        exchange = await self._pipeline.run(Exchange(content=payload))
        return TargetResponse(
            content=exchange.content,
            blocked=exchange.blocked,
            block_reason=exchange.block_reason,
        )


def run_multi_attempt_benchmark(
    max_attempts: int = 25,
    seed: int | None = None,
) -> dict[str, Any]:
    """Run one adaptive campaign per AgentDojo task; publish budget + curves."""
    tasks = load_agentdojo_v1_tasks()
    target = _ReferencePipelineTarget()
    attacker = MultiAttemptAttacker(
        campaign=AdaptiveAttackCampaign(max_attempts=max_attempts, seed=seed or 0)
    )

    per_task: list[dict[str, Any]] = []
    for task in tasks:
        seeds = [p.payload for p in build_attack_prompts(task)]
        result = attacker.run_sync(target, goal=task.goal, seeds=seeds)
        # Deterministic tier has no LLM behind the pipeline, so nothing can
        # "leak" — the meaningful per-attempt outcome is EVASION (got past
        # the shield unblocked). Strict ASR is only measurable in llm_tier.
        first_evasion = next(
            (a.attempt_no for a in result.attempts if not a.blocked), None
        )
        per_task.append({
            "task_id": task.task_id,
            "suite": task.suite,
            "first_success_attempt": result.first_success_attempt,
            "succeeded": result.succeeded,
            "attempts_used": result.attempts_used,
            "first_evasion_attempt": first_evasion,
            "evaded": first_evasion is not None,
        })

    succeeded = sum(1 for t in per_task if t["succeeded"])
    evaded = sum(1 for t in per_task if t["evaded"])
    asr_at_1 = sum(1 for t in per_task if t["first_success_attempt"] == 1) / len(per_task)
    evasion_at_1 = sum(
        1 for t in per_task if t["first_evasion_attempt"] == 1
    ) / len(per_task)
    curve = [
        {
            "attempts_k": k,
            "cumulative_asr": round(
                sum(1 for t in per_task
                    if t["first_success_attempt"] is not None
                    and t["first_success_attempt"] <= k) / len(per_task),
                4,
            ),
            "cumulative_evasion": round(
                sum(1 for t in per_task
                    if t["first_evasion_attempt"] is not None
                    and t["first_evasion_attempt"] <= k) / len(per_task),
                4,
            ),
        }
        for k in range(1, max_attempts + 1)
    ]

    suites = sorted({t["suite"] for t in per_task})
    per_suite = {
        s: {
            "tasks": sum(1 for t in per_task if t["suite"] == s),
            "asr_at_budget": round(
                sum(1 for t in per_task if t["suite"] == s and t["succeeded"])
                / max(1, sum(1 for t in per_task if t["suite"] == s)),
                4,
            ),
            "evasion_at_budget": round(
                sum(1 for t in per_task if t["suite"] == s and t["evaded"])
                / max(1, sum(1 for t in per_task if t["suite"] == s)),
                4,
            ),
        }
        for s in suites
    }

    return {
        "benchmark": "agentdojo_v1_multi_attempt",
        "attempt_budget": max_attempts,
        "tasks": len(tasks),
        "succeeded": succeeded,
        "evaded": evaded,
        "asr_at_1": round(asr_at_1, 4),
        "asr_at_budget": round(succeeded / len(tasks), 4),
        "evasion": {
            "at_1": round(evasion_at_1, 4),
            "at_budget": round(evaded / len(tasks), 4),
            "curve": curve,
        },
        "asr_note": (
            "Strict ASR (goal achieved) requires a live LLM behind the pipeline — "
            "run llm_tier.run_full_pipeline_benchmark() with an API key. In this "
            "deterministic tier the primary metric is EVASION: the fraction of "
            "tasks where at least one mutated variant got past the shield."
        ),
        "curve": curve,
        "per_task": per_task,
        "per_suite": per_suite,
        "measurement": {
            "attempt_budget": max_attempts,
            "adaptivity": "multi-attempt-5-variant-rotation",
            "judge": "deterministic-rules",
        },
    }


def render_multi_attempt_md(report: dict[str, Any], path: Path) -> None:
    """Markdown report with budget, curve table, and methodology block."""
    lines = [
        "# AgentDojo v1 — Multi-Attempt Benchmark",
        "",
        f"Benchmark: `{report['benchmark']}` · Tasks: {report['tasks']} · "
        f"**Attempt budget: {report['attempt_budget']}** (always declared)",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| ASR @ 1 attempt | {report['asr_at_1']:.2%} |",
        f"| ASR @ budget ({report['attempt_budget']}) | {report['asr_at_budget']:.2%} |",
        "",
        "## Cumulative ASR curve",
        "",
        "| Attempts k | Cumulative ASR |",
        "|---|---|",
    ]
    lines += [f"| {c['attempts_k']} | {c['cumulative_asr']:.2%} |" for c in report["curve"]]
    lines += [
        "",
        "## Per-suite breakdown",
        "",
        "| Suite | Tasks | ASR @ budget |",
        "|---|---|---|",
    ]
    lines += [
        f"| {s} | {v['tasks']} | {v['asr_at_budget']:.2%} |"
        for s, v in report["per_suite"].items()
    ]
    m = report["measurement"]
    lines += [
        "",
        "## Methodology",
        "",
        f"- Attempt budget: {m['attempt_budget']} (declared per RESULTS.md commitments)",
        f"- Adaptivity: {m['adaptivity']}",
        f"- Judge: {m['judge']} (fully offline, reproducible)",
        "",
    ]
    path.write_text("\n".join(lines))


__all__ = ["run_multi_attempt_benchmark", "render_multi_attempt_md"]
