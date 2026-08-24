"""Full-pipeline (LLM-tier) benchmark — env-gated (E2.7 item 38).

The published AgentDojo numbers in RESULTS.md are deterministic-tier only
(zero LLM calls). This module closes that credibility gap honestly: it runs
the corpus against a REAL upstream LLM through the reference defense pipeline
and reports full-pipeline ASR — but ONLY when ARCHON_ATTACK_PROVIDER_API_KEY
is set. Without a key it returns an explicit disabled report rather than
extrapolating.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from archon_core.targets.base import TargetAdapter
from archon_core.targets.openai_compat import detect_refusal

from .agentdojo_corpus import load_agentdojo_v1_tasks
from .multi_attempt import _ReferencePipelineTarget
from .runner import build_attack_prompts

_DISABLED_REPORT: dict[str, Any] = {
    "enabled": False,
    "reason": (
        "ARCHON_ATTACK_PROVIDER_API_KEY not set — full-pipeline tier requires "
        "a live upstream. Deterministic-tier numbers remain valid; see RESULTS.md."
    ),
}


def _default_target() -> TargetAdapter:
    from archon_core.providers import provider_from_env
    from archon_core.targets.openai_compat import OpenAICompatTarget

    provider = provider_from_env()
    return OpenAICompatTarget(
        base_url=os.environ.get(
            "ARCHON_BENCHMARK_UPSTREAM_URL",
            "https://generativelanguage.googleapis.com/v1beta/openai",
        ),
        api_key=os.environ["ARCHON_ATTACK_PROVIDER_API_KEY"],
        model=provider.model,
    )


def run_full_pipeline_benchmark(target: TargetAdapter | None = None) -> dict[str, Any]:
    """Run corpus attacks past the pipeline into a live LLM; measure real ASR.

    ``target`` is injectable for tests; production uses the Gemini-compatible
    endpoint configured via ARCHON_ATTACK_PROVIDER_* / ARCHON_BENCHMARK_UPSTREAM_URL.
    """
    if target is None and not os.environ.get("ARCHON_ATTACK_PROVIDER_API_KEY"):
        return dict(_DISABLED_REPORT)

    live = target if target is not None else _default_target()
    pipeline = _ReferencePipelineTarget()
    tasks = load_agentdojo_v1_tasks()

    total = 0
    blocked_by_pipeline = 0
    reached_llm = 0
    llm_complied = 0
    per_suite: dict[str, dict[str, int]] = {}

    for task in tasks:
        suite_stats = per_suite.setdefault(
            task.suite, {"attacks": 0, "blocked": 0, "succeeded": 0}
        )
        for probe in build_attack_prompts(task):
            total += 1
            suite_stats["attacks"] += 1

            async def _run() -> tuple[bool, bool]:
                guard = await pipeline.send(probe.payload)
                if guard.blocked:
                    return True, False
                resp = await live.send(probe.payload)
                return False, not detect_refusal(resp.content)

            blocked, succeeded = asyncio.run(_run())
            if blocked:
                blocked_by_pipeline += 1
                suite_stats["blocked"] += 1
            else:
                reached_llm += 1
                if succeeded:
                    llm_complied += 1
                    suite_stats["succeeded"] += 1

    return {
        "enabled": True,
        "benchmark": "agentdojo_v1_full_pipeline",
        "total_attacks": total,
        "blocked_by_pipeline": blocked_by_pipeline,
        "reached_llm": reached_llm,
        "llm_complied": llm_complied,
        "asr_full_pipeline": round(llm_complied / total, 4) if total else 0.0,
        "per_suite": per_suite,
        "measurement": {
            "attempt_budget": 1,
            "adaptivity": "static",
            "judge": "refusal-heuristic",
        },
    }


__all__ = ["run_full_pipeline_benchmark"]
