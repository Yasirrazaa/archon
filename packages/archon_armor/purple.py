"""One-click purple-team runs: attack (red) and measure the diff (blue).

`run_purple` battles two registered agents against the same probe pack and
feeds both battle reports through the compare engine, producing a single
verdict (improved | regressed | equal) plus probe-level newly
blocked/unblocked lists — the CI-gating primitive for policy changes.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict

from archon_core.observability.base import Tracer
from archon_core.registry.base import Registry

from .battles import Battle, BattleManager
from .compare import compare_battles
from .probes import get_pack


def _resolve_registry(registry_path_or_registry) -> Registry:
    """Accept either a live Registry or a path to a SQLite registry file."""
    if isinstance(registry_path_or_registry, Registry):
        return registry_path_or_registry
    from archon_core.registry.sqlite import SqliteRegistry

    return SqliteRegistry(str(registry_path_or_registry))


def _battle_report(battle: Battle) -> dict:
    """Flatten a finished Battle into the report shape compare_battles expects."""
    return {
        "agent_id": battle.agent_id,
        "battle_id": battle.battle_id,
        **battle.summary,
        "results": [asdict(v) for v in battle.results],
        # compare_battles consumes the nested shape; flattened keys above are
        # a convenience for callers.
        "summary": dict(battle.summary),
    }


async def run_purple(
    registry_path_or_registry,
    agent_id_a: str,
    agent_id_b: str,
    *,
    pack: str = "core",
    tracer: Tracer | None = None,
) -> dict:
    """Run identical red-team packs against two agents and compare outcomes."""
    registry = _resolve_registry(registry_path_or_registry)
    manager = BattleManager(registry, tracer=tracer)
    probes = get_pack(pack)

    reports: dict[str, dict] = {}
    for label, agent_id in (("a", agent_id_a), ("b", agent_id_b)):
        battle = manager.create(agent_id)
        await manager.execute(battle.battle_id, probes=probes)
        reports[label] = _battle_report(battle)

    comparison = compare_battles(reports["a"], reports["b"])

    return {
        "pack": pack,
        "labels": comparison["labels"],
        "verdict": comparison["verdict"],
        "a": reports["a"],
        "b": reports["b"],
        "delta": {
            "block_rate": comparison["block_rate"],
            "per_category": comparison["per_category"],
            "newly_unblocked": comparison["newly_unblocked"],
            "newly_blocked": comparison["newly_blocked"],
            "control": comparison["control"],
            "severity": comparison["severity"],
        },
    }


def run_purple_sync(
    registry_path_or_registry,
    agent_id_a: str,
    agent_id_b: str,
    **kwargs,
) -> dict:
    """Synchronous convenience wrapper for CLI/scripts."""
    return asyncio.run(
        run_purple(registry_path_or_registry, agent_id_a, agent_id_b, **kwargs)
    )


def render_purple_md(report: dict) -> str:
    """Render a purple-run report as markdown."""
    label_a = report["labels"]["a"]
    label_b = report["labels"]["b"]
    br = report["delta"]["block_rate"]
    lines: list[str] = []
    lines.append(f"# Purple run — {report['pack']} pack — {label_a} vs {label_b}")
    lines.append("")
    lines.append(f"**Verdict:** `{report['verdict']}`")
    lines.append("")
    lines.append("## Block rates")
    lines.append("")
    lines.append(f"| Metric | {label_a} | {label_b} | Delta |")
    lines.append("|---|---|---|---|")
    lines.append(f"| Block rate | {br['a']:.1%} | {br['b']:.1%} | {br['delta']:+.1%} |")

    if report["delta"]["newly_unblocked"]:
        lines.append("")
        lines.append("## Regressions — previously blocked, now passing")
        for name in report["delta"]["newly_unblocked"]:
            lines.append(f"- `{name}`")

    if report["delta"]["newly_blocked"]:
        lines.append("")
        lines.append("## Improvements — now blocked")
        for name in report["delta"]["newly_blocked"]:
            lines.append(f"- `{name}`")

    lines.append("")
    return "\n".join(lines)
