"""One-click purple-team runs: attack (red) and measure the diff (blue).

`run_purple` battles two registered agents against the same probe pack and
feeds both battle reports through the compare engine, producing a single
verdict (improved | regressed | equal) plus probe-level newly
blocked/unblocked lists — the CI-gating primitive for policy changes.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from dataclasses import asdict

from archon_core.observability.base import Tracer
from archon_core.registry.base import Registry

from .battles import Battle, BattleManager
from .compare import compare_battles
from .probes import get_pack

_RATE_EPSILON = 0.001


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


def _baseline_snapshot(report: dict) -> dict:
    """Extract the measured agent's (side 'b') battle facts for baseline storage."""
    b = report["b"]
    return {
        "pack": report.get("pack", ""),
        "agent_id": b.get("agent_id", ""),
        "block_rate": b["block_rate"],
        "control_passed": bool(b["control_passed"]),
        "results": b["results"],
    }


def save_baseline(report: dict, path: str) -> None:
    """Persist the measured agent's results as a Policy-CI baseline (atomic)."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(_baseline_snapshot(report), fh, indent=2)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def load_baseline(path: str) -> dict | None:
    """Load a saved baseline; missing files yield None so CI can fail soft."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def compare_to_baseline(
    current_report: dict,
    baseline: dict,
    rate_epsilon: float = _RATE_EPSILON,
) -> dict:
    """Compare a fresh purple run against a baseline snapshot.

    A regression is any of: a probe unblocked now that was blocked in the
    baseline, the block rate strictly below the baseline (> epsilon), or a
    control failure now where the baseline passed.
    """
    current = _baseline_snapshot(current_report)

    base_blocked = {
        r["probe_name"] for r in baseline.get("results", []) if r["blocked"]
    }
    newly_unblocked = sorted(
        r["probe_name"]
        for r in current.get("results", [])
        if r["probe_name"] in base_blocked and not r["blocked"]
    )

    base_rate = float(baseline.get("block_rate", 0.0))
    current_rate = float(current.get("block_rate", 0.0))
    dropped_block_rate: float | None = None
    if current_rate < base_rate - rate_epsilon:
        dropped_block_rate = round(base_rate - current_rate, 6)

    control_failed = bool(baseline.get("control_passed")) and not bool(
        current.get("control_passed")
    )

    details: list[dict] = []
    if newly_unblocked:
        details.append({"kind": "probe_unblocked", "probes": newly_unblocked})
    if dropped_block_rate is not None:
        details.append({
            "kind": "block_rate_drop",
            "detail": f"{base_rate:.3f} -> {current_rate:.3f}",
        })
    if control_failed:
        details.append({"kind": "control_failed"})

    return {
        "regressed": bool(details),
        "newly_unblocked": newly_unblocked,
        "dropped_block_rate": dropped_block_rate,
        "details": details,
    }


def render_baseline_md(comparison: dict) -> str:
    """Render a baseline comparison as a short markdown verdict block."""
    lines: list[str] = ["## Baseline comparison"]
    lines.append("")
    if comparison.get("regressed"):
        lines.append("**Verdict:** `regressed`")
        lines.append("")
        if comparison.get("newly_unblocked"):
            lines.append("### Newly unblocked probes")
            lines.append("")
            for name in comparison["newly_unblocked"]:
                lines.append(f"- `{name}`")
            lines.append("")
        for detail in comparison.get("details", []):
            if detail["kind"] == "block_rate_drop":
                lines.append(f"- Block rate drop: {detail['detail']}")
            elif detail["kind"] == "control_failed":
                lines.append("- Benign control failed (was passing in baseline)")
        lines.append("")
    else:
        lines.append("**Verdict:** `no regressions`")
        lines.append("")
    return "\n".join(lines)
