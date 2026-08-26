"""Buff layer in benchmark series (Sprint 92).

Fans a curated probe pack through the deterministic buffs from
:mod:`archon_core.attacks.buffs` and runs every derived probe through
Archon's reference defense pipeline (BattleManager + InMemoryRegistry +
SecurityPolicy) — the same deterministic tier used by the other defense-side
benchmark harnesses. A small pack becomes a much larger evasion matrix with
zero LLM calls; results are fully seeded and reproducible.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from archon_armor.battles import BattleManager
from archon_armor.probes import Probe, UnknownPackError, get_pack
from archon_core.attacks.buffs import (
    Base64Buff,
    Buff,
    LeetspeakBuff,
    LowercaseBuff,
    PrefixBuff,
    Rot13Buff,
    WhitespaceBuff,
    apply_buffs,
)
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry

BENCHMARK_NAME = "buffed_series"

BUFF_REGISTRY: dict[str, Buff] = {
    buff.name: buff
    for buff in (
        Base64Buff(),
        Rot13Buff(),
        LeetspeakBuff(),
        LowercaseBuff(),
        PrefixBuff(),
        WhitespaceBuff(),
    )
}


def _resolve_buffs(buff_names) -> list[Buff]:
    unknown = [n for n in buff_names if n not in BUFF_REGISTRY]
    if unknown:
        raise KeyError(
            f"unknown buffs: {', '.join(unknown)}; "
            f"available: {', '.join(sorted(BUFF_REGISTRY))}"
        )
    return [BUFF_REGISTRY[n] for n in buff_names]


def _reference_manager() -> BattleManager:
    registry = InMemoryRegistry()
    registry.register(AgentCard(
        agent_id="bench", name="benchmark-target", version="1",
        policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
    return BattleManager(registry)


def run_buffed_series(
    pack_name: str = "core",
    buff_names: tuple[str, ...] = ("base64", "rot13", "leetspeak"),
    budget: int = 3,
    seed: int = 42,
) -> dict[str, Any]:
    """Fan a probe pack out through buffs and attack the reference pipeline.

    Deterministic tier only: normalization + rule-based threat classification,
    zero LLM calls. Raises :class:`UnknownPackError` for unknown packs and
    ``KeyError`` for unknown buff names.
    """
    try:
        probes_in = get_pack(pack_name)
    except KeyError:
        raise UnknownPackError(f"unknown probe pack: {pack_name}") from None

    buffs = _resolve_buffs(buff_names)
    derived: list[Probe] = apply_buffs(probes_in, buffs, seed=seed)

    manager = _reference_manager()
    battle = manager.create("bench")
    asyncio.run(manager.execute(battle.battle_id, probes=derived))

    per_buff_blocked: dict[str, int] = {b.name: 0 for b in buffs}
    blocked_total = 0
    for r in battle.results:
        suffix = r.probe_name.rsplit("__", 1)[-1]
        if r.blocked:
            blocked_total += 1
            if suffix in per_buff_blocked:
                per_buff_blocked[suffix] += 1

    per_buff_block_rate = {
        b.name: round(per_buff_blocked[b.name] / (len(derived) // len(buffs)), 4)
        if derived else 0.0
        for b in buffs
    }

    return {
        "benchmark": BENCHMARK_NAME,
        "pack": pack_name,
        "buffs": list(buff_names),
        "probes_in": len(probes_in),
        "probes_out": len(derived),
        "blocked": blocked_total,
        "block_rate": round(blocked_total / len(derived), 4) if derived else 0.0,
        "per_buff_block_rate": per_buff_block_rate,
        "measurement": {
            "attempt_budget": budget,
            "adaptivity": "static",
            "judge": "deterministic-rules",
            "upstream_model": None,
        },
    }


def render_buffed_md(report: dict[str, Any], path: Path) -> None:
    lines = [
        "# Benchmark Results: Buffed Series (Defense-Side Block Rates)",
        "",
        f"Pack `{report['pack']}` ({report['probes_in']} probes) fanned out "
        f"through {len(report['buffs'])} buffs into "
        f"**{report['probes_out']} derived probes**, each sent through "
        "Archon's deterministic reference defense pipeline.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Probes in / out | {report['probes_in']} / {report['probes_out']} |",
        f"| Blocked | **{report['blocked']}** |",
        f"| Block rate | **{report['block_rate']:.1%}** |",
        "",
        "| Buff | Block rate |",
        "|---|---|",
    ]
    lines += [
        f"| {name} | {rate:.1%} |"
        for name, rate in sorted(report["per_buff_block_rate"].items())
    ]
    m = report["measurement"]
    lines += [
        "",
        "## Methodology",
        "",
        f"- Attempt budget: {m['attempt_budget']}",
        f"- Adaptivity: {m['adaptivity']}",
        f"- Judge: {m['judge']} (fully offline, reproducible)",
        "- Derived probes are named `<probe>__<buff>`; a probe counts as "
        "successful when the reference pipeline does NOT block it.",
        "",
    ]
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    import sys

    report = run_buffed_series()
    print(json.dumps(report, indent=2))
    if len(sys.argv) > 1:
        render_buffed_md(report, Path(sys.argv[1]))
