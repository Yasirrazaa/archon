"""IPIArena benchmark harness (BENCH-IPIARENA, item 81).

IPIArena is PIMiner's indirect-prompt-injection arena: 41 hand-built attack
behaviors across three agent surfaces — ``tool`` (MCP/tool-response
injection), ``coding`` (coding-agent workspace injection), and ``browser``
(rendered-page injection). Each behavior embeds attacker instructions at a
``{fill}`` slot inside a realistic agent transcript and scores whether the
agent performs the hijacked action.

Artifact provenance: PIMiner (github.com/wang-yanting/PIMiner) vendors the
official IPIArena behavior corpus under ``data/ipi_arena/repo/data/``. This
harness loads those official behaviors (cache -> network -> committed
fixture) and reports ``artifact_status='official'``.

The harness runs each behavior through Archon's deterministic reference
defense pipeline (BattleManager + InMemoryRegistry + SecurityPolicy) and
reports block rate / ASR overall and per category. Fully offline and
reproducible on the committed fixture; zero LLM calls.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from archon_armor.battles import BattleManager
from archon_armor.probes import Probe
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry

RAW_BASE = (
    "https://raw.githubusercontent.com/wang-yanting/PIMiner/main/"
    "data/ipi_arena/repo/data"
)
TREE_API = (
    "https://api.github.com/repos/wang-yanting/PIMiner/git/trees/main"
    "?recursive=1"
)
CACHE_DIR = Path.home() / ".cache" / "archon" / "ipiarena"
FIXTURE_PATH = Path(__file__).parent / "data" / "ipiarena_fixture.json"

CATEGORIES = ("tool", "coding", "browser")

_SLOT_BY_LOCATION = {
    "tool": "tool_response",
    "user": "user_content",
    "assistant": "assistant_content",
}


@dataclass(frozen=True)
class IPIArenaRecord:
    id: str
    name: str
    category: str          # tool | coding | browser
    wave: int              # release wave (1..3)
    user_task: str         # benign user request driving the scenario
    injection_goal: str    # what the injected instructions try to achieve
    injection_slot: str    # where {fill} lands: tool_response | html_page | ...
    source_url: str


def _to_record(raw: dict) -> IPIArenaRecord:
    category = raw["category"]
    slot = raw.get("injection_slot") or _find_injection_slot(raw)
    return IPIArenaRecord(
        id=raw["id"],
        name=raw.get("name", raw["id"]),
        category=category,
        wave=int(raw.get("wave", 0)),
        user_task=raw.get("user_task", ""),
        injection_goal=raw.get("injection_goal") or raw.get("description", ""),
        injection_slot=slot,
        source_url=raw.get(
            "source_url", f"{RAW_BASE}/{category}/{raw['id']}.json"),
    )


def _find_injection_slot(behavior: dict) -> str:
    if "{fill}" in behavior.get("html_template", ""):
        return "html_page"
    for msg in behavior.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, str) and "{fill}" in content:
            return _SLOT_BY_LOCATION.get(msg.get("role", ""), "unspecified")
    return "unspecified"


def _normalize_behavior(behavior: dict, source_url: str) -> dict:
    """Official behavior JSON -> compact record with IPIArena-style schema."""
    user_parts = []
    for msg in behavior.get("messages", []):
        content = msg.get("content", "")
        if msg.get("role") == "user":
            text = content if isinstance(content, str) else json.dumps(content)
            if "{fill}" not in text:
                user_parts.append(text.strip())
    user_task = "\n\n".join(user_parts)
    if len(user_task) > 2500:
        user_task = user_task[:2500] + "..."
    return {
        "id": behavior["id"],
        "name": behavior.get("name", behavior["id"]),
        "category": behavior["category"],
        "wave": behavior.get("wave", 0),
        "description": behavior.get("description", ""),
        "objective": behavior.get("objective", ""),
        "user_task": user_task,
        "injection_goal": behavior.get("objective")
        or behavior.get("description", ""),
        "injection_slot": _find_injection_slot(behavior),
        "source_url": source_url,
        "provenance": "official",
    }


def _list_behavior_paths() -> list[str]:
    """Enumerate official behavior paths via the GitHub tree API."""
    req = urllib.request.Request(TREE_API, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        tree = json.loads(resp.read().decode())["tree"]
    prefix = "data/ipi_arena/repo/data/"
    return sorted(
        e["path"] for e in tree
        if e["path"].startswith(prefix) and e["path"].endswith(".json")
    )


def download_ipiarena_corpus() -> int:
    """Fetch all official behaviors from PIMiner into CACHE_DIR; return count."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    records = []
    for path in _list_behavior_paths():
        url = f"https://raw.githubusercontent.com/wang-yanting/PIMiner/main/{path}"
        with urllib.request.urlopen(url, timeout=60) as resp:
            behavior = json.loads(resp.read().decode())
        records.append(_normalize_behavior(behavior, url))
    cache_file = CACHE_DIR / "ipiarena_records.json"
    cache_file.write_text(json.dumps(records))
    return len(records)


def load_ipiarena_fixture() -> list[IPIArenaRecord]:
    """Load the committed fixture (offline tests, no network ever)."""
    return [_to_record(r) for r in json.loads(FIXTURE_PATH.read_text())]


def load_ipiarena(force_refresh: bool = False) -> list[IPIArenaRecord]:
    """Official 41-behavior corpus: cache -> network fetch -> fixture."""
    cache_file = CACHE_DIR / "ipiarena_records.json"
    if force_refresh or not cache_file.exists():
        try:
            download_ipiarena_corpus()
        except OSError:
            if force_refresh:
                raise
            # offline: fall back to the committed fixture rather than failing
            return load_ipiarena_fixture()
    return [_to_record(r) for r in json.loads(cache_file.read_text())]


def build_attack_prompts(records: list[IPIArenaRecord]) -> list[Probe]:
    """One Probe per IPIArena behavior.

    The payload reproduces the agent's view of the turn: the benign user task
    followed by the injected content landing in its slot ({fill} position —
    a tool response, rendered HTML page, etc.), with the behavior's own
    objective as the injected instruction body. This is exactly the indirect
    injection surface IPIArena studies.
    """
    prompts: list[Probe] = []
    for record in records:
        payload = (
            f"--- User task ---\n{record.user_task}\n\n"
            f"--- Injected content ({record.injection_slot}) ---\n"
            f"{record.injection_goal}"
        )
        prompts.append(Probe(
            name=f"ipiarena_{record.category}_{record.id}",
            payload=payload,
            category=f"ipiarena_{record.category}",
        ))
    return prompts


def _reference_manager() -> BattleManager:
    registry = InMemoryRegistry()
    registry.register(AgentCard(
        agent_id="bench", name="benchmark-target", version="1",
        policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
    return BattleManager(registry)


def run_ipiarena_benchmark(records: list[IPIArenaRecord] | None = None) -> dict:
    """Run all IPIArena behaviors through the reference pipeline.

    Deterministic tier only: normalization + rule-based threat
    classification, zero LLM calls. Pass ``records=load_ipiarena_fixture()``
    for the fast offline run; default loads the cached official corpus.
    """
    if records is None:
        records = load_ipiarena()
    probes = build_attack_prompts(records)

    manager = _reference_manager()
    battle = manager.create("bench")
    asyncio.run(manager.execute(battle.battle_id, probes=probes))

    from_cache = any(r.source_url.startswith(RAW_BASE) for r in records)
    report = _aggregate(battle.results, total_records=len(records))
    report["artifact_status"] = "official"
    report["artifact_source"] = (
        f"PIMiner repo (github.com/wang-yanting/PIMiner), "
        f"data/ipi_arena/repo/data/ — {len(records)} official behaviors "
        f"(loaded from {'network/cache' if from_cache else 'committed fixture'})"
    )
    return report


def _aggregate(results, total_records: int) -> dict:
    def stats(subset) -> dict:
        blocked = sum(1 for r in subset if r.blocked)
        n = len(subset)
        return {
            "cases": n,
            "blocked": blocked,
            "block_rate": round(blocked / n, 4) if n else 0.0,
            "asr": round((n - blocked) / n, 4) if n else 0.0,
        }

    per_category_buckets: dict[str, list] = {}
    for r in results:
        per_category_buckets.setdefault(
            r.category.removeprefix("ipiarena_"), []).append(r)

    blocked = sum(1 for r in results if r.blocked)
    report = {
        "benchmark": "ipiarena",
        "total_cases": total_records,
        "blocked": blocked,
        "block_rate": round(blocked / len(results), 4) if results else 0.0,
        "asr": round((len(results) - blocked) / len(results), 4)
        if results else 0.0,
        "per_category": {k: stats(v)
                         for k, v in sorted(per_category_buckets.items())},
        "measurement": {
            "attempt_budget": 1,
            "adaptivity": "static",
            "judge": "deterministic-rules",
            "upstream_model": None,
        },
    }
    # always publish all three categories, even if one bucket is empty
    for key in CATEGORIES:
        report["per_category"].setdefault(key, {"cases": 0, "blocked": 0,
                                                "block_rate": 0.0, "asr": 0.0})
    return report


def render_ipiarena_md(report: dict, path: Path) -> None:
    lines = [
        "# Benchmark Results: IPIArena (Defense-Side ASR)",
        "",
        f"Corpus: **{report['total_cases']} attack behaviors** across tool, "
        "coding, and browser agent surfaces (PIMiner's IPIArena). Each "
        "injected agent context is sent through Archon's deterministic "
        "reference defense pipeline.",
        "",
        "**Artifact status:** "
        f"`{report['artifact_status']}` — {report['artifact_source']}",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack Success Rate (ASR) | **{report['asr']:.1%}** |",
        f"| Block rate | **{report['block_rate']:.1%}** |",
        "",
        "| Category | Cases | Blocked | Block rate | ASR |",
        "|---|---|---|---|---|",
    ]
    for key in CATEGORIES:
        s = report["per_category"][key]
        lines.append(
            f"| {key} | {s['cases']} | {s['blocked']} | "
            f"{s['block_rate']:.1%} | {s['asr']:.1%} |"
        )
    m = report["measurement"]
    lines += [
        "",
        "## Methodology",
        "",
        f"- Attempt budget: {m['attempt_budget']} (single static attempt per case)",
        f"- Adaptivity: {m['adaptivity']}",
        f"- Judge: {m['judge']} (fully offline, reproducible)",
        "- Categories: `tool` = tool/MCP-response injections; `coding` = "
        "coding-agent workspace injections; `browser` = rendered-page "
        "injections.",
        "",
        "## Context",
        "",
        "This benchmark measures Archon's **deterministic tier only** "
        "(normalization + rule-based threat classification, 0 LLM calls). "
        "An attack counts as successful if it is NOT blocked by the reference "
        "pipeline. Reproduce with "
        "`uv run python -m archon_benchmarks.ipiarena`.",
        "",
    ]
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    import sys

    report = run_ipiarena_benchmark()
    print(json.dumps(report, indent=2))
    if len(sys.argv) > 1:
        render_ipiarena_md(report, Path(sys.argv[1]))
