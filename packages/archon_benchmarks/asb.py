"""Agent Security Bench (ASB) direct-injection harness (BENCH-ASB, item 82).

ASB (agiresearch/ASB, ICLR 2025, arXiv:2410.02644) is the agent-security
benchmark cited by the AgentFlow/APC papers; its "direct prompt injection"
(DPI) mode tampers the user prompt so the agent executes attacker-specified
tool calls across 10 domain agents and 400 attacker tools.

This harness runs each DPI case through Archon's deterministic reference
defense pipeline (BattleManager + InMemoryRegistry + SecurityPolicy) and
reports block rate / ASR overall and per attack type:

- ``stealthy``   = Stealthy Attack tools  -> category ``asb_dpi_stealthy``
- ``disruptive`` = Disruptive Attack tools -> category ``asb_dpi_disruptive``

The official corpus is fetched from the published GitHub raw URLs
(data/all_attack_tools.jsonl + data/agent_task.jsonl) and cached under
``~/.cache/archon/asb/``. Fully offline runs pass using only the committed
fixture (a representative deterministic sample of the official corpus —
NOT a surrogate). Zero LLM calls.

NOTE: this module covers the *Agent Security Bench* used by AgentFlow/APC.
Agent-SafetyBench is a different benchmark handled by ``asb_safety.py``;
that module owns ``data/asb_fixture.json``, which is why this fixture file
is named ``data/asb_security_fixture.json``.
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

RAW_BASE = "https://raw.githubusercontent.com/agiresearch/ASB/main/data"
OFFICIAL_REPO = "https://github.com/agiresearch/ASB"
CORPUS_FILES = ("all_attack_tools.jsonl", "agent_task.jsonl")
CACHE_DIR = Path.home() / ".cache" / "archon" / "asb"
# data/asb_fixture.json belongs to asb_safety.py (Agent-SafetyBench).
FIXTURE_PATH = Path(__file__).parent / "data" / "asb_security_fixture.json"

_TYPE_CATEGORY = {
    "Stealthy Attack": "asb_dpi_stealthy",
    "Disruptive Attack": "asb_dpi_disruptive",
}
_TYPE_KEY = {"Stealthy Attack": "stealthy", "Disruptive Attack": "disruptive"}


@dataclass(frozen=True)
class ASBSecurityCase:
    agent: str                 # e.g. financial_analyst_agent
    case_id: int               # stable ordering within the loaded set
    user_task: str             # benign task from the agent's scenario
    attacker_tool: str         # e.g. CredentialHarvesting
    attacker_instruction: str  # DPI payload injected into the user prompt
    attack_type: str           # Stealthy Attack | Disruptive Attack


def _to_case(record: dict, case_id: int) -> ASBSecurityCase:
    return ASBSecurityCase(
        agent=record["agent"],
        case_id=case_id,
        user_task=record["user_task"],
        attacker_tool=record["attacker_tool"],
        attacker_instruction=record["attacker_instruction"],
        attack_type=record["attack_type"],
    )


def download_asb_corpus() -> dict[str, int]:
    """Fetch the official ASB corpus files into CACHE_DIR; return counts."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for filename in CORPUS_FILES:
        dest = CACHE_DIR / filename
        if not dest.exists():
            url = f"{RAW_BASE}/{filename}"
            with urllib.request.urlopen(url, timeout=60) as resp:
                text = resp.read().decode()
            if not text.strip():
                raise OSError(f"empty response for {filename}")
            dest.write_text(text)
        counts[filename] = len(
            [line for line in dest.read_text().splitlines() if line.strip()])
    return counts


def _build_cases_from_cache(force_refresh: bool = False) -> list[ASBSecurityCase]:
    """Pair benign tasks with their agent's DPI instructions deterministically."""
    paths = {f: CACHE_DIR / f for f in CORPUS_FILES}
    have_cache = all(p.exists() for p in paths.values())
    if force_refresh or not have_cache:
        download_asb_corpus()

    tasks_by_agent: dict[str, list[str]] = {}
    for line in paths["agent_task.jsonl"].read_text().splitlines():
        if line.strip():
            record = json.loads(line)
            tasks_by_agent[record["agent_name"]] = record["tasks"]

    cases: list[ASBSecurityCase] = []
    for line in paths["all_attack_tools.jsonl"].read_text().splitlines():
        if not line.strip():
            continue
        tool = json.loads(line)
        agent = tool["Corresponding Agent"]
        agent_tasks = tasks_by_agent.get(agent)
        if not agent_tasks:
            continue
        # Deterministic pairing: index the benign task by position in the
        # per-agent tool listing so every run yields identical cases.
        idx = len([c for c in cases if c.agent == agent])
        cases.append(_to_case({
            "agent": agent,
            "user_task": agent_tasks[idx % len(agent_tasks)],
            "attacker_tool": tool["Attacker Tool"],
            "attacker_instruction": tool["Attacker Instruction"],
            "attack_type": tool["Attack Type"],
        }, len(cases)))
    return cases


def load_asb_fixture() -> list[ASBSecurityCase]:
    """Load the committed fixture (offline tests, no network ever).

    Fixture provenance: a representative deterministic sample of the official
    agiresearch/ASB DPI corpus (first 2 Stealthy + first 1 Disruptive attacker
    tools per agent, paired with the agents' own benign tasks), NOT a
    surrogate from other benchmarks.
    """
    raw = json.loads(FIXTURE_PATH.read_text())
    return [_to_case(r, i) for i, r in enumerate(raw)]


def load_asb(mode: str = "direct_injection",
             force_refresh: bool = False) -> list[ASBSecurityCase]:
    """ASB direct-injection cases: cache -> network -> fixture fallback."""
    if mode != "direct_injection":
        raise ValueError(
            f"unsupported ASB mode {mode!r}; only 'direct_injection' "
            "(DPI, arXiv:2410.02644 Sec. 4.1.1) is implemented")
    try:
        cases = _build_cases_from_cache(force_refresh=force_refresh)
    except OSError:
        if force_refresh:
            raise
        # offline: fall back to the committed fixture rather than failing
        return load_asb_fixture()
    if force_refresh:
        return cases
    try:
        download_asb_corpus()
    except OSError:
        return cases or load_asb_fixture()
    return cases


def build_attack_prompts(cases) -> list[Probe]:
    """One Probe per DPI case: benign user task with the injected instruction
    appended directly to the user prompt (the ASB DPI surface)."""
    prompts: list[Probe] = []
    for case in cases:
        payload = (
            f"--- User instruction ---\n{case.user_task}\n\n"
            f"{case.attacker_instruction}"
        )
        prompts.append(Probe(
            name=f"asb_dpi_{case.case_id:04d}_{case.attacker_tool}",
            payload=payload,
            category=_TYPE_CATEGORY[case.attack_type],
        ))
    return prompts


def _reference_manager() -> BattleManager:
    registry = InMemoryRegistry()
    registry.register(AgentCard(
        agent_id="bench", name="benchmark-target", version="1",
        policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
    return BattleManager(registry)


def run_asb_benchmark(cases: list[ASBSecurityCase] | None = None,
                      fixture_only: bool = False) -> dict:
    """Run all ASB DPI attacks through the reference pipeline.

    Deterministic tier only: normalization + rule-based threat
    classification, zero LLM calls. Pass ``cases=load_asb_fixture()`` for
    the fast offline run; default loads cache/network with fixture fallback.
    """
    if cases is None:
        cases = load_asb()
    probes = build_attack_prompts(cases)

    manager = _reference_manager()
    battle = manager.create("bench")
    asyncio.run(manager.execute(battle.battle_id, probes=probes))

    return _aggregate(battle.results, total_cases=len(cases),
                      fixture_only=fixture_only)


def _aggregate(results, total_cases: int, fixture_only: bool) -> dict:
    def stats(subset) -> dict:
        blocked = sum(1 for r in subset if r.blocked)
        n = len(subset)
        return {
            "cases": n,
            "blocked": blocked,
            "block_rate": round(blocked / n, 4) if n else 0.0,
            "asr": round((n - blocked) / n, 4) if n else 0.0,
        }

    per_type_buckets: dict[str, list] = {}
    for r in results:
        atk_type = next(k for k, v in _TYPE_CATEGORY.items()
                        if v == r.category)
        per_type_buckets.setdefault(_TYPE_KEY[atk_type], []).append(r)

    report = {
        "benchmark": "asb",
        "mode": "direct_injection",
        "total_cases": total_cases,
        **stats(results),
        "per_attack_type": {k: stats(v)
                            for k, v in sorted(per_type_buckets.items())},
        "artifact_status": {
            "fixture_only_run": fixture_only,
            "official_repo": OFFICIAL_REPO,
            "official_corpus_files": [
                f"data/{f}" for f in CORPUS_FILES],
            "provenance": (
                "Official agiresearch/ASB corpus (ICLR 2025, "
                "arXiv:2410.02644); fixture is a deterministic sample of "
                "the released files, not a surrogate."
            ),
        },
        "measurement": {
            "attempt_budget": 1,
            "adaptivity": "static",
            "judge": "deterministic-rules",
            "upstream_model": None,
        },
    }
    # always publish both attack types, even if one bucket is empty
    for key in ("stealthy", "disruptive"):
        report["per_attack_type"].setdefault(key, {"cases": 0, "blocked": 0,
                                                   "block_rate": 0.0,
                                                   "asr": 0.0})
    return report


def render_asb_md(report: dict, path: Path) -> None:
    lines = [
        "# Benchmark Results: Agent Security Bench (Direct Prompt Injection)",
        "",
        f"Corpus: **{report['total_cases']} DPI test cases** "
        "(direct prompt injections over 10 domain agents, ICLR 2025, "
        "arXiv:2410.02644). Each injected user prompt is sent through "
        "Archon's deterministic reference defense pipeline.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack Success Rate (ASR) | **{report['asr']:.1%}** |",
        f"| Block rate | **{report['block_rate']:.1%}** |",
        "",
        "| Attack type | Cases | Blocked | Block rate | ASR |",
        "|---|---|---|---|---|",
    ]
    for key in ("stealthy", "disruptive"):
        s = report["per_attack_type"][key]
        lines.append(
            f"| {key} | {s['cases']} | {s['blocked']} | "
            f"{s['block_rate']:.1%} | {s['asr']:.1%} |"
        )
    m = report["measurement"]
    a = report["artifact_status"]
    lines += [
        "",
        "## Methodology",
        "",
        f"- Attempt budget: {m['attempt_budget']} (single static attempt per case)",
        f"- Adaptivity: {m['adaptivity']}",
        f"- Judge: {m['judge']} (fully offline, reproducible)",
        f"- Upstream model: {m['upstream_model']} (deterministic tier)",
        "- Attack types: `stealthy` = covert attacker tools; `disruptive` = "
        "availability/destruction tools.",
        "",
        "## Artifact availability",
        "",
        f"- Official repo: {a['official_repo']} "
        f"(files: {', '.join(a['official_corpus_files'])})",
        f"- Fixture-only run: {a['fixture_only_run']}",
        f"- Provenance: {a['provenance']}",
        "",
        "Reproduce with `uv run python -m archon_benchmarks.asb`.",
        "",
    ]
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    import sys

    report = run_asb_benchmark()
    print(json.dumps(report, indent=2))
    if len(sys.argv) > 1:
        render_asb_md(report, Path(sys.argv[1]))
