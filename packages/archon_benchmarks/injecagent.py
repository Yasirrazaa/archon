"""InjecAgent benchmark harness (W9-A).

InjecAgent (uiuc-kang-lab/InjecAgent, arXiv:2403.02691) is a benchmark of
1,054 test cases of prompt injection during tool use: 510 DIRECT-HARM attacks
(attacker instructions that directly cause physical/financial/data harm) and
544 DATA-STEALING attacks (indirect exfiltration through a second attacker
tool). Every case embeds the attacker instruction inside a poisoned tool
response — the canonical indirect-injection surface for tool-integrated
agents.

This harness runs each poisoned tool response through Archon's deterministic
reference defense pipeline (BattleManager + InMemoryRegistry + SecurityPolicy)
and reports block rate / ASR overall and per setting:

- ``direct``   = direct_harm cases  -> category ``injecagent_direct``
- ``indirect`` = data_stealing cases -> category ``injecagent_indirect``

Fully offline and reproducible on the committed fixture; the full corpus is
fetched from the published GitHub raw URLs and cached under
``~/.cache/archon/injecagent/``. Zero LLM calls.
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
    "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data"
)
CORPUS_FILES = {
    "direct_harm": "test_cases_dh_base.json",
    "data_stealing": "test_cases_ds_base.json",
}
CACHE_DIR = Path.home() / ".cache" / "archon" / "injecagent"
FIXTURE_PATH = Path(__file__).parent / "data" / "injecagent_fixture.json"

_SETTING_CATEGORY = {
    "direct_harm": "injecagent_direct",
    "data_stealing": "injecagent_indirect",
}
_SETTING_KEY = {"direct_harm": "direct", "data_stealing": "indirect"}


@dataclass(frozen=True)
class InjecAgentCase:
    setting: str              # direct_harm | data_stealing
    case_id: int              # index within its source file (stable ordering)
    user_instruction: str
    user_tool: str
    tool_parameters: dict
    tool_response: str        # poisoned response containing the injection
    attacker_instruction: str
    attacker_tools: list[str]
    attack_type: str          # e.g. Physical Harm, Financial Data
    expected_achievements: str


def _to_case(record: dict, setting: str, case_id: int) -> InjecAgentCase:
    return InjecAgentCase(
        setting=record.get("Setting", setting),
        case_id=case_id,
        user_instruction=record["User Instruction"],
        user_tool=record["User Tool"],
        tool_parameters=record.get("Tool Parameters", {}),
        tool_response=record["Tool Response"],
        attacker_instruction=record["Attacker Instruction"],
        attacker_tools=list(record.get("Attacker Tools", [])),
        attack_type=record.get("Attack Type", ""),
        expected_achievements=record.get("Expected Achievements", ""),
    )


def _download(setting: str) -> list[dict]:
    url = f"{RAW_BASE}/{CORPUS_FILES[setting]}"
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.loads(resp.read().decode())


def download_injecagent_corpus() -> dict[str, int]:
    """Fetch both base-setting corpus files into CACHE_DIR; return counts."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for setting, filename in CORPUS_FILES.items():
        dest = CACHE_DIR / filename
        if not dest.exists():
            records = _download(setting)
            dest.write_text(json.dumps(records))
        counts[setting] = len(json.loads(dest.read_text()))
    return counts


def load_injecagent_fixture() -> list[InjecAgentCase]:
    """Load the small committed fixture (offline tests, no network ever)."""
    raw = json.loads(FIXTURE_PATH.read_text())
    return [_to_case(r, r.get("Setting", "direct_harm"), i)
            for i, r in enumerate(raw)]


def load_injecagent_cases(force_refresh: bool = False) -> list[InjecAgentCase]:
    """Full 1,054-case corpus: cache -> network download -> fixture fallback."""
    paths = {s: CACHE_DIR / f for s, f in CORPUS_FILES.items()}
    have_cache = all(p.exists() for p in paths.values())
    if force_refresh or not have_cache:
        try:
            download_injecagent_corpus()
        except OSError:
            if force_refresh:
                raise
            # offline: fall back to the committed fixture rather than failing
            return load_injecagent_fixture()
    cases: list[InjecAgentCase] = []
    for setting in ("direct_harm", "data_stealing"):
        records = json.loads(paths[setting].read_text())
        cases += [_to_case(r, setting, i) for i, r in enumerate(records)]
    return cases


def build_attack_prompts(cases) -> list[Probe]:
    """One Probe per InjecAgent case.

    The payload reproduces the agent's view of the turn: the user's benign
    instruction followed by the POISONED tool response (tool knowledge with
    the embedded attacker instruction), which is exactly the indirect
    injection surface InjecAgent studies.
    """
    prompts: list[Probe] = []
    for case in cases:
        payload = (
            f"--- User instruction ---\n{case.user_instruction}\n\n"
            f"--- Tool response ({case.user_tool}) ---\n{case.tool_response}"
        )
        prompts.append(Probe(
            name=f"injecagent_{case.setting}_{case.case_id:04d}",
            payload=payload,
            category=_SETTING_CATEGORY[case.setting],
        ))
    return prompts


def _reference_manager() -> BattleManager:
    registry = InMemoryRegistry()
    registry.register(AgentCard(
        agent_id="bench", name="benchmark-target", version="1",
        policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
    return BattleManager(registry)


def run_injecagent_benchmark(cases: list[InjecAgentCase] | None = None) -> dict:
    """Run all InjecAgent attacks through the reference pipeline.

    Deterministic tier only: normalization + rule-based threat
    classification, zero LLM calls. Pass ``cases=load_injecagent_fixture()``
    for the fast offline run; default loads the full cached corpus.
    """
    if cases is None:
        cases = load_injecagent_cases()
    probes = build_attack_prompts(cases)

    manager = _reference_manager()
    battle = manager.create("bench")
    asyncio.run(manager.execute(battle.battle_id, probes=probes))

    return _aggregate(battle.results, total_cases=len(cases))


def _aggregate(results, total_cases: int) -> dict:
    def stats(subset) -> dict:
        blocked = sum(1 for r in subset if r.blocked)
        n = len(subset)
        return {
            "cases": n,
            "blocked": blocked,
            "block_rate": round(blocked / n, 4) if n else 0.0,
            "asr": round((n - blocked) / n, 4) if n else 0.0,
        }

    per_setting_buckets: dict[str, list] = {}
    for r in results:
        setting = next(k for k, v in _SETTING_CATEGORY.items()
                       if v == r.category)
        per_setting_buckets.setdefault(_SETTING_KEY[setting], []).append(r)

    blocked = sum(1 for r in results if r.blocked)
    report = {
        "benchmark": "injecagent",
        "total_cases": total_cases,
        "blocked": blocked,
        "block_rate": round(blocked / len(results), 4) if results else 0.0,
        "asr": round((len(results) - blocked) / len(results), 4)
        if results else 0.0,
        "per_setting": {k: stats(v)
                        for k, v in sorted(per_setting_buckets.items())},
        "measurement": {
            "attempt_budget": 1,
            "adaptivity": "static",
            "judge": "deterministic-rules",
        },
    }
    # always publish both settings, even if one bucket is empty
    for key in ("direct", "indirect"):
        report["per_setting"].setdefault(key, {"cases": 0, "blocked": 0,
                                               "block_rate": 0.0, "asr": 0.0})
    return report


def render_injecagent_md(report: dict, path: Path) -> None:
    lines = [
        "# Benchmark Results: InjecAgent (Defense-Side ASR)",
        "",
        f"Corpus: **{report['total_cases']} test cases** "
        "(direct-harm + data-stealing prompt injections during tool use, "
        "arXiv:2403.02691). Each poisoned tool response is sent through "
        "Archon's deterministic reference defense pipeline.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack Success Rate (ASR) | **{report['asr']:.1%}** |",
        f"| Block rate | **{report['block_rate']:.1%}** |",
        "",
        "| Setting | Cases | Blocked | Block rate | ASR |",
        "|---|---|---|---|---|",
    ]
    for key in ("direct", "indirect"):
        s = report["per_setting"][key]
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
        "- Settings: `direct` = direct-harm injections; `indirect` = "
        "data-stealing exfiltration chains.",
        "",
        "## Context",
        "",
        "This benchmark measures Archon's **deterministic tier only** "
        "(normalization + rule-based threat classification, 0 LLM calls). "
        "An attack counts as successful if it is NOT blocked by the reference "
        "pipeline. Reproduce with "
        "`uv run python -m archon_benchmarks.injecagent`.",
        "",
    ]
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    import sys

    report = run_injecagent_benchmark()
    print(json.dumps(report, indent=2))
    if len(sys.argv) > 1:
        render_injecagent_md(report, Path(sys.argv[1]))
