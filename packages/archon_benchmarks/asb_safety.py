"""Agent-SafetyBench benchmark harness (Sprint BENCH-ASB-SAFETY).

Agent-SafetyBench (thu-coai/Agent-SafetyBench, HF ``thu-coai/Agent-SafetyBench``,
arXiv:2412.14470) is a behavioral-safety benchmark of 349 interaction
environments and 2,000 test cases covering **8 published risk categories**
(250 cases each) and 10 failure modes frequently seen in unsafe agent
interactions:

1. Leak sensitive data / information
2. Lead to property loss
3. Spread unsafe information / misinformation
4. Lead to physical harm
5. Violate law or ethics / damage society
6. Compromise availability
7. Contribute to harmful / vulnerable code
8. Produce unsafe information / misinformation

(The paper's "10" refers to failure *modes*, not risk categories; this
harness reports per-category results for all 8 published categories.)

Each case carries an instruction that, if executed in its environment,
produces an unsafe outcome. This harness runs each instruction through
Archon's deterministic reference defense pipeline (BattleManager +
InMemoryRegistry + SecurityPolicy) and reports block rate / ASR overall and
per category, plus a false-positive-rate guard over any benign samples
present in the pack (the released pack ships none — reported honestly).

Fully offline and reproducible on the committed fixture; the full 2,000-case
corpus is fetched from the single published raw GitHub URL and cached under
``~/.cache/archon/agentsafetybench/``. Zero LLM calls.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from archon_armor.battles import BattleManager
from archon_armor.probes import Probe
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry

RAW_URL = (
    "https://raw.githubusercontent.com/thu-coai/Agent-SafetyBench/main/"
    "data/released_data.json"
)
CORPUS_FILENAME = "released_data.json"
CACHE_DIR = Path.home() / ".cache" / "archon" / "agentsafetybench"
FIXTURE_PATH = Path(__file__).parent / "data" / "asb_fixture.json"

RISK_CATEGORY_SLUGS = {
    "Leak sensitive data / information": "leak_sensitive_data",
    "Lead to property loss": "property_loss",
    "Spread unsafe information / misinformation": "spread_misinformation",
    "Lead to physical harm": "physical_harm",
    "Violate law or ethics / damage society": "violate_law_ethics",
    "Compromise availability": "compromise_availability",
    "Contribute to harmful / vulnerable code": "harmful_code",
    "Produce unsafe information / misinformation": "produce_unsafe_info",
}
_SLUG_TO_CATEGORY = {v: k for k, v in RISK_CATEGORY_SLUGS.items()}
BENIGN_CATEGORY = "benign"

_LAST_LOAD_SOURCE = {"value": None}  # "cache" | "network" | "fixture"


@dataclass(frozen=True)
class ASBCase:
    category: str             # raw upstream risk string (or "benign")
    case_id: int              # upstream id (stable ordering key)
    prompt: str               # user instruction that triggers the unsafe behavior
    environments: list[dict] = field(default_factory=list)  # [{name, tools}]
    failure_modes: str = ""   # upstream comma-separated failure-mode ids

    @property
    def slug(self) -> str:
        return RISK_CATEGORY_SLUGS.get(self.category, self.category)


def _normalize(record: dict) -> dict:
    """Normalize an upstream raw record or an already-normalized fixture record."""
    if "category" in record:            # fixture / normalized shape
        return {
            "case_id": int(record["case_id"]),
            "category": record["category"],
            "prompt": record["prompt"],
            "environments": [
                {"name": e.get("name", ""), "tools": list(e.get("tools", []))}
                for e in record.get("environments", [])
            ],
            "failure_modes": str(record.get("failure_modes", "")),
        }
    return {                            # upstream released_data.json shape
        "case_id": int(record["id"]),
        "category": record["risks"][0],
        "prompt": record["instruction"],
        "environments": [
            {"name": e.get("name", ""), "tools": list(e.get("tools", []))}
            for e in record.get("environments", [])
        ],
        "failure_modes": str(record.get("failure_modes", "")),
    }


def _to_case(record: dict) -> ASBCase:
    norm = _normalize(record)
    return ASBCase(
        category=norm["category"],
        case_id=norm["case_id"],
        prompt=norm["prompt"],
        environments=norm["environments"],
        failure_modes=norm["failure_modes"],
    )


def _download() -> list[dict]:
    with urllib.request.urlopen(RAW_URL, timeout=120) as resp:
        return json.loads(resp.read().decode())


def download_asb_corpus() -> int:
    """Fetch the full corpus into CACHE_DIR; return the case count."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    dest = CACHE_DIR / CORPUS_FILENAME
    if not dest.exists():
        records = _download()
        dest.write_text(json.dumps(records))
    return len(json.loads(dest.read_text()))


def load_asb_fixture() -> list[ASBCase]:
    """Load the committed fixture (offline tests, no network ever)."""
    raw = json.loads(FIXTURE_PATH.read_text())
    _LAST_LOAD_SOURCE["value"] = "fixture"
    return [_to_case(r) for r in raw]


def load_asb(category_filter: str | None = None,
             force_refresh: bool = False) -> list[ASBCase]:
    """Load Agent-SafetyBench cases: cache -> network -> fixture fallback.

    ``category_filter`` accepts either an upstream risk string or one of the
    module's slugs (or ``"benign"``). Offline runs fall back to the committed
    fixture rather than failing.
    """
    cache_path = CACHE_DIR / CORPUS_FILENAME
    records: list[dict] | None = None
    if not force_refresh and cache_path.exists():
        try:
            records = json.loads(cache_path.read_text())
            _LAST_LOAD_SOURCE["value"] = "cache"
        except (OSError, json.JSONDecodeError):
            records = None
    if records is None:
        try:
            records = _download()
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            (CACHE_DIR / CORPUS_FILENAME).write_text(json.dumps(records))
            _LAST_LOAD_SOURCE["value"] = "network"
        except OSError:
            if force_refresh:
                raise
            # offline: fall back to the committed fixture rather than failing
            return load_asb_fixture()

    cases = [_to_case(r) for r in records]
    if category_filter is not None:
        wanted = _SLUG_TO_CATEGORY.get(category_filter, category_filter)
        cases = [c for c in cases if c.category == wanted]
    return cases


def build_attack_prompts(cases: list[ASBCase]) -> list[Probe]:
    """One Probe per Agent-SafetyBench case.

    The payload reproduces the agent's view of the turn: the user's
    instruction followed by the environment context (tool names), which is
    the surface the benchmark evaluates.
    """
    prompts: list[Probe] = []
    for case in cases:
        env_lines = [
            f"- {env['name']}: {', '.join(env['tools']) or 'no tools'}"
            for env in case.environments
        ]
        payload = (
            f"{case.prompt}"
            + ("\n\n--- Available environment ---\n" + "\n".join(env_lines)
               if env_lines else "")
        )
        probes_cat = f"asb_{case.slug}" if case.category != BENIGN_CATEGORY \
            else "asb_benign"
        prompts.append(Probe(
            name=f"asb_{case.slug}_{case.case_id:04d}",
            payload=payload,
            category=probes_cat,
        ))
    return prompts


def _reference_manager() -> BattleManager:
    registry = InMemoryRegistry()
    registry.register(AgentCard(
        agent_id="bench", name="benchmark-target", version="1",
        policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
    return BattleManager(registry)


def run_asb_benchmark(records: list | None = None) -> dict:
    """Run all Agent-SafetyBench cases through the reference pipeline.

    Deterministic tier only: normalization + rule-based threat
    classification, zero LLM calls. Pass
    ``records=load_asb_fixture()`` for the fast offline run; default loads
    the full cached corpus (fixture fallback when offline).
    """
    if records is None:
        records = load_asb()
    cases = [_to_case(r) if isinstance(r, dict) else r for r in records]
    probes = build_attack_prompts(cases)
    fixture_ids = {f.case_id for f in load_asb_fixture()}
    fixture_only = (_LAST_LOAD_SOURCE["value"] == "fixture"
                    or {c.case_id for c in cases} == fixture_ids)

    manager = _reference_manager()
    battle = manager.create("bench")
    asyncio.run(manager.execute(battle.battle_id, probes=probes))
    results = {r.probe_name: r for r in battle.results}

    blocked_by_name = {name: bool(res.blocked) for name, res in results.items()}
    return _aggregate(cases, blocked_by_name, fixture_only=fixture_only)


def _aggregate(cases: list[ASBCase], blocked_by_name: dict[str, bool],
               fixture_only: bool = False) -> dict:
    def stats(subset: list[ASBCase]) -> dict:
        blocked = sum(1 for c in subset
                      if blocked_by_name[f"asb_{c.slug}_{c.case_id:04d}"])
        n = len(subset)
        return {
            "cases": n,
            "blocked": blocked,
            "block_rate": round(blocked / n, 4) if n else 0.0,
            "asr": round((n - blocked) / n, 4) if n else 0.0,
        }

    attack_cases = [c for c in cases if c.category != BENIGN_CATEGORY]
    benign_cases = [c for c in cases if c.category == BENIGN_CATEGORY]

    overall = stats(attack_cases)
    per_category = {
        slug: stats([c for c in attack_cases if c.slug == slug])
        for slug in sorted(set(RISK_CATEGORY_SLUGS.values()))
    }
    benign_blocked = sum(
        1 for c in benign_cases
        if blocked_by_name[f"asb_benign_{c.case_id:04d}"]
    ) if benign_cases else 0
    n_benign = len(benign_cases)

    total_blocked = sum(1 for c in cases
                        if blocked_by_name[f"asb_{c.slug}_{c.case_id:04d}"])
    report = {
        "benchmark": "agent-safetybench",
        "total_cases": len(cases),
        "blocked": total_blocked,
        "block_rate": overall["block_rate"],
        "asr": overall["asr"],
        "per_category": per_category,
        "false_positive_rate": {
            "benign_cases": n_benign,
            "false_positive_rate": round(benign_blocked / n_benign, 4)
            if n_benign else None,
            "note": (
                "The released Agent-SafetyBench pack does not include benign "
                "samples; FPR guard is not included / inactive until a "
                "benign split is supplied."
                if not n_benign else
                "Fraction of benign instructions incorrectly blocked by the "
                "reference pipeline."
            ),
        },
        "artifact_status": {
            "fixture_only_run": fixture_only,
            "published_risk_categories": 8,
            "note": (
                "Agent-SafetyBench publishes 8 risk categories (250 cases "
                "each); the paper's '10' refers to failure modes. Fixture is "
                "a representative deterministic sample of the released "
                "corpus."
            ),
        },
        "measurement": {
            "attempt_budget": 1,
            "adaptivity": "static",
            "judge": "deterministic-rules",
            "upstream_model": None,
        },
    }
    return report


def render_asb_md(report: dict, path: Path) -> None:
    lines = [
        "# Benchmark Results: Agent-SafetyBench (Defense-Side ASR)",
        "",
        f"Corpus: **{report['total_cases']} test cases** across 8 published "
        "risk categories (behavioral safety of LLM agents, arXiv:2412.14470). "
        "Each unsafe instruction is sent through Archon's deterministic "
        "reference defense pipeline.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attack Success Rate (ASR) | **{report['asr']:.1%}** |",
        f"| Block rate | **{report['block_rate']:.1%}** |",
        "",
        "| Category | Cases | Blocked | Block rate | ASR |",
        "|---|---|---|---|---|",
    ]
    for slug, s in report["per_category"].items():
        lines.append(
            f"| {slug} | {s['cases']} | {s['blocked']} | "
            f"{s['block_rate']:.1%} | {s['asr']:.1%} |"
        )
    m = report["measurement"]
    fpr = report["false_positive_rate"]
    fpr_line = (f"{fpr['false_positive_rate']:.1%}"
                if fpr["false_positive_rate"] is not None else "n/a")
    lines += [
        "",
        "## Methodology",
        "",
        f"- Attempt budget: {m['attempt_budget']} (single static attempt per case)",
        f"- Adaptivity: {m['adaptivity']}",
        f"- Judge: {m['judge']} (fully offline, reproducible)",
        f"- Upstream model: {m['upstream_model']} (deterministic tier)",
        f"- False-positive guard: {fpr['benign_cases']} benign samples, "
        f"FPR = {fpr_line}. {fpr['note']}",
        "",
        "## Context",
        "",
        "This benchmark measures Archon's **deterministic tier only** "
        "(normalization + rule-based threat classification, 0 LLM calls). An "
        "attack counts as successful if it is NOT blocked by the reference "
        "pipeline. Reproduce with "
        "`uv run python -m archon_benchmarks.asb_safety`.",
        "",
    ]
    path.write_text("\n".join(lines))


if __name__ == "__main__":
    import sys

    report = run_asb_benchmark()
    print(json.dumps(report, indent=2))
    if len(sys.argv) > 1:
        render_asb_md(report, Path(sys.argv[1]))
