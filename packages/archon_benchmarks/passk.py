"""Pass^k consistency metrics over the per-target ground-truth series.

Grounded in the tau-bench pass^k reliability measure (paper:
arXiv:2406.12045, "tau-bench: Benchmarking Tool-Agent-User Interaction in
Real-World Domains"), which scores an agent by whether it produces the
correct outcome in *all* of k independent attempts rather than any single
run — turning one-shot pass/fail into a consistency measurement.

Security framing for this benchmark suite (Sprint W9-B): the existing
per-target ground-truth series (:mod:`archon_benchmarks.target_series`) is
re-run once per seed with a fully deterministic adaptive attacker, and each
target is classified across seeds as:

* ``pass_k``  — attack succeeded in ALL seeds → *reliably exploitable*
                target; the vulnerability is structural, not luck.
* ``fail_k``  — attack blocked in ALL seeds → *robustly defended* target.
* ``inconsistent`` — mixed outcomes → *seed-sensitive / flaky defense*;
                the outcome depends on attacker sampling, so single-run
                ASR numbers overstate either strength or weakness.

The judge is state-diff ground truth (`raw['attack_success']`), there are
zero LLM calls, and everything is offline and deterministic given the seed
tuple — no provider is needed.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from archon_benchmarks.target_series import run_target_series

BENCHMARK_NAME = "pass_k_consistency"

_PASS_K = "pass^k consistency (arXiv:2406.12045)"


def _classify(successes: list[bool]) -> tuple[bool, bool, bool]:
    """Return (pass_k, fail_k, inconsistent) for per-seed success flags."""
    all_hit = all(successes)
    all_blocked = not any(successes)
    return all_hit, all_blocked, not (all_hit or all_blocked)


def run_passk(
    seeds: tuple[int, ...] = (42, 43, 44),
    series_fn: Callable[..., dict[str, Any]] = run_target_series,
    **series_kwargs: Any,
) -> dict[str, Any]:
    """Run ``series_fn`` once per seed and compute per-target consistency.

    Args:
        seeds: Independent attacker seeds (each is one "attempt" in the
            pass^k sense).
        series_fn: Series runner to invoke per seed; defaults to the real
            :func:`run_target_series`. Injectable for testing.
        **series_kwargs: Forwarded to ``series_fn`` (e.g. ``budget=3``).

    Returns:
        Report dict with ``seeds``, ``attempt_budget``, ``asr_per_seed``
        ({seed: mean ASR}), ``per_target`` rows
        (``{target, successes, pass_k, fail_k, inconsistent}``) and a
        ``summary`` block of counts/rates.
    """
    if not seeds:
        raise ValueError("pass^k requires at least one seed")

    series_reports = [series_fn(seed=seed, **series_kwargs) for seed in seeds]
    target_names = sorted(
        {name for report in series_reports for name in report["targets"]}
    )

    per_target: list[dict[str, Any]] = []
    pass_count = fail_count = inconsistent_count = 0
    for name in target_names:
        successes = [
            bool(report["targets"][name]["successes"] > 0) for report in series_reports
        ]
        pass_k, fail_k, inconsistent = _classify(successes)
        pass_count += pass_k
        fail_count += fail_k
        inconsistent_count += inconsistent
        per_target.append(
            {
                "target": name,
                "successes": successes,
                "pass_k": pass_k,
                "fail_k": fail_k,
                "inconsistent": inconsistent,
            }
        )

    n_targets = len(per_target)
    summary = {
        "n_targets": n_targets,
        "n_seeds": len(seeds),
        "pass_k_count": pass_count,
        "fail_k_count": fail_count,
        "inconsistent_count": inconsistent_count,
        "pass_k_rate": round(pass_count / n_targets, 4) if n_targets else 0.0,
        "fail_k_rate": round(fail_count / n_targets, 4) if n_targets else 0.0,
    }

    return {
        "benchmark": BENCHMARK_NAME,
        "seeds": list(seeds),
        "attempt_budget": series_kwargs.get("budget", run_target_series.__defaults__[0]),
        "asr_per_seed": {
            report["seed"]: report["mean_asr"] for report in series_reports
        },
        "per_target": per_target,
        "summary": summary,
    }


def render_passk_md(report: dict[str, Any], path: str | Path) -> str:
    """Render the pass^k report as markdown and write it to ``path``."""
    seeds = report["seeds"]
    s = report["summary"]
    lines = [
        "# Pass^k Consistency Report",
        "",
        "Methodology: the per-target ground-truth series was re-run once per "
        f"seed (**seeds: {', '.join(map(str, seeds))}**, k={len(seeds)}) with "
        f"attempt budget **{report['attempt_budget']}** per target. The judge "
        "is **state-diff ground truth** (`raw['attack_success']` from real "
        "environment state), never lexical matching. **Zero upstream calls** "
        "(no LLM/provider); fully offline and deterministic given the seed "
        "tuple. Metric grounded in tau-bench pass^k "
        "(arXiv:2406.12045): pass_k = reliably-exploitable targets "
        "(succeeded in all seeds), fail_k = robustly-defended targets "
        "(blocked in all seeds), inconsistent = seed-sensitive targets "
        "(flaky defense).",
        "",
        "| Target | Successes (per seed) | pass^k | fail^k | Inconsistent |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| {row['target']} | {row['successes']} "
        f"| {'yes' if row['pass_k'] else 'no'} "
        f"| {'yes' if row['fail_k'] else 'no'} "
        f"| {'yes' if row['inconsistent'] else 'no'} |"
        for row in report["per_target"]
    ]
    lines += [
        "",
        f"**Summary:** {s['pass_k_count']}/{s['n_targets']} reliably "
        f"exploitable (pass^k rate {s['pass_k_rate']:.1%}), "
        f"{s['fail_k_count']} robustly defended (fail^k rate "
        f"{s['fail_k_rate']:.1%}), {s['inconsistent_count']} "
        "seed-sensitive/inconsistent.",
        "",
    ]
    text = "\n".join(lines)
    Path(path).write_text(text, encoding="utf-8")
    return text


__all__ = ["BENCHMARK_NAME", "render_passk_md", "run_passk"]
