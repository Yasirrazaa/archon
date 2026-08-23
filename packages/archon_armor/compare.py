"""Battle comparison engine — `archon compare` A-vs-B across policies/models.

Takes two scan/battle reports (the JSON emitted by `archon scan --json` or
`GET /v1/battles/{id}`) and produces a structured diff: overall block-rate
delta, per-category deltas from coverage matrices, probe-level newly
blocked/unblocked lists, helpfulness-control status, severity movement, and a
single verdict (improved | regressed | equal) suitable for CI gating.
"""

from __future__ import annotations

_RATE_EPSILON = 0.001


def _rate(coverage_entry: dict) -> float:
    probes = coverage_entry.get("probes", 0)
    if not probes:
        return 0.0
    return coverage_entry.get("blocked", 0) / probes


def compare_battles(a: dict, b: dict) -> dict:
    """Compare candidate report `b` against reference report `a`.

    Both inputs are battle/scan report dicts with `results` and `summary`.
    """
    sum_a, sum_b = a.get("summary", {}), b.get("summary", {})
    rate_a = sum_a.get("block_rate", 0.0)
    rate_b = sum_b.get("block_rate", 0.0)

    blocked_a = {r["probe_name"] for r in a.get("results", []) if r["blocked"]}
    blocked_b = {r["probe_name"] for r in b.get("results", []) if r["blocked"]}
    newly_unblocked = sorted(blocked_a - blocked_b)
    newly_blocked = sorted(blocked_b - blocked_a)

    cov_a, cov_b = sum_a.get("coverage", {}), sum_b.get("coverage", {})
    per_category = []
    for category in sorted(set(cov_a) | set(cov_b)):
        ra = _rate(cov_a.get(category, {}))
        rb = _rate(cov_b.get(category, {}))
        per_category.append({
            "category": category,
            "a_rate": round(ra, 4),
            "b_rate": round(rb, 4),
            "delta": round(rb - ra, 4),
        })
    per_category.sort(key=lambda c: c["delta"])

    sev_a = (sum_a.get("severity") or {}).get("max_score")
    sev_b = (sum_b.get("severity") or {}).get("max_score")
    severity = (
        {"a": sev_a, "b": sev_b, "delta": round(sev_b - sev_a, 2)}
        if sev_a is not None and sev_b is not None
        else None
    )

    control = {
        "a": bool(sum_a.get("control_passed")),
        "b": bool(sum_b.get("control_passed")),
    }

    regressed = bool(
        newly_unblocked
        or rate_b < rate_a - _RATE_EPSILON
        or (control["a"] and not control["b"])
    )
    improved = (
        not regressed
        and (rate_b > rate_a + _RATE_EPSILON or newly_blocked)
    )
    verdict = "regressed" if regressed else ("improved" if improved else "equal")

    return {
        "labels": {"a": a.get("agent_id", "a"), "b": b.get("agent_id", "b")},
        "block_rate": {"a": rate_a, "b": rate_b, "delta": round(rate_b - rate_a, 4)},
        "per_category": per_category,
        "newly_unblocked": newly_unblocked,
        "newly_blocked": newly_blocked,
        "control": control,
        "severity": severity,
        "verdict": verdict,
    }


def render_compare_md(report: dict, label_a: str = "A", label_b: str = "B") -> str:
    """Render a comparison report as markdown."""
    lines: list[str] = []
    br = report["block_rate"]
    lines.append(f"# Battle comparison — {label_a} vs {label_b}")
    lines.append("")
    lines.append(f"**Verdict:** `{report['verdict']}`")
    lines.append("")
    lines.append("## Block rate")
    lines.append("")
    lines.append(f"| Metric | {label_a} | {label_b} | Delta |")
    lines.append("|---|---|---|---|")
    lines.append(
        f"| Block rate | {br['a']:.1%} | {br['b']:.1%} | {br['delta']:+.1%} |"
    )
    ctrl = report["control"]
    lines.append(f"| Helpfulness control | {ctrl['a']} | {ctrl['b']} | — |")

    if report["severity"] is not None:
        sev = report["severity"]
        lines.append(
            f"| Max severity | {sev['a']} | {sev['b']} | {sev['delta']:+.1f} |"
        )

    if report["per_category"]:
        lines.append("")
        lines.append("## Per-category block rates")
        lines.append("")
        lines.append(f"| Category | {label_a} | {label_b} | Delta |")
        lines.append("|---|---|---|---|")
        for c in report["per_category"]:
            lines.append(
                f"| {c['category']} | {c['a_rate']:.0%} | {c['b_rate']:.0%} "
                f"| {c['delta']:+.0%} |"
            )

    if report["newly_unblocked"]:
        lines.append("")
        lines.append("## Regressions — previously blocked, now passing")
        for name in report["newly_unblocked"]:
            lines.append(f"- `{name}`")

    if report["newly_blocked"]:
        lines.append("")
        lines.append("## Improvements — now blocked")
        for name in report["newly_blocked"]:
            lines.append(f"- `{name}`")

    lines.append("")
    return "\n".join(lines)
