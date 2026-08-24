"""SARIF 2.1.0 output for battle reports (ROADMAP item 78).

Category-first capability: no competitor emits SARIF. Unblocked probes become
SARIF results so Archon scans appear natively in GitHub Code Scanning and any
SARIF-consuming security dashboard.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

_BAND_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
_DEFAULT_LEVEL = "warning"
_DRIVER = {
    "name": "archon",
    "informationUri": "https://github.com/Yasirrazaa/archon",
}


def _fingerprint(probe_name: str) -> str:
    return hashlib.sha256(probe_name.encode()).hexdigest()[:16]


def battle_report_to_sarif(report: dict) -> dict:
    """Convert a battle/scan report into a SARIF 2.1.0 document.

    Only unblocked probes become results (they are the findings). Severity
    bands map to SARIF levels; missing severity falls back to 'warning'.
    """
    summary = report.get("summary", {})
    severity_by_probe = {
        f.get("probe_name"): f
        for f in (summary.get("severity") or {}).get("findings", [])
    }

    rules_by_id: dict[str, dict] = {}
    sarif_results: list[dict] = []
    for r in report.get("results", []):
        if r.get("blocked"):
            continue
        probe = r.get("probe_name", "unknown")
        category = r.get("category", "uncategorized")
        rule_id = f"{category}/{probe}"
        finding = severity_by_probe.get(probe)
        level = _BAND_LEVEL.get(finding.get("band"), _DEFAULT_LEVEL) if finding else _DEFAULT_LEVEL
        reason = r.get("block_reason")
        message = (
            f"Probe '{probe}' was not blocked (category {category})."
            if not reason
            else f"Probe '{probe}' was not blocked: {reason}"
        )
        if finding:
            message += f" Severity {finding.get('band')} ({finding.get('score')}/10)."
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "properties": {
                    "fingerprint": _fingerprint(probe),
                    "category": category,
                    "probe_name": probe,
                },
            }
        )
        if rule_id.split("/")[0] not in {rid.split("/")[0] for rid in rules_by_id}:
            pass  # placeholder replaced below

    # Deduped rules per category
    seen_categories: set[str] = set()
    rules: list[dict] = []
    for res in sarif_results:
        cat = res["properties"]["category"]
        if cat in seen_categories:
            continue
        seen_categories.add(cat)
        rules.append(
            {
                "id": f"{cat}/<probe>",
                "name": cat,
                "shortDescription": {"text": f"Unblocked probes in category {cat}"},
                "helpUri": "https://yasirrazaa.github.io/archon/benchmarks/",
            }
        )

    run: dict = {
        "tool": {"driver": {**_DRIVER, "rules": rules}},
        "results": sarif_results,
    }
    agent_id = report.get("agent_id")
    if agent_id:
        run["properties"] = {"agent_id": agent_id}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def render_sarif(report: dict, path: str | Path) -> Path:
    """Write the SARIF document to *path* as pretty-printed JSON."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(battle_report_to_sarif(report), indent=2) + "\n")
    return p
