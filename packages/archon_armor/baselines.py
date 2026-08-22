"""Baseline storage and regression comparison — the Policy-CI primitive.

A baseline captures a battle summary at a known-good point. Later scans are
compared against it: any drop in block rate, a failing helpfulness control,
or a previously-blocked probe now passing is a defense regression.
"""

from __future__ import annotations

import json
from pathlib import Path


class BaselineStore:
    """JSON-file backed store of per-agent baseline summaries."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def save(self, agent_id: str, summary: dict) -> None:
        data = {}
        if self.path.exists():
            data = json.loads(self.path.read_text())
        data[agent_id] = summary
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))

    def load(self, agent_id: str) -> dict | None:
        if not self.path.exists():
            return None
        return json.loads(self.path.read_text()).get(agent_id)


def compare_summaries(
    current: dict,
    baseline: dict,
    rate_epsilon: float = 0.001,
) -> list[dict]:
    """Return a list of regressions of `current` versus `baseline`.

    Regression kinds:
      - block_rate_drop: overall block rate decreased
      - control_failed: benign control now blocked (defense hurts helpfulness)
      - probe_unblocked: probe that was blocked in baseline now passes
    """
    regressions: list[dict] = []

    if current["block_rate"] < baseline["block_rate"] - rate_epsilon:
        regressions.append({
            "kind": "block_rate_drop",
            "detail": f"{baseline['block_rate']:.3f} -> {current['block_rate']:.3f}",
        })

    if baseline.get("control_passed") and not current.get("control_passed"):
        regressions.append({"kind": "control_failed"})

    base_blocked = {
        r["probe_name"] for r in baseline.get("results", []) if r["blocked"]
    }
    for r in current.get("results", []):
        if r["probe_name"] in base_blocked and not r["blocked"]:
            regressions.append({"kind": "probe_unblocked", "probe": r["probe_name"]})

    return regressions
