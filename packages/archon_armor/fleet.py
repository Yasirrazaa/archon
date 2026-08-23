"""Fleet overview — the server-side primitive behind a security dashboard.

FleetSummary aggregates per-agent baselines (known-good scan results) into
single-view metrics: registered agents, coverage, average block rate, and
the list of agents whose baselines fall below an organization minimum
(under-protected fleet members). This is the backbone for the managed-cloud
wedge and for a future read-only dashboard UI.
"""

from __future__ import annotations

from typing import Any

from archon_core.registry.base import Registry

from .baselines import BaselineStore


class FleetSummary:
    def __init__(
        self,
        registry: Registry,
        baselines: BaselineStore,
        min_block_rate: float = 0.75,
    ) -> None:
        self._registry = registry
        self._baselines = baselines
        self.min_block_rate = min_block_rate

    def metrics(self) -> dict[str, Any]:
        agents = self._registry.list_agents()
        rates: list[float] = []
        degraded: list[str] = []
        with_baseline = 0
        for card in agents:
            bl = self._baselines.load(card.agent_id)
            if bl is None:
                continue
            with_baseline += 1
            rate = float(bl.get("block_rate", 0.0))
            rates.append(rate)
            if rate < self.min_block_rate:
                degraded.append(card.agent_id)
        rates.sort(reverse=True)
        return {
            "registered": len(agents),
            "with_baseline": with_baseline,
            "avg_block_rate": round(sum(rates) / len(rates), 4) if rates else 0.0,
            "min_agent_block_rate": round(rates[-1], 4) if rates else None,
            "degraded": degraded,
            "fleet_min_block_rate": self.min_block_rate,
        }