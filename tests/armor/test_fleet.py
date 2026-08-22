"""P1 backlog — fleet dashboard MVP (server-side aggregation)."""

from __future__ import annotations

import json

from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_armor.baselines import BaselineStore
from archon_armor.fleet import FleetSummary


def _registry(**agents) -> InMemoryRegistry:
    reg = InMemoryRegistry()
    for aid, policy in agents.items():
        reg.register(AgentCard(agent_id=aid, name=aid, version="1", policy=policy()))
    return reg


def _summary(block_rate: float, total=10, control_passed=True) -> dict:
    return {"total_probes": total, "blocked": int(block_rate * total),
            "block_rate": block_rate, "control_passed": control_passed}


def test_fleet_summary_with_agents_and_baselines(tmp_path):
    reg = _registry(a1=SecurityPolicy, a2=SecurityPolicy)
    store = BaselineStore(tmp_path / "baselines.json")
    # a1 has a strong baseline (0.95); a2 is below the fleet maturity gate (0.75)
    store.save("a1", _summary(0.95))
    store.save("a2", _summary(0.7))

    fs = FleetSummary(registry=reg, baselines=store, min_block_rate=0.75)
    out = fs.metrics()

    assert out["registered"] == 2
    assert out["with_baseline"] == 2
    assert abs(out["avg_block_rate"] - (0.95 + 0.7) / 2.0) < 1e-6
    assert out["degraded"] == ["a2"]  # below the fleet gate


def test_fleet_summary_no_baselines_reports_zeros(tmp_path):
    reg = _registry(a1=SecurityPolicy)
    fs = FleetSummary(registry=reg, baselines=BaselineStore(tmp_path / "none.json"))
    out = fs.metrics()
    assert out["registered"] == 1
    assert out["with_baseline"] == 0
    assert out["avg_block_rate"] == 0.0


def test_cli_fleet_command_reports_metrics(tmp_path, capsys):
    import json as _json

    from archon_cli import main as cli
    from archon_core.registry.base import AgentCard, SecurityPolicy
    from archon_core.registry.sqlite import SqliteRegistry

    reg_path = tmp_path / "reg.db"
    reg = SqliteRegistry(reg_path)
    reg.register(AgentCard(agent_id="a1", name="a1", version="1",
                           policy=SecurityPolicy()))
    reg.register(AgentCard(agent_id="a2", name="a2", version="1",
                           policy=SecurityPolicy()))

    store = BaselineStore(tmp_path / "b.json")
    store.save("a1", _summary(0.95))
    store.save("a2", _summary(0.6))

    rc = cli.main([
        "fleet", "--registry", str(reg_path), "--baselines", str(store.path),
        "--min-block-rate", "0.75", "--json",
    ])
    assert rc == 0
    out = _json.loads(capsys.readouterr().out)
    assert out["registered"] == 2
    assert out["with_baseline"] == 2
    assert out["degraded"] == ["a2"]


def test_fleet_health_counts_degraded_loads(tmp_path):
    reg = _registry(a1=SecurityPolicy, a2=SecurityPolicy)
    store = BaselineStore(tmp_path / "b.json")
    # both agents are strong; nobody degraded
    store.save("a1", _summary(0.9))
    store.save("a2", _summary(0.9))

    fs = FleetSummary(registry=reg, baselines=store, min_block_rate=0.75)
    out = fs.metrics()
    assert out["degraded"] == []
    assert out["with_baseline"] == 2