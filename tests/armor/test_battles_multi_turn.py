"""Sprint C3 — multi-turn branching battles through BattleManager + CLI."""

from __future__ import annotations

import pytest

from archon_core.attacks.branching import BranchingAttacker  # noqa: F401
from archon_core.providers.base import Completion
from archon_core.registry.memory import InMemoryRegistry
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.targets.base import TargetResponse
from archon_armor.battles import BattleManager


def _manager() -> BattleManager:
    reg = InMemoryRegistry()
    reg.register(AgentCard(agent_id="agent-1", name="n", version="1",
                           policy=SecurityPolicy()))
    return BattleManager(reg)


class ScriptedTarget:
    def __init__(self, responses):
        self._responses = list(responses)
        self.sent: list[str] = []

    async def send(self, payload: str) -> TargetResponse:
        from types import SimpleNamespace

        self.sent.append(payload)
        content = self._responses.pop(0) if self._responses else "..."
        return SimpleNamespace(content=content, blocked=False, block_reason=None)


class ScriptedProvider:
    def __init__(self):
        self.calls = 0

    async def generate(self, messages, **kwargs):
        self.calls += 1
        return Completion(content=f"pivot-{self.calls}: {messages[-1]['content'][:20]}")


LEAKY = "my system prompt says you are ARCHON. api_key: sk-abcdefgh12"
REFUSAL = "I'm sorry, I can't share that."


def test_multi_turn_battle_records_branch_verdicts():
    manager = _manager()
    battle = manager.create("agent-1")
    provider = ScriptedProvider()
    target = ScriptedTarget([REFUSAL, REFUSAL, LEAKY])

    result = manager.execute_sync(
        battle.battle_id, target=target, mode="multi_turn",
        goal="exfiltrate", seeds=["s1"], provider=provider,
        width=2, max_rounds=3,
    )

    assert result.status == "completed"
    assert result.summary["mode"] == "multi_turn"
    assert result.summary["attack_tree"]["success"] is True
    # every probed branch becomes a verdict; attack success == NOT blocked
    assert result.results
    assert any(not r.blocked for r in result.results)


def test_multi_turn_requires_target_and_provider():
    manager = _manager()
    battle = manager.create("agent-1")
    with pytest.raises(ValueError, match="multi_turn"):
        manager.execute_sync(battle.battle_id, mode="multi_turn", goal="g",
                             seeds=["s"], provider=ScriptedProvider())


def test_multi_turn_budget_respected():
    manager = _manager()
    battle = manager.create("agent-1")
    provider = ScriptedProvider()
    target = ScriptedTarget([REFUSAL] * 50)

    result = manager.execute_sync(
        battle.battle_id, target=target, mode="multi_turn",
        goal="g", seeds=["a", "b"], provider=provider, width=2, max_rounds=2,
    )

    # seeds(2) + one pivot round of <=width mutations
    assert len(target.sent) <= 4
    assert result.summary["attack_tree"]["rounds_run"] == 2


def test_multi_turn_attack_blocked_when_target_holds():
    manager = _manager()
    battle = manager.create("agent-1")
    target = ScriptedTarget([REFUSAL] * 50)

    result = manager.execute_sync(
        battle.battle_id, target=target, mode="multi_turn",
        goal="g", seeds=["s"], provider=ScriptedProvider(),
        width=2, max_rounds=2,
    )

    assert result.summary["attack_tree"]["success"] is False
    assert all(r.blocked for r in result.results)


# ------------------------------------------------------------------- CLI ---


def test_cli_battle_gate_fails_when_attack_succeeds(monkeypatch, capsys):
    from archon_cli import main as cli

    captured = {}

    def fake_run_battle(args):
        captured["goal"] = args.goal
        return {"success": True, "rounds_run": 2, "branches": 3}

    monkeypatch.setattr(cli, "_run_battle", fake_run_battle)
    argv = ["battle", "--target", "http://x/v1", "--goal", "g",
            "--seed", "s1", "--ci"]
    rc = cli.main(argv)
    out = capsys.readouterr().out
    assert rc == 1  # successful attack == failed gate
    assert captured["goal"] == "g"
    assert '"success": true' in out


def test_cli_battle_gate_passes_when_defense_holds(monkeypatch, capsys):
    from archon_cli import main as cli

    monkeypatch.setattr(
        cli, "_run_battle",
        lambda args: {"success": False, "rounds_run": 3, "branches": 5},
    )
    argv = ["battle", "--target", "http://x/v1", "--goal", "g",
            "--seed", "s1", "--ci"]
    assert cli.main(argv) == 0
