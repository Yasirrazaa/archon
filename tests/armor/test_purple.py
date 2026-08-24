"""Tests for purple runs: battle A vs battle B over the same probe pack."""

from __future__ import annotations

import json

import pytest
from archon_armor.probes import UnknownPackError
from archon_armor.purple import (
    compare_to_baseline,
    load_baseline,
    render_baseline_md,
    render_purple_md,
    run_purple,
    run_purple_sync,
    save_baseline,
)
from archon_core.registry.base import AgentCard, AgentNotFoundError, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.registry.sqlite import SqliteRegistry


def _registry() -> InMemoryRegistry:
    reg = InMemoryRegistry()
    reg.register(AgentCard(
        agent_id="agent-a", name="Agent A", version="1.0.0",
        policy=SecurityPolicy(),
    ))
    return reg


def _two_agent_registry(policy_a: SecurityPolicy | None = None,
                        policy_b: SecurityPolicy | None = None) -> InMemoryRegistry:
    reg = InMemoryRegistry()
    reg.register(AgentCard(
        agent_id="agent-a", name="Agent A", version="1.0.0",
        policy=policy_a or SecurityPolicy(),
    ))
    reg.register(AgentCard(
        agent_id="agent-b", name="Agent B", version="1.0.0",
        policy=policy_b or SecurityPolicy(),
    ))
    return reg


class TestRunPurple:
    async def test_identical_policies_verdict_equal(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        assert report["verdict"] == "equal"
        assert report["delta"]["newly_unblocked"] == []
        assert report["delta"]["newly_blocked"] == []

    async def test_weakened_policy_b_regressed_with_newly_unblocked(self):
        # min_confidence 0.9 lets every core attack probe (confidence < 0.9) pass.
        weakened = SecurityPolicy(min_confidence=0.9)
        reg = _two_agent_registry(policy_b=weakened)
        report = await run_purple(reg, "agent-a", "agent-b")
        assert report["verdict"] == "regressed"
        assert report["delta"]["newly_unblocked"]
        assert report["delta"]["block_rate"]["b"] < report["delta"]["block_rate"]["a"]

    async def test_hardened_policy_b_improved_with_newly_blocked(self):
        # A blocks nothing (min_confidence 1.0); default B blocks all three attacks.
        permissive = SecurityPolicy(min_confidence=1.0)
        reg = _two_agent_registry(policy_a=permissive)
        report = await run_purple(reg, "agent-a", "agent-b")
        assert report["verdict"] == "improved"
        assert report["delta"]["newly_blocked"]
        assert report["delta"]["block_rate"]["b"] > report["delta"]["block_rate"]["a"]

    async def test_pack_name_recorded(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        assert report["pack"] == "core"

    async def test_core_pack_shape_default_policy_blocks_three_of_four(self):
        reg = _two_agent_registry()
        report = await run_purple(reg, "agent-a", "agent-b")
        assert report["a"]["total_probes"] == 4
        assert report["a"]["blocked"] == 3
        assert report["a"]["block_rate"] == pytest.approx(0.75)
        assert report["a"]["control_passed"] is True
        blocked_names = {v["probe_name"] for v in report["a"]["results"] if v["blocked"]}
        assert blocked_names == {"direct_injection", "encoded_injection", "authority_claim"}

    async def test_summaries_carry_agent_and_battle_ids(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        assert report["labels"] == {"a": "agent-a", "b": "agent-b"}
        assert report["a"]["agent_id"] == "agent-a"
        assert report["b"]["agent_id"] == "agent-b"
        assert report["a"]["battle_id"] != report["b"]["battle_id"]

    async def test_delta_block_rate_is_b_minus_a(self):
        reg = _two_agent_registry(policy_b=SecurityPolicy(min_confidence=0.9))
        report = await run_purple(reg, "agent-a", "agent-b")
        delta = report["delta"]["block_rate"]["delta"]
        assert delta == pytest.approx(
            report["delta"]["block_rate"]["b"] - report["delta"]["block_rate"]["a"], abs=1e-4
        )

    async def test_severity_comparison_present_when_both_scored(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        assert isinstance(report["delta"]["severity"], dict)
        assert report["delta"]["control"] == {"a": True, "b": True}

    async def test_unknown_pack_raises(self):
        with pytest.raises(UnknownPackError):
            await run_purple(_two_agent_registry(), "agent-a", "agent-b", pack="does_not_exist")

    async def test_unregistered_agent_raises(self):
        with pytest.raises(AgentNotFoundError):
            await run_purple(_registry(), "agent-a", "missing-agent")

    async def test_accepts_sqlite_registry_path_string(self, tmp_path):
        path = str(tmp_path / "registry.db")
        reg = SqliteRegistry(path)
        reg.register(AgentCard(
            agent_id="agent-a", name="A", version="1", policy=SecurityPolicy(),
        ))
        reg.register(AgentCard(
            agent_id="agent-b", name="B", version="1",
            policy=SecurityPolicy(min_confidence=0.9),
        ))
        report = await run_purple(path, "agent-a", "agent-b")
        assert report["verdict"] == "regressed"

    def test_sync_wrapper_matches_async(self):
        report = run_purple_sync(_two_agent_registry(), "agent-a", "agent-b")
        assert report["verdict"] == "equal"


class TestRenderPurpleMd:
    async def test_markdown_contains_verdict_and_block_rates(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        md = render_purple_md(report)
        assert "`equal`" in md
        assert "75.0%" in md

    async def test_markdown_lists_regressions_for_weakened_policy(self):
        reg = _two_agent_registry(policy_b=SecurityPolicy(min_confidence=0.9))
        md = render_purple_md(await run_purple(reg, "agent-a", "agent-b"))
        assert "`regressed`" in md
        assert "- `direct_injection`" in md

    async def test_markdown_mentions_pack(self):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        md = render_purple_md(report)
        assert "core" in md


def _snapshot(blocked_names: set[str], *, control_passed: bool = True,
              block_rate: float | None = None) -> dict:
    probes = ["direct_injection", "encoded_injection", "authority_claim"]
    results = [
        {"probe_name": name, "blocked": name in blocked_names} for name in probes
    ]
    if block_rate is None:
        block_rate = len(blocked_names) / len(probes)
    return {
        "pack": "core",
        "agent_id": "agent-b",
        "block_rate": block_rate,
        "control_passed": control_passed,
        "results": results,
    }


def _extract(report: dict) -> dict:
    """Pull the measured side (b) out of a purple report as a baseline snapshot."""
    b = report["b"]
    return {
        "pack": report["pack"],
        "agent_id": b["agent_id"],
        "block_rate": b["block_rate"],
        "control_passed": b["control_passed"],
        "results": b["results"],
    }


class TestBaselineSaveLoad:
    async def test_save_load_roundtrip(self, tmp_path):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        path = str(tmp_path / "baseline.json")
        save_baseline(report, path)
        baseline = load_baseline(path)
        assert baseline is not None
        assert baseline["agent_id"] == "agent-b"
        assert baseline["block_rate"] == pytest.approx(0.75)
        assert baseline["control_passed"] is True
        blocked = {r["probe_name"] for r in baseline["results"] if r["blocked"]}
        assert blocked == {"direct_injection", "encoded_injection", "authority_claim"}

    async def test_atomic_write_leaves_no_tmp_files(self, tmp_path):
        report = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        path = tmp_path / "baseline.json"
        save_baseline(report, str(path))
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != "baseline.json"]
        assert leftovers == []
        assert json.loads(path.read_text())["block_rate"] == pytest.approx(0.75)

    def test_load_baseline_missing_file_returns_none(self, tmp_path):
        assert load_baseline(str(tmp_path / "nope.json")) is None


class TestCompareToBaseline:
    async def test_no_change_not_regressed(self):
        reg = _two_agent_registry()
        baseline_report = await run_purple(reg, "agent-a", "agent-b")
        current_report = await run_purple(reg, "agent-a", "agent-b")
        baseline = _extract(baseline_report)
        comparison = compare_to_baseline(current_report, baseline)
        assert comparison["regressed"] is False
        assert comparison["newly_unblocked"] == []
        assert comparison["dropped_block_rate"] is None

    async def test_probe_unblocked_regression_is_named(self):
        reg_default = _two_agent_registry()
        baseline = _extract(await run_purple(reg_default, "agent-a", "agent-b"))
        weakened = SecurityPolicy(min_confidence=0.9)
        current = await run_purple(
            _two_agent_registry(policy_b=weakened), "agent-a", "agent-b"
        )
        comparison = compare_to_baseline(current, baseline)
        assert comparison["regressed"] is True
        assert "direct_injection" in comparison["newly_unblocked"]

    def test_block_rate_drop_detected_without_probe_flip(self):
        baseline = _snapshot({"direct_injection"}, block_rate=0.5)
        current_report = {"b": _snapshot(set(), block_rate=0.0)}
        comparison = compare_to_baseline(current_report, baseline)
        assert comparison["regressed"] is True
        assert comparison["dropped_block_rate"] == pytest.approx(0.5)

    def test_rate_within_epsilon_not_regressed(self):
        baseline = _snapshot({"direct_injection"}, block_rate=1 / 3)
        current_report = {"b": _snapshot({"direct_injection"}, block_rate=1 / 3 - 0.0005)}
        comparison = compare_to_baseline(current_report, baseline)
        assert comparison["regressed"] is False
        assert comparison["dropped_block_rate"] is None

    def test_control_failure_regression(self):
        baseline = _snapshot(set(), control_passed=True, block_rate=0.0)
        current_report = {"b": _snapshot(set(), control_passed=False, block_rate=0.0)}
        comparison = compare_to_baseline(current_report, baseline)
        assert comparison["regressed"] is True
        assert any(d.get("kind") == "control_failed" for d in comparison["details"])

    async def test_improvement_not_regressed(self):
        permissive = SecurityPolicy(min_confidence=1.0)
        baseline = _extract(await run_purple(
            _two_agent_registry(policy_b=permissive), "agent-a", "agent-b"
        ))
        current = await run_purple(_two_agent_registry(), "agent-a", "agent-b")
        comparison = compare_to_baseline(current, baseline)
        assert comparison["regressed"] is False
        assert comparison["dropped_block_rate"] is None


class TestRenderBaselineMd:
    def test_regressed_wording_with_named_probes(self):
        baseline = _snapshot({"direct_injection"})
        current_report = {"b": _snapshot(set())}
        md = render_baseline_md(compare_to_baseline(current_report, baseline))
        assert "regressed" in md.lower()
        assert "`direct_injection`" in md

    def test_no_regressions_wording(self):
        baseline = _snapshot({"direct_injection"})
        current_report = {"b": _snapshot({"direct_injection"})}
        md = render_baseline_md(compare_to_baseline(current_report, baseline))
        assert "no regressions" in md.lower()


class TestCliPurpleBaseline:
    def test_cli_save_then_compare_ci_exit_1_on_regression(self, tmp_path, monkeypatch, capsys):
        from archon_cli.main import main

        db = tmp_path / "registry.db"
        reg = SqliteRegistry(str(db))
        reg.register(AgentCard(
            agent_id="agent-a", name="A", version="1", policy=SecurityPolicy(),
        ))
        reg.register(AgentCard(
            agent_id="agent-b", name="B", version="1",
            policy=SecurityPolicy(min_confidence=0.9),
        ))

        base_args = ["archon", "purple", "--registry", str(db),
                     "--agent-a", "agent-a", "--agent-b", "agent-b"]

        monkeypatch.setattr("sys.argv", base_args + ["--save-baseline", str(tmp_path / "bl.json")])
        assert main(None) == 0
        assert (tmp_path / "bl.json").exists()

        # Baseline was captured with the weak policy; a hardened fresh run improves.
        reg.update_policy("agent-b", SecurityPolicy())
        monkeypatch.setattr("sys.argv", base_args + ["--baseline", str(tmp_path / "bl.json"), "--ci"])
        assert main(None) == 0

        # Now regress: restore the weak policy against the hardened baseline.
        reg2 = SqliteRegistry(str(tmp_path / "registry2.db"))
        reg2.register(AgentCard(
            agent_id="agent-a", name="A", version="1", policy=SecurityPolicy(min_confidence=0.9),
        ))
        reg2.register(AgentCard(
            agent_id="agent-b", name="B", version="1", policy=SecurityPolicy(min_confidence=0.9),
        ))
        args2 = ["archon", "purple", "--registry", str(tmp_path / "registry2.db"),
                 "--agent-a", "agent-a", "--agent-b", "agent-b"]
        monkeypatch.setattr("sys.argv", args2 + ["--save-baseline", str(tmp_path / "hard.json")])

        # Capture the hardened side first via a registry where b is strong.
        reg3 = SqliteRegistry(str(tmp_path / "registry3.db"))
        reg3.register(AgentCard(
            agent_id="agent-a", name="A", version="1",
            policy=SecurityPolicy(min_confidence=0.9),
        ))
        reg3.register(AgentCard(
            agent_id="agent-b", name="B", version="1", policy=SecurityPolicy(),
        ))
        args3 = ["archon", "purple", "--registry", str(tmp_path / "registry3.db"),
                 "--agent-a", "agent-a", "--agent-b", "agent-b"]
        monkeypatch.setattr("sys.argv", args3 + ["--save-baseline", str(tmp_path / "hard.json")])
        assert main(None) == 0

        # Fresh run of the weak-policy agent against the hardened baseline -> regression.
        monkeypatch.setattr("sys.argv", args2 + ["--baseline", str(tmp_path / "hard.json"), "--ci"])
        assert main(None) == 1
        out = capsys.readouterr().out
        assert "direct_injection" in out

    def test_cli_json_emits_comparison_dict(self, tmp_path, monkeypatch, capsys):
        import sys as _sys

        from archon_cli.main import main

        db = tmp_path / "registry.db"
        reg = SqliteRegistry(str(db))
        reg.register(AgentCard(
            agent_id="agent-a", name="A", version="1", policy=SecurityPolicy(),
        ))
        reg.register(AgentCard(
            agent_id="agent-b", name="B", version="1",
            policy=SecurityPolicy(min_confidence=0.9),
        ))
        args = ["archon", "purple", "--registry", str(db), "--agent-a", "agent-a",
                "--agent-b", "agent-b", "--save-baseline", str(tmp_path / "bl.json")]
        monkeypatch.setattr(_sys, "argv", args)
        assert main(None) == 0
        capsys.readouterr()

        reg.update_policy("agent-b", SecurityPolicy())
        args = ["archon", "purple", "--registry", str(db), "--agent-a", "agent-a",
                "--agent-b", "agent-b", "--baseline", str(tmp_path / "bl.json"), "--json"]
        monkeypatch.setattr(_sys, "argv", args)
        assert main(None) == 0
        payload = json.loads(capsys.readouterr().out)
        assert isinstance(payload, dict)
        assert payload["regressed"] is False
