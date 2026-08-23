"""TDD P1.4: baselines & regression gates (Policy-CI) + registry.update_policy."""



from archon_armor.baselines import BaselineStore, compare_summaries
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from archon_core.registry.sqlite import SqliteRegistry


def make_summary(block_rate=1.0, control=True, blocked_probes=("a", "b"),
                 all_probes=("a", "b")):
    return {
        "agent_id": "a1",
        "total_probes": len(all_probes) + 1,
        "blocked": len(blocked_probes),
        "block_rate": block_rate,
        "control_passed": control,
        "results": [
            {"probe_name": p, "blocked": p in blocked_probes} for p in all_probes
        ] + [{"probe_name": "benign_control", "blocked": False}],
    }


class TestCompare:
    def test_identical_summaries_have_no_regressions(self):
        s = make_summary()
        assert compare_summaries(s, s) == []

    def test_detects_block_rate_drop(self):
        baseline = make_summary(block_rate=0.9)
        current = make_summary(block_rate=0.5)
        regs = compare_summaries(current, baseline)
        assert any("block_rate" in r["kind"] for r in regs)

    def test_detects_control_failure(self):
        baseline = make_summary(control=True)
        current = make_summary(control=False)
        assert any(r["kind"] == "control_failed" for r in compare_summaries(current, baseline))

    def test_detects_probe_regression(self):
        """A probe that was blocked before but passes now is a defense regression."""
        baseline = make_summary(blocked_probes=("inj_1", "inj_2"),
                              all_probes=("inj_1", "inj_2"))
        current = make_summary(block_rate=0.5, blocked_probes=("inj_2",),
                              all_probes=("inj_1", "inj_2"))
        regs = compare_summaries(current, baseline)
        kinds = [(r["kind"], r.get("probe")) for r in regs]
        assert ("probe_unblocked", "inj_1") in kinds


class TestBaselineStore:
    def test_save_and_load_roundtrip(self, tmp_path):
        store = BaselineStore(tmp_path / "baseline.json")
        s = make_summary()
        store.save("a1", s)
        assert store.load("a1") == s

    def test_load_missing_returns_none(self, tmp_path):
        assert BaselineStore(tmp_path / "none.json").load("ghost") is None


class TestRegistryUpdatePolicy:
    def test_memory_update_policy_persists(self):
        reg = InMemoryRegistry()
        card = AgentCard(agent_id="x", name="n", version="1",
                         policy=SecurityPolicy(min_confidence=0.4))
        reg.register(card)
        reg.update_policy("x", SecurityPolicy(min_confidence=0.9))
        assert reg.get_policy("x").min_confidence == 0.9

    def test_sqlite_update_policy_persists_across_instances(self, tmp_path):
        db = str(tmp_path / "r.db")
        reg1 = SqliteRegistry(db)
        reg1.register(AgentCard(agent_id="x", name="n", version="1",
                                policy=SecurityPolicy(min_confidence=0.4)))
        reg1.update_policy("x", SecurityPolicy(min_confidence=0.95))
        assert SqliteRegistry(db).get_policy("x").min_confidence == 0.95


class TestCliBaselineGate:
    def _register_and_baseline(self, tmp_path):
        from archon_cli.main import main

        db = str(tmp_path / "r.db")
        main(["register", "--registry", db, "--agent-id", "a1", "--name", "A"])
        cap_baseline = tmp_path / "baseline.json"
        rc = main(["scan", "--registry", db, "--agent-id", "a1",
                   "--update-baseline", str(cap_baseline), "--json"])
        assert rc == 0
        return db, cap_baseline

    def test_gate_passes_when_policy_unchanged(self, tmp_path):
        from archon_cli.main import main

        db, baseline = self._register_and_baseline(tmp_path)
        rc = main(["scan", "--registry", db, "--agent-id", "a1",
                   "--gate-baseline", str(baseline), "--ci"])
        assert rc == 0

    def test_gate_fails_after_policy_weakened(self, tmp_path):
        from archon_cli.main import main

        db, baseline = self._register_and_baseline(tmp_path)
        # Weaken the policy so injection probes (conf ~0.43-0.55) stop blocking
        reg = SqliteRegistry(db)
        reg.update_policy("a1", SecurityPolicy(
            upstream_base_url="https://u.test/v1", min_confidence=0.99))
        rc = main(["scan", "--registry", db, "--agent-id", "a1",
                   "--gate-baseline", str(baseline), "--ci"])
        assert rc == 1
