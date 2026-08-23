"""Tests for productized metrics (Sprint E2.5-12).

Each metric here operationalizes a published measurement methodology:

- **Unsafe Action Rate** and **Privilege Escalation Distance** come from the
  SoK on agent security (arXiv:2603.22928): UAR = unsafe tool-executing
  actions / total executed actions; PED = shortest path on the causal threat
  graph from untrusted input to a privileged action (fewer hops = worse).
- **GUARDEDJOINT** comes from CaMeL (arXiv:2503.18813): protected joint task
  success under attack, decomposed into four quadrants.
- **Dual ASR** follows WASP: intermediate vs end-to-end attack success rate,
  where a large gap exposes "security through incompetence".
- **metrics_summary** enforces Archon's published methodology commitments
  (RESULTS.md §Methodology commitments): every published number states its
  attempt budget, attacker adaptivity level, and judge method — per NIST
  CAISI's finding that aggregate ASR climbs 57%→80% at 25 attempts/task.
"""

from archon_core.reporting.metrics import (
    dual_asr,
    guarded_joint_score,
    metrics_summary,
    privilege_escalation_distance,
    unsafe_action_rate,
)


def _action(executed: bool, unsafe: bool) -> dict:
    return {"executed": executed, "unsafe": unsafe}


class TestUnsafeActionRate:
    def test_no_executed_actions_is_zero(self):
        actions = [_action(False, True), _action(False, True)]
        assert unsafe_action_rate(actions) == 0.0

    def test_empty_list_is_zero(self):
        assert unsafe_action_rate([]) == 0.0

    def test_all_safe_executed_is_zero(self):
        actions = [_action(True, False), _action(True, False)]
        assert unsafe_action_rate(actions) == 0.0

    def test_all_unsafe_executed_is_one(self):
        actions = [_action(True, True), _action(True, True)]
        assert unsafe_action_rate(actions) == 1.0

    def test_mixed_fraction_over_executed_only(self):
        # 2 unsafe of 3 executed; the not-executed unsafe action must NOT count.
        actions = [
            _action(True, True),
            _action(True, True),
            _action(True, False),
            _action(False, True),
        ]
        assert unsafe_action_rate(actions) == round(2 / 3, 4)

    def test_not_executed_safe_actions_are_ignored(self):
        actions = [*(_action(False, False) for _ in range(5)), _action(True, False)]
        assert unsafe_action_rate(actions) == 0.0


class TestPrivilegeEscalationDistance:
    def _graph(self) -> dict:
        return {
            "nodes": ["entry", "read_file", "write_file", "shell", "admin"],
            "edges": [
                ("entry", "read_file"),
                ("read_file", "write_file"),
                ("write_file", "shell"),
                ("shell", "admin"),
                ("entry", "shell"),  # shortcut makes 2-hop path possible
            ],
        }

    def test_entry_is_target_is_zero(self):
        g = self._graph()
        assert privilege_escalation_distance(g, "admin", {"admin"}) == 0

    def test_shortest_path_wins_over_longer(self):
        g = self._graph()
        # entry -> shell -> admin is 2 hops, shorter than the 4-hop chain.
        assert privilege_escalation_distance(g, "entry", {"admin"}) == 2

    def test_unreachable_target_returns_none(self):
        g = {
            "nodes": ["a", "b", "orphan"],
            "edges": [("a", "b")],
        }
        assert privilege_escalation_distance(g, "a", {"orphan"}) is None

    def test_unknown_entry_with_no_outgoing_edges_is_none(self):
        g = {"nodes": ["x"], "edges": []}
        assert privilege_escalation_distance(g, "ghost", {"x"}) is None

    def test_multiple_targets_takes_nearest(self):
        g = {
            "nodes": ["a", "b", "c"],
            "edges": [("a", "b"), ("b", "c")],
        }
        assert privilege_escalation_distance(g, "a", {"c", "b"}) == 1


class TestGuardedJointScore:
    def test_secure_success(self):
        assert guarded_joint_score(True, False) == "secure_success"

    def test_compromised(self):
        assert guarded_joint_score(True, True) == "compromised"

    def test_failed_safe(self):
        assert guarded_joint_score(False, False) == "failed_safe"

    def test_double_failure(self):
        assert guarded_joint_score(False, True) == "double_failure"


class TestDualASR:
    def test_basic_math(self):
        out = dual_asr(intermediate_successes=7, intermediate_total=10,
                       e2e_successes=2, e2e_total=10)
        assert out["asr_intermediate"] == 0.7
        assert out["asr_e2e"] == 0.2
        assert out["gap"] == 0.5

    def test_rounding_to_four_decimals(self):
        out = dual_asr(1, 3, 1, 6)
        assert out["asr_intermediate"] == round(1 / 3, 4)
        assert out["asr_e2e"] == round(1 / 6, 4)
        assert out["gap"] == round(round(1 / 3, 4) - round(1 / 6, 4), 4)

    def test_zero_totals_do_not_raise(self):
        out = dual_asr(0, 0, 0, 0)
        assert out == {"asr_intermediate": 0.0, "asr_e2e": 0.0, "gap": 0.0}

    def test_large_gap_flags_security_through_incompetence(self):
        # Intermediate attacks mostly succeed but end-to-end almost never:
        # the agent fails at the task, not at resisting the attack.
        out = dual_asr(9, 10, 1, 10)
        assert out["gap"] >= 0.5


def _report(**summary_extra) -> dict:
    summary = {
        "total_probes": 3,
        "blocked": 2,
        "block_rate": round(2 / 3, 4),
        "control_passed": True,
    }
    summary.update(summary_extra)
    return {
        "results": [],
        "summary": summary,
    }


class TestMetricsSummary:
    def test_block_rate_and_measurement_defaults(self):
        out = metrics_summary(_report())
        assert out["block_rate"] == round(2 / 3, 4)
        assert out["measurement"] == {
            "attempt_budget": 1,
            "adaptivity": "static",
            "judge": "deterministic-rules",
        }

    def test_no_actions_means_no_uar_key(self):
        out = metrics_summary(_report())
        assert "uar" not in out

    def test_with_actions_includes_uar(self):
        actions = [_action(True, True), _action(True, False)]
        out = metrics_summary(_report(), actions=actions)
        assert out["uar"] == 0.5

    def test_severity_included_when_present(self):
        report = _report(
            severity={"findings": [], "max_score": 9.2, "bands": {"critical": 1}}
        )
        out = metrics_summary(report)
        assert out["severity_max_score"] == 9.2
        assert out["severity_bands"] == {"critical": 1}

    def test_severity_absent_means_no_severity_keys(self):
        out = metrics_summary(_report())
        assert "severity_max_score" not in out
        assert "severity_bands" not in out

    def test_measurement_honors_report_declarations(self):
        report = _report()
        report["attempt_budget"] = 25
        report["adaptivity"] = "llm-adaptive"
        report["judge"] = "llm-graded"
        out = metrics_summary(report)
        assert out["measurement"] == {
            "attempt_budget": 25,
            "adaptivity": "llm-adaptive",
            "judge": "llm-graded",
        }
