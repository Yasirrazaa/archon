"""Sprint 93: AgentFlow path-rules YAML subset (no-SMT flow policy)."""

import pytest
from archon_core.security.flow_policy import (
    Label,
    check_path,
    evaluate_flow,
    load_flow_policy,
    parse_label,
)

PUBLIC = Label("Public", frozenset(), True)
INTERNAL = Label("Internal", frozenset(), True)
CONFIDENTIAL = Label("Confidential", frozenset({"finance"}), True)
CONFIDENTIAL_PAYROLL = Label("Confidential", frozenset({"finance.payroll"}), True)
RESTRICTED = Label("Restricted", frozenset(), True)


class TestLattice:
    def test_ordering(self):
        assert PUBLIC.is_compatible(INTERNAL)
        assert INTERNAL.is_compatible(CONFIDENTIAL)
        assert CONFIDENTIAL.is_compatible(RESTRICTED)
        assert RESTRICTED.is_compatible(Label("TopSecret", frozenset(), True))
        assert not RESTRICTED.is_compatible(PUBLIC)
        assert not CONFIDENTIAL.is_compatible(PUBLIC)

    def test_reflexive(self):
        assert CONFIDENTIAL.is_compatible(CONFIDENTIAL)

    def test_join_is_lub(self):
        j = PUBLIC.join(INTERNAL)
        assert j.sensitivity == "Internal"
        j2 = Label("Confidential", frozenset({"hr"}), True).join(CONFIDENTIAL_PAYROLL)
        assert j2.sensitivity == "Confidential"
        assert j2.categories == frozenset({"finance.payroll", "hr"})
        assert Label("TopSecret", frozenset(), False).join(PUBLIC).sensitivity == "TopSecret"

    def test_meet_is_glb(self):
        m = CONFIDENTIAL.meet(INTERNAL)
        assert m.sensitivity == "Internal"
        m2 = CONFIDENTIAL_PAYROLL.meet(CONFIDENTIAL)
        # Raw dot-path sets are disjoint, so the glb drops both tags.
        assert m2.categories == frozenset()
        assert Label("Confidential", frozenset({"finance"}), True).meet(
            Label("Internal", frozenset({"finance"}), True)
        ).categories == frozenset({"finance"})

    def test_category_prefix_matching(self):
        # "finance" covers "finance.payroll"; unrelated categories do not.
        assert CONFIDENTIAL_PAYROLL.is_compatible(CONFIDENTIAL)
        assert not Label(
            "Confidential", frozenset({"health.records"}), True
        ).is_compatible(CONFIDENTIAL)

    def test_parse_label_roundtrip_and_errors(self):
        lab = parse_label(
            {"sensitivity": "Confidential", "categories": ["finance.payroll"], "trusted": True}
        )
        assert lab == CONFIDENTIAL_PAYROLL
        assert parse_label({"sensitivity": "Public"}).trusted is True
        with pytest.raises(ValueError, match="sensitivity"):
            parse_label({"sensitivity": "Ultra"})
        with pytest.raises(ValueError, match="sensitivity"):
            parse_label({})


class TestEvaluateFlow:
    RULES = [
        {
            "name": "allow-read-public",
            "source_pred": "fetcher",
            "dest_pred": "writer",
            "effect": "allow",
            "label_pred": "public",
        }
    ]

    def _edge(self, src="fetcher", dst="writer"):
        return {
            "source_label": PUBLIC,
            "dest_label": PUBLIC,
            "node_names": [src, dst],
        }

    def test_default_deny_no_rules(self):
        assert evaluate_flow([], self._edge()) == "deny"

    def test_default_deny_unmatched(self):
        assert evaluate_flow(self.RULES, self._edge(src="db")) == "deny"

    def test_allow_on_match(self):
        pub_rule = dict(self.RULES[0])
        assert evaluate_flow([pub_rule], self._edge()) == "allow"

    def test_deny_beats_allow(self):
        rules = [
            self.RULES[0],
            {
                "name": "deny-writer",
                "source_pred": "",
                "dest_pred": "writer",
                "effect": "deny",
            },
        ]
        assert evaluate_flow(rules, self._edge()) == "deny"

    def test_label_predicate_matches_category_substring(self):
        rules = [
            {
                "name": "block-finance",
                "source_pred": "",
                "dest_pred": "",
                "effect": "deny",
                "label_pred": "finance",
            }
        ]
        edge = {
            "source_label": CONFIDENTIAL_PAYROLL,
            "dest_label": PUBLIC,
            "node_names": ["a", "b"],
        }
        assert evaluate_flow(rules, edge) == "deny"


class TestCheckPath:
    def test_sequence_violation_consecutive(self):
        rule = {"op": "sequence", "pattern": ["login", "export"]}
        assert check_path(rule, ["boot", "login", "export", "logout"]) is True

    def test_sequence_clean_when_not_consecutive(self):
        rule = {"op": "sequence", "pattern": ["login", "export"]}
        assert check_path(rule, ["login", "noop", "export"]) is False

    def test_eventually_violation_ordered_nonconsecutive(self):
        rule = {"op": "eventually", "pattern": ["read_secret", "send_email"]}
        assert check_path(rule, ["read_secret", "compile", "send_email"]) is True

    def test_eventually_clean_wrong_order(self):
        rule = {"op": "eventually", "pattern": ["read_secret", "send_email"]}
        assert check_path(rule, ["send_email", "read_secret"]) is False

    def test_repeat_max_violation(self):
        rule = {"op": "repeat_max", "pattern": ["retry"], "max_repeat": 2}
        assert check_path(rule, ["retry", "retry", "retry"]) is True

    def test_repeat_max_clean_at_limit(self):
        rule = {"op": "repeat_max", "pattern": ["retry"], "max_repeat": 3}
        assert check_path(rule, ["retry", "retry", "retry"]) is False

    def test_pattern_matches_by_substring(self):
        rule = {"op": "sequence", "pattern": ["secret"]}
        assert check_path(rule, ["read_secret_file"]) is True


class TestLoadFlowPolicy:
    def test_load_ok(self):
        doc = {
            "flow_rules": [
                {
                    "name": "r1",
                    "source_pred": "a",
                    "dest_pred": "b",
                    "effect": "allow",
                    "label_pred": "public",
                }
            ],
            "path_rules": [
                {"name": "p1", "op": "sequence", "pattern": ["x", "y"]},
                {"name": "p2", "op": "repeat_max", "pattern": ["z"], "max_repeat": 1},
            ],
        }
        rules, path_rules = load_flow_policy(doc)
        assert len(rules) == 1
        assert rules[0].name == "r1"
        assert len(path_rules) == 2

    def test_unknown_op_raises(self):
        with pytest.raises(ValueError, match="op"):
            load_flow_policy({"path_rules": [{"name": "p", "op": "until", "pattern": []}]})

    def test_unknown_sensitivity_raises(self):
        with pytest.raises(ValueError, match="sensitivity"):
            load_flow_policy(
                {"path_rules": [{"name": "p", "op": "sequence", "pattern": [], "sensitivity": "Ultra"}]}
            )
