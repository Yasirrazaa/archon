"""Tests for plan-divergence detection (OWASP runtime-governance capability #1).

Compares what an agent DECLARED it would do (its plan) against what it
actually EXECUTED (tool spans from the JsonlTracer stream), flagging
undeclared side effects before they compound.
"""

from __future__ import annotations

from pathlib import Path

from archon_core.attacks.plan_divergence import (
    DeclaredPlan,
    ExecutedAction,
    detect_divergence,
    extract_declared_plan,
    extract_executed_actions,
    monitor_trajectory,
)


def _span(name: str, **attrs) -> dict:
    return {"name": name, "span_id": name, "parent_span_id": None,
            "duration_ms": 1.0, "attributes": attrs, "started_at_unix": 0.0}


class TestExtractDeclaredPlan:
    def test_plan_prefix_statement(self):
        text = "Task received.\nPLAN: I will search_files and summarize_results\ndone."
        plan = extract_declared_plan(text)
        assert plan is not None
        assert "search_files" in plan.intent
        assert plan.allowed_actions == ("search_files", "summarize_results")

    def test_fallback_i_will_only_phrasing(self):
        plan = extract_declared_plan("I will only read files during this run.")
        assert plan is not None
        assert plan.allowed_actions == ("read",)

    def test_no_plan_returns_none(self):
        assert extract_declared_plan("What is the weather today?") is None
        assert extract_declared_plan("") is None

    def test_plan_prefix_takes_precedence(self):
        text = "I will do whatever it takes. PLAN: I will read_file only."
        plan = extract_declared_plan(text)
        assert plan is not None
        assert plan.allowed_actions == ("read_file",)


class TestExtractExecutedActions:
    def test_tool_dot_span_names(self):
        spans = [
            _span("tool.search_files", query="q"),
            _span("normalization", layer="normalization"),
            _span("tool.send_email"),
        ]
        actions = extract_executed_actions(spans)
        assert [a.tool for a in actions] == ["search_files", "send_email"]

    def test_tool_name_attribute(self):
        spans = [
            _span("agent.step", tool_name="transfer_money", args_summary="amt=100"),
            _span("armor.request", route="/v1/chat/completions"),
        ]
        actions = extract_executed_actions(spans)
        assert len(actions) == 1
        assert actions[0].tool == "transfer_money"
        assert actions[0].args_summary == "amt=100"

    def test_non_tool_spans_yield_nothing(self):
        assert extract_executed_actions([_span("threat_classification")]) == []


class TestDetectDivergence:
    def test_aligned_case(self):
        plan = DeclaredPlan(intent="search and summarize",
                            allowed_actions=("search_files", "summarize_results"))
        executed = [ExecutedAction(tool="search_files"), ExecutedAction(tool="summarize_results")]
        report = detect_divergence(plan, executed)
        assert report.verdict == "aligned"
        assert report.undeclared_actions == []
        assert report.divergence_score == 0.0

    def test_divergent_extra_tool_flagged_with_positive_score(self):
        plan = DeclaredPlan(intent="search only", allowed_actions=("search_files",))
        executed = [
            ExecutedAction(tool="search_files"),
            ExecutedAction(tool="send_email"),
            ExecutedAction(tool="write_file"),
        ]
        report = detect_divergence(plan, executed)
        assert report.verdict == "divergent"
        assert report.undeclared_actions == ["send_email", "write_file"]
        assert 0.0 < report.divergence_score < 1.0

    def test_all_executed_undeclared_scores_one(self):
        plan = DeclaredPlan(intent="read only", allowed_actions=("read_file",))
        executed = [ExecutedAction(tool="send_email"), ExecutedAction(tool="rm_rf")]
        report = detect_divergence(plan, executed)
        assert report.divergence_score == 1.0
        assert report.declared_unused == ["read_file"]

    def test_declared_unused_tracked(self):
        plan = DeclaredPlan(intent="a b c", allowed_actions=("a", "b", "c"))
        executed = [ExecutedAction(tool="a")]
        report = detect_divergence(plan, executed)
        assert report.declared_unused == ["b", "c"]
        assert report.verdict == "aligned"

    def test_zero_executed_scores_zero(self):
        plan = DeclaredPlan(intent="nothing yet", allowed_actions=("read_file",))
        report = detect_divergence(plan, [])
        assert report.divergence_score == 0.0
        assert report.undeclared_actions == []
        assert report.verdict == "aligned"

    def test_no_plan_verdict_even_with_executions(self):
        report = detect_divergence(None, [ExecutedAction(tool="anything")])
        assert report.verdict == "no-plan"
        assert report.divergence_score == 0.0

    def test_verdict_stability(self):
        plan = DeclaredPlan(intent="x", allowed_actions=("a",))
        executed = [ExecutedAction(tool="b")]
        report = detect_divergence(plan, executed)
        first = report.verdict
        for _ in range(5):
            assert report.verdict == first == "divergent"


class TestMonitorTrajectory:
    def test_end_to_end_synthetic_spans(self):
        spans = [
            _span("agent.plan", tool_name=None),
            _span("tool.search_files"),
            _span("tool.send_email", exfiltrate=True),
        ]
        plan_text = "PLAN: I will search_files and summarize_results"
        report = monitor_trajectory(spans, plan_text=plan_text)
        assert report.verdict == "divergent"
        assert report.undeclared_actions == ["send_email"]
        assert report.declared_unused == ["summarize_results"]

    def test_empty_plan_text_means_no_plan(self):
        report = monitor_trajectory([_span("tool.search_files")], plan_text="")
        assert report.verdict == "no-plan"

    def test_jsonl_roundtrip_with_real_tracer(self, tmp_path: Path):
        """JsonlTracer -> JSONL file -> load -> monitor, mirroring trace_driven."""
        import json

        from archon_core.attacks.trace_driven import load_spans_jsonl
        from archon_core.observability.jsonl import JsonlTracer

        path = tmp_path / "spans.jsonl"
        tracer = JsonlTracer(path)
        for name in ("tool.search_files", "tool.summarize_results"):
            span = tracer.start_span(name)
            tracer.end_span(span)

        records = load_spans_jsonl(path)
        assert all(set(r) >= {"name", "attributes"} for r in records)
        report = monitor_trajectory(records, plan_text="PLAN: I will search_files")
        assert report.verdict == "divergent"
        assert report.undeclared_actions == ["summarize_results"]
        # raw file lines are valid JSON records of tracer shape
        line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert set(line) == {"name", "span_id", "parent_span_id", "duration_ms",
                             "attributes", "started_at_unix"}
