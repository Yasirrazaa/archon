"""Tests for agent-loop detection metric (zero-LLM-cost, stdlib only).

Metric design follows deepeval's AgentLoopDetectionMetric
(deepeval/metrics/agent_loop_detection): three independent sub-signals —
identical-call repetition, reasoning stagnation, and call-graph cycles —
combined into a weighted loop score.
"""


from archon_core.reporting.loop_metric import (
    Span,
    _call_label,
    agent_loop_score,
    cycle_score,
    repetition_score,
    stagnation_score,
)


def _span(name="search", arguments='{"q": "flights"}', **kw) -> Span:
    return Span(name=name, arguments=arguments, **kw)


class TestCallLabel:
    def test_label_format_sha_truncation(self):
        label = _call_label(_span())
        prefix, tool, arg_hash = label.split(":")
        assert prefix == "tool"
        assert tool == "search"
        # 12 hex chars = truncated sha256 of the arguments string
        assert len(arg_hash) == 12
        int(arg_hash, 16)  # valid hex

    def test_label_stable_for_identical_spans(self):
        a = _call_label(_span(arguments='{"q": "x"}'))
        b = _call_label(_span(arguments='{"q": "x"}'))
        c = _call_label(_span(arguments='{"q": "y"}'))
        assert a == b
        assert a != c

    def test_label_none_arguments(self):
        label = _call_label(Span(name="plan", span_type="llm"))
        assert label == "llm:plan:none"


class TestRepetition:
    def test_repetition_zero_for_unique_calls(self):
        spans = [
            _span(name="search", arguments='{"q": "a"}'),
            _span(name="search", arguments='{"q": "b"}'),
            _span(name="book", arguments='{"id": 1}'),
        ]
        assert repetition_score(spans) == 0.0

    def test_repetition_counts_identical_calls(self):
        args = '{"q": "same"}'
        spans = [
            _span(name="search", arguments=args),
            _span(name="other"),
            _span(name="search", arguments=args),
            _span(name="third"),
            _span(name="search", arguments=args),
        ]
        # 2 of 5 spans repeat an earlier label
        assert repetition_score(spans) == 2 / 5

    def test_repetition_empty_input_safe(self):
        assert repetition_score([]) == 0.0


class TestStagnation:
    def test_stagnation_high_for_identical_texts(self):
        texts = ["I will search the database for flights"] * 3
        assert stagnation_score(texts) == 1.0

    def test_stagnation_low_for_diverse_texts(self):
        texts = [
            "Parsing the invoice totals from row data now",
            "Booking confirmation requires passenger passport number",
            "Refund policy window expires after fourteen days",
        ]
        assert stagnation_score(texts) < 0.3

    def test_stagnation_needs_two_texts(self):
        assert stagnation_score([]) == 0.0
        assert stagnation_score(["only one text here"]) == 0.0


class TestCycle:
    def test_cycle_detects_duplicate_label(self):
        labels = ["tool:search:aaa", "tool:book:bbb", "tool:search:aaa"]
        assert cycle_score(labels) == 1.0

    def test_cycle_unique_labels_zero(self):
        labels = ["tool:a:1", "tool:b:2", "tool:c:3"]
        assert cycle_score(labels) == 0.0


class TestAgentLoopScore:
    def test_from_dict_creates_span(self):
        d = {"name": "search", "tool_name": "web_search",
             "arguments": '{"q": "x"}', "span_type": "tool"}
        s = Span.from_dict(d)
        assert s.name == "search"
        assert s.tool_name == "web_search"
        assert s.arguments == '{"q": "x"}'
        assert s.span_type == "tool"

    def test_clean_trace_no_loop(self):
        spans = [
            _span(name="a", arguments="1"),
            _span(name="b", arguments="2"),
            _span(name="c", arguments="3"),
        ]
        result = agent_loop_score(spans)
        assert result["loop_detected"] is False
        assert result["repetition"] == 0.0
        assert result["cycle"] == 0.0
        assert 0.0 <= result["weighted"] <= 1.0

    def test_weighted_math_exact(self):
        spans = [_span(name="x", arguments="1")] * 4 + [_span(name="y")]
        # repetition = 3/5; cycle = 1.0 (duplicate); no texts -> stagnation excluded
        result = agent_loop_score(spans)
        expected = round((0.5 * (3 / 5) + 0.3 * 1.0) / 0.8, 4)
        assert result["weighted"] == expected
        assert result["stagnation"] is None

    def test_with_reasoning_texts_included(self):
        spans = [_span(name=f"t{i}", arguments=str(i)) for i in range(3)]
        texts = ["same reasoning text over and over"] * 3
        result = agent_loop_score(spans, reasoning_texts=texts)
        assert result["stagnation"] == 1.0
        assert result["loop_detected"] is True
        expected = round(0.5 * 0.0 + 0.3 * 0.0 + 0.2 * 1.0, 4)
        assert result["weighted"] == expected

    def test_realistic_trace_three_identical_calls_loops(self):
        """Fixture from spec: 5 spans where 3 calls are identical."""
        same_args = '{"query": "cheapest flights LON->JFK"}'
        trace = [
            Span(name="agent_step_1", span_type="llm"),
            Span(name="web_search", arguments=same_args),
            Span(name="summarize_results", span_type="llm"),
            Span(name="web_search", arguments=same_args),
            Span(name="web_search", arguments=same_args),
        ]
        result = agent_loop_score(trace)
        assert result["cycle"] == 1.0
        assert result["repetition"] == 2 / 5
        assert result["stagnation"] is None
        assert result["loop_detected"] is True
