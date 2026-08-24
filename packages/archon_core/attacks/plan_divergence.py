"""Plan-divergence detection — declared intent vs executed trajectory.

OWASP State of Agentic AI v2.01 ranks plan-divergence detection as runtime-
governance capability #1: compare what an agent DECLARED it would do against
what it actually EXECUTED, so undeclared side effects are caught the moment
they happen rather than in post-hoc audit.

Archon already generates attacks from traces (``attacks.trace_driven``); this
module closes the loop on defense:

    plan = extract_declared_plan(agent_text)          # DeclaredPlan | None
    actions = extract_executed_actions(load_spans_jsonl("spans.jsonl"))
    report = detect_divergence(plan, actions)         # -> DivergenceReport
    report.verdict                                    # aligned|divergent|no-plan

Span sources mirror ``trace_driven.analyze_spans``: any JSONL file written by
``JsonlTracer``, or in-memory dicts of the same shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

__all__ = [
    "DeclaredPlan",
    "DivergenceReport",
    "ExecutedAction",
    "detect_divergence",
    "extract_declared_plan",
    "extract_executed_actions",
    "monitor_trajectory",
]

# English filler words stripped when mining declared action verbs from prose.
_STOPWORDS = frozenset({
    "i", "we", "you", "will", "shall", "only", "then", "and", "or", "also",
    "but", "the", "a", "an", "to", "of", "in", "on", "for", "with", "without",
    "using", "use", "just", "some", "any", "all", "no", "not", "never",
    "file", "files", "data", "things", "stuff", "them", "it", "its",
    "this", "that", "these", "those", "nothing", "else", "everything",
    "anything", "something", "during", "run", "runs", "step", "steps",
})

_PLAN_PREFIX_RE = re.compile(r"\bPLAN:\s*(?P<body>[^\n]+)", re.IGNORECASE)
_FALLBACK_PLAN_RE = re.compile(
    r"\bI\s+will(?:\s+only)?\s+(?P<body>[^.\n]+)", re.IGNORECASE
)
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")


@dataclass(frozen=True)
class DeclaredPlan:
    """What the agent declared it would do, before acting."""

    intent: str
    allowed_actions: tuple[str, ...]


@dataclass
class ExecutedAction:
    """A single observed tool invocation mined from the span stream."""

    tool: str
    args_summary: str = ""
    timestamp: float = 0.0


@dataclass
class DivergenceReport:
    """Outcome of comparing a declared plan against the executed trajectory."""

    undeclared_actions: list[str] = field(default_factory=list)
    declared_unused: list[str] = field(default_factory=list)
    divergence_score: float = 0.0
    plan: DeclaredPlan | None = None
    executed: list[ExecutedAction] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        """'no-plan' when nothing was declared, 'divergent' on undeclared use."""
        if self.plan is None:
            return "no-plan"
        if self.undeclared_actions:
            return "divergent"
        return "aligned"


def _mine_action_tokens(body: str) -> tuple[str, ...]:
    seen: set[str] = set()
    actions: list[str] = []
    for token in _TOKEN_RE.findall(body):
        token = token.strip(".").lower()
        if not token or token in _STOPWORDS:
            continue
        if token not in seen:
            seen.add(token)
            actions.append(token)
    return tuple(actions)


def extract_declared_plan(text: str) -> DeclaredPlan | None:
    """Parse an agent's declared plan from its own text.

    Prefers explicit ``PLAN: ...`` statements; falls back to natural phrasing
    like ``I will only read files``. Returns ``None`` when neither pattern is
    present (the 'no-plan' verdict case).
    """
    match = _PLAN_PREFIX_RE.search(text) or _FALLBACK_PLAN_RE.search(text)
    if not match:
        return None
    body = match.group("body").strip()
    actions = _mine_action_tokens(body)
    return DeclaredPlan(intent=body, allowed_actions=actions)


def extract_executed_actions(spans: Iterable[dict[str, Any]]) -> list[ExecutedAction]:
    """Mine tool invocations from JsonlTracer-shaped span records.

    Mirrors ``trace_driven.analyze_spans`` conventions: spans named like
    ``tool.<name>`` or carrying a ``tool_name`` attribute count as executions.
    """
    actions: list[ExecutedAction] = []
    prefix = len("tool.")
    for span in spans:
        name = str(span.get("name", ""))
        attrs = span.get("attributes") or {}
        timestamp = float(span.get("started_at_unix") or 0.0)

        tool_name = attrs.get("tool_name")
        if tool_name:
            actions.append(
                ExecutedAction(
                    tool=str(tool_name),
                    args_summary=str(attrs.get("args_summary", "")),
                    timestamp=timestamp,
                )
            )
        elif name.startswith("tool.") and len(name) > prefix:
            actions.append(ExecutedAction(tool=name[prefix:], timestamp=timestamp))
    return actions


def detect_divergence(
    plan: DeclaredPlan | None, executed: list[ExecutedAction]
) -> DivergenceReport:
    """Compare declared actions against executed ones (capability #1).

    Score is undeclared / total_executed in [0, 1]; 0 when nothing executed
    (or nothing diverged). With no plan at all, the verdict is 'no-plan'.
    """
    executed_tools: list[str] = []
    for action in executed:
        if action.tool not in executed_tools:
            executed_tools.append(action.tool)

    if plan is None:
        return DivergenceReport(plan=None, executed=executed)

    undeclared = [t for t in executed_tools if t not in plan.allowed_actions]
    unused = [a for a in plan.allowed_actions if a not in executed_tools]
    score = len(undeclared) / len(executed) if executed else 0.0
    return DivergenceReport(
        undeclared_actions=undeclared,
        declared_unused=unused,
        divergence_score=score,
        plan=plan,
        executed=executed,
    )


def monitor_trajectory(
    spans: Iterable[dict[str, Any]], plan_text: str = ""
) -> DivergenceReport:
    """Convenience: extract + detect in one call over a span stream."""
    plan = extract_declared_plan(plan_text) if plan_text else None
    executed = extract_executed_actions(list(spans))
    return detect_divergence(plan, executed)
