"""Agent-loop detection metric for execution traces.

Zero-LLM-cost, stdlib-only re-implementation of the sub-signals from
deepeval's ``AgentLoopDetectionMetric``
(deepeval/deepeval/metrics/agent_loop_detection/agent_loop_detection.py):

1. **Repetition** — fraction of spans whose
   ``span_type:tool_name:arg_hash`` label already appeared earlier in the
   trace (identical-call repetition).
2. **Stagnation** — MAX consecutive-pair bigram-Jaccard similarity across
   reasoning texts, with stop words filtered. We deliberately return the
   *maximum* over consecutive pairs (not a mean) so that one verbatim
   repeated reasoning step is enough to flag stagnation: high score means
   stagnant. Returns 0.0 when fewer than 2 texts are supplied.
3. **Cycle** — simplified DFS back-edge detection: ordered labels are
   treated as a path graph, so any repeated label forms a cycle
   (a back-edge to its earlier occurrence). Score is 1.0 if any label
   duplicates, else 0.0.

The aggregate returns each sub-score plus ``loop_detected`` (any
sub-signal > 0.5) and a weighted blend. When no reasoning texts are
given, stagnation is excluded from the weighted sum and the remaining
weights are renormalized so the result stays in [0, 1].
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

__all__ = [
    "Span",
    "_call_label",
    "agent_loop_score",
    "cycle_score",
    "repetition_score",
    "stagnation_score",
]

# Mirrors deepeval agent_loop_detection._STOP_WORDS (subset sufficient to
# keep boilerplate phrases from inflating Jaccard similarity).
_STOP_WORDS = frozenset(
    "the a an is are was were i will now based on information provided "
    "to of in and that this with for it my next step going so do be have "
    "has not but as or from at by about above below up its let".split()
)


@dataclass(frozen=True)
class Span:
    """One step of an agent trace (tool call or LLM reasoning span)."""

    name: str
    tool_name: str | None = None
    arguments: str | None = None
    span_type: str = "tool"

    @classmethod
    def from_dict(cls, d: dict) -> Span:
        return cls(
            name=d.get("name", ""),
            tool_name=d.get("tool_name"),
            arguments=d.get("arguments"),
            span_type=d.get("span_type", "tool"),
        )


def _call_label(span: Span) -> str:
    """Stable identity label: ``type:name[:12-hex sha256 of arguments]``."""
    if span.arguments:
        arg_hash = hashlib.sha256(span.arguments.encode()).hexdigest()[:12]
    else:
        arg_hash = "none"
    return f"{span.span_type}:{span.tool_name or span.name}:{arg_hash}"


def _bigrams(text: str) -> set[tuple[str, str]]:
    words = [
        w for w in text.lower().split() if w not in _STOP_WORDS and len(w) > 2
    ]
    return set(zip(words, words[1:]))


def stagnation_score(texts: list[str]) -> float:
    """MAX consecutive-pair bigram-Jaccard similarity; high = stagnant.

    Returning the max (documented choice) flags stagnation as soon as any
    single pair of consecutive reasoning steps repeats, instead of
    diluting it across an otherwise diverse trace. 0.0 when < 2 texts.
    """
    if len(texts) < 2:
        return 0.0
    max_sim = 0.0
    for a, b in zip(texts, texts[1:]):
        bg_a, bg_b = _bigrams(a), _bigrams(b)
        union = bg_a | bg_b
        if not union:
            continue
        max_sim = max(max_sim, len(bg_a & bg_b) / len(union))
        if max_sim == 1.0:
            break
    return max_sim


def repetition_score(spans: list[Span]) -> float:
    """Fraction of spans whose call label already appeared before them."""
    if not spans:
        return 0.0
    seen: set[str] = set()
    repeats = 0
    for span in spans:
        label = _call_label(span)
        if label in seen:
            repeats += 1
        seen.add(label)
    return repeats / len(spans)


def cycle_score(labels: list[str]) -> float:
    """1.0 if any label repeats along the ordered path (DFS back-edge)."""
    return 1.0 if len(set(labels)) < len(labels) else 0.0


def agent_loop_score(
    spans: list[Span], reasoning_texts: list[str] | None = None
) -> dict:
    """Aggregate loop signals into a single verdict dict.

    ``loop_detected`` is True when any available sub-signal exceeds 0.5.
    Without ``reasoning_texts`` the stagnation weight (0.2) is dropped and
    remaining weights renormalized so ``weighted`` stays in [0, 1].
    """
    rep = repetition_score(spans)
    cyc = cycle_score([_call_label(s) for s in spans])
    stag: float | None = (
        stagnation_score(reasoning_texts) if reasoning_texts is not None else None
    )

    total_w = 0.5 + 0.3 + (0.2 if stag is not None else 0.0)
    weighted = 0.5 * rep + 0.3 * cyc + 0.2 * (stag or 0.0)

    signals = [rep, cyc] + ([stag] if stag is not None else [])
    return {
        "repetition": rep,
        "stagnation": stag,
        "cycle": cyc,
        "loop_detected": any(s > 0.5 for s in signals),
        "weighted": round(weighted / total_w, 4),
    }
