"""Typed metric output contract for Archon judges (Sprint 75).

Every judge's number is only as trustworthy as the judge itself — per
'A Coin Flip for Safety', LLM judges can agree with human labels barely
better than a coin flip, so a judge's raw output must be (a) typed against
a declared shape and (b) checked for agreement with humans before it is
published.

The output taxonomy mirrors ragas ``MetricOutputType``
(ragas/src/ragas/metrics/base.py, ~line 67): BINARY / DISCRETE /
CONTINUOUS / RANKING. ``metric_contract`` is a decorator factory in the
spirit of ragas' discrete.py decorators: wrap any ``judge(text) -> value``
function and it returns ``judge(text) -> MetricResult`` with automatic
validation of the declared output type.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

__all__ = [
    "MetricOutputType",
    "MetricResult",
    "agreement_report",
    "kappa_agreement",
    "metric_contract",
]

_BINARY_VALUES = {0, 1, True, False}


class MetricOutputType(str, Enum):
    """Declared shape of a judge/metric output (mirrors ragas base.py).

    Attributes
    ----------
    BINARY : str
        0/1 (or True/False) verdicts, e.g. attack succeeded or not.
    CONTINUOUS : str
        A float in [0.0, 1.0], e.g. a graded severity score.
    DISCRETE : str
        A label from a finite allowed set, e.g. pass/partial/fail.
    RANKING : str
        An ordered list of integer positions, e.g. preference ranking.
    """

    BINARY = "binary"
    CONTINUOUS = "continuous"
    DISCRETE = "discrete"
    RANKING = "ranking"


@dataclass
class MetricResult:
    """A validated judge output with its declared type.

    Attributes
    ----------
    value : object
        The raw judge value; must satisfy the constraints of
        ``output_type`` when ``validate()`` is called.
    output_type : MetricOutputType
        The declared shape of ``value``.
    reason : str | None
        Optional free-text justification from the judge.
    allowed_values : frozenset | None
        For DISCRETE results: the finite set of legal labels.
    """

    value: object
    output_type: MetricOutputType
    reason: str | None = None
    allowed_values: frozenset | None = field(default=None)

    def validate(self) -> "MetricResult":
        """Check ``value`` against ``output_type``; raise ValueError if invalid.

        BINARY values must be in {0, 1, True, False}; CONTINUOUS values must
        lie in [0, 1]; DISCRETE values must be members of ``allowed_values``
        when that set was provided at construction; RANKING values must be a
        list of ints. Returns self on success so calls can chain.
        """
        if self.output_type is MetricOutputType.BINARY:
            if self.value not in _BINARY_VALUES:
                raise ValueError(
                    f"BINARY result must be in {{0, 1, True, False}}, got {self.value!r}"
                )
        elif self.output_type is MetricOutputType.CONTINUOUS:
            if not isinstance(self.value, (int, float)) or isinstance(
                self.value, bool
            ):
                raise ValueError(
                    f"CONTINUOUS result must be numeric, got {self.value!r}"
                )
            if not 0.0 <= self.value <= 1.0:
                raise ValueError(
                    f"CONTINUOUS result must be in [0, 1], got {self.value!r}"
                )
        elif self.output_type is MetricOutputType.DISCRETE:
            if self.allowed_values is not None and self.value not in self.allowed_values:
                allowed = sorted(self.allowed_values, key=repr)
                raise ValueError(
                    f"DISCRETE result {self.value!r} not in allowed set {allowed}"
                )
        elif self.output_type is MetricOutputType.RANKING:
            if not isinstance(self.value, list) or not all(
                isinstance(v, int) and not isinstance(v, bool) for v in self.value
            ):
                raise ValueError(
                    f"RANKING result must be a list of ints, got {self.value!r}"
                )
        return self

    def to_dict(self) -> dict:
        """Serialize to a plain dict (``output_type`` as its string value)."""
        return {
            "value": self.value,
            "output_type": self.output_type.value,
            "reason": self.reason,
        }


def metric_contract(
    output_type: MetricOutputType,
    allowed_values: frozenset | set | None = None,
) -> Callable:
    """Decorator factory: enforce an output contract on a judge function.

    Wraps a ``judge(text) -> value`` function into one returning a validated
    ``MetricResult``. The wrapped function may instead return a
    ``(value, reason)`` tuple, in which case the reason is passed through to
    the result. Validation errors surface immediately as ValueError rather
    than silently polluting downstream metrics.

    Mirrors the decorator style of ragas metrics/discrete.py, with the
    output taxonomy from ragas metrics/base.py MetricOutputType.
    """

    def decorator(fn: Callable) -> Callable:
        def wrapper(text: str) -> MetricResult:
            out = fn(text)
            if isinstance(out, tuple) and len(out) == 2:
                value, reason = out
            else:
                value, reason = out, None
            return MetricResult(
                value=value,
                output_type=output_type,
                reason=reason,
                allowed_values=frozenset(allowed_values) if allowed_values else None,
            ).validate()

        return wrapper

    return decorator


def kappa_agreement(ratings_a: list, ratings_b: list) -> float:
    """Cohen's kappa between two raters over equal-length label lists.

    kappa = (po - pe) / (1 - pe), where po is observed agreement and pe the
    agreement expected by chance given each rater's marginal distribution
    (standard confusion-matrix formulation; implemented with stdlib only).

    kappa is undefined when pe == 1 — e.g. both raters emit a single
    category, making 1 - pe == 0. By documented convention this function
    returns 0.0 in that case rather than raising: no disagreement
    information exists, so no agreement credit is granted.

    Raises ValueError when the lists differ in length.
    """
    if len(ratings_a) != len(ratings_b):
        raise ValueError("ratings_a and ratings_b must be equal length")
    n = len(ratings_a)
    if n == 0:
        return 0.0

    categories = set(ratings_a) | set(ratings_b)
    counts_a: dict = {}
    counts_b: dict = {}
    matches = 0
    for a, b in zip(ratings_a, ratings_b, strict=True):
        counts_a[a] = counts_a.get(a, 0) + 1
        counts_b[b] = counts_b.get(b, 0) + 1
        matches += a == b

    po = matches / n
    pe = sum(counts_a.get(c, 0) * counts_b.get(c, 0) for c in categories) / (n * n)
    if pe == 1.0:
        # Undefined (single-category raters): documented fallback is 0.0.
        return 0.0
    return (po - pe) / (1.0 - pe)


def agreement_report(
    judge_fn: Callable, dataset: list[tuple]
) -> dict:
    """Measure a judge's reliability against human labels.

    Runs ``judge_fn(text)`` over ``dataset`` entries of ``(text,
    human_label)`` pairs and reports:

    - ``predictions``: the judge's raw values (unwrapped from MetricResult
      when the judge is contract-decorated),
    - ``accuracy``: fraction of predictions equal to human labels (4dp),
    - ``kappa``: Cohen's kappa between predictions and human labels.

    This operationalizes 'A Coin Flip for Safety': publish a judge only
    after showing its agreement with humans exceeds chance.
    """
    predictions: list = []
    human_labels: list = []
    for text, human_label in dataset:
        raw = judge_fn(text)
        if isinstance(raw, MetricResult):
            raw = raw.value  # contract-decorated judge: use its validated value
        predictions.append(raw)
        human_labels.append(human_label)

    correct = sum(p == h for p, h in zip(predictions, human_labels, strict=True))
    accuracy = round(correct / len(predictions), 4) if predictions else 0.0
    return {
        "predictions": predictions,
        "accuracy": accuracy,
        "kappa": kappa_agreement(predictions, human_labels),
    }
