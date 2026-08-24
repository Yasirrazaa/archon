"""Ensemble score aggregation for boolean safety verdicts.

Modeled on PyRIT's ``TrueFalseScoreAggregator``
(PyRIT/pyrit/score/true_false/true_false_score_aggregator.py), which
reduces lists of true/false scores with ``operator.and_``/``or_`` and a
strict-majority rule (``sum(bs) > len(bs)/2``). Here a *scorer* is simply
``Callable[[str], bool]`` mapping response text to "unsafe?".

Rationale: ensembling heterogeneous scorers — cheap regex/substring
detectors plus LLM judges — trades compute for accuracy. An OR ensemble
cuts false negatives (any detector firing flags the payload, catching
paraphrases a single regex misses); an AND ensemble cuts false positives
(only payloads every judge agrees on are flagged); majority voting
smooths noisy individual judges.

Empty-list behavior is documented and uniform: all three aggregators
return False on an empty input (PyRIT also returns a neutral False for
no scores). For AND this deliberately forgoes vacuous truth so that
"no evidence" never reads as "flagged".
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

__all__ = [
    "EnsembleScorer",
    "Scorer",
    "WeightedEnsemble",
    "aggregate_and",
    "aggregate_majority",
    "aggregate_or",
    "summarize_ensemble",
]

Verdict = bool
Scorer = Callable[[str], Verdict]

_STRATEGIES = ("and", "or", "majority")


def aggregate_and(scores: list[Verdict]) -> Verdict:
    """True iff every verdict is True (PyRIT ``AND``, reduce of ``and_``).

    Empty list -> False by documented choice: an empty conjunction must
    not flag anything.
    """
    return bool(scores) and all(scores)


def aggregate_or(scores: list[Verdict]) -> Verdict:
    """True iff any verdict is True (PyRIT ``OR``, reduce of ``or_``).

    Empty list -> False.
    """
    return any(scores)


def aggregate_majority(scores: list[Verdict]) -> Verdict:
    """Strict majority of True verdicts (PyRIT ``MAJORITY``).

    Uses ``sum(scores) > len(scores) / 2``; ties therefore resolve to
    False (documented choice matching PyRIT's strict comparison).
    Empty list -> False.
    """
    return sum(scores) > len(scores) / 2


class EnsembleScorer:
    """Apply every scorer to the text and combine verdicts by strategy.

    Mirrors PyRIT's composite-scorer pattern: one call fans out to N
    scorers, then folds their booleans via ``aggregate_and``,
    ``aggregate_or``, or ``aggregate_majority``.
    """

    def __init__(self, scorers: list[Scorer], strategy: str):
        if strategy not in _STRATEGIES:
            raise ValueError(
                f"strategy must be one of {_STRATEGIES}, got {strategy!r}"
            )
        self.scorers = scorers
        self.strategy = strategy

    def __call__(self, text: str) -> Verdict:
        scores = [scorer(text) for scorer in self.scorers]
        combine = {
            "and": aggregate_and,
            "or": aggregate_or,
            "majority": aggregate_majority,
        }[self.strategy]
        return combine(scores)


class WeightedEnsemble:
    """Confidence-weighted mean of 0/1 verdicts against a threshold.

    Generalizes majority voting with fractional weights (cf. PyRIT's
    float-scale thresholding in ``float_scale_threshold_scorer.py``):
    each scorer contributes ``weight * (0 or 1)``, normalized by total
    weight, and the text is flagged when the weighted mean is >=
    ``threshold`` (inclusive boundary).
    """

    def __init__(self, items: list[tuple[Scorer, float]], threshold: float):
        self.items = items
        self.threshold = threshold

    def weighted_mean(self, text: str) -> float:
        total_weight = sum(w for _, w in self.items)
        if not self.items or total_weight == 0:
            return 0.0
        return sum(scorer(text) * w for scorer, w in self.items) / total_weight

    def __call__(self, text: str) -> Verdict:
        return self.weighted_mean(text) >= self.threshold


def summarize_ensemble(texts: Sequence[str], scorer: Scorer) -> dict:
    """Flag-rate summary over texts: ``{n, flagged, rate}``.

    ``rate`` is the fraction of flagged texts rounded to 4 decimal
    places (0.0 for no texts).
    """
    n = len(texts)
    flagged = sum(bool(scorer(t)) for t in texts)
    rate = round(flagged / n, 4) if n else 0.0
    return {"n": n, "flagged": flagged, "rate": rate}
