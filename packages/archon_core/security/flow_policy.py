"""AgentFlow path-rules YAML subset (Sprint 93, no-SMT flow policy).

Implements the no-SMT subset of arXiv:2608.22868: a finite security lattice
(Public < Internal < Confidential < Restricted < TopSecret) with dot-path
categories, flow rules evaluated default-deny (deny beats allow), and
path rules over session traces using sequence/eventually/repeat_max
operators. Deterministic and stdlib-only.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SENSITIVITIES: tuple[str, ...] = (
    "Public",
    "Internal",
    "Confidential",
    "Restricted",
    "TopSecret",
)

_SENS_RANK = {name: i for i, name in enumerate(SENSITIVITIES)}

_OPS = ("sequence", "eventually", "repeat_max")

_EFFECTS = ("allow", "deny")


def _category_covered(cat: str, by: str) -> bool:
    """True when ``by`` covers ``cat`` under dot-path prefix semantics."""
    return cat == by or cat.startswith(by + ".")


@dataclass(frozen=True)
class Label:
    """A lattice label: sensitivity rank plus dot-path categories."""

    sensitivity: str
    categories: frozenset[str] = field(default=frozenset())
    trusted: bool = True

    def __post_init__(self) -> None:
        if self.sensitivity not in _SENS_RANK:
            raise ValueError(f"unknown sensitivity: {self.sensitivity!r}")

    def _rank(self) -> int:
        return _SENS_RANK[self.sensitivity]

    def is_compatible(self, dst: Label) -> bool:
        """Information-flow check: this label may flow into ``dst``."""
        if self._rank() > dst._rank():
            return False
        if not dst.categories:
            return True
        return all(
            any(_category_covered(c, d) for d in dst.categories)
            for c in self.categories
        )

    def join(self, other: Label) -> Label:
        """Least upper bound."""
        return Label(
            sensitivity=SENSITIVITIES[max(self._rank(), other._rank())],
            categories=self.categories | other.categories,
            trusted=self.trusted and other.trusted,
        )

    def meet(self, other: Label) -> Label:
        """Greatest lower bound."""
        return Label(
            sensitivity=SENSITIVITIES[min(self._rank(), other._rank())],
            categories=self.categories & other.categories,
            trusted=self.trusted or other.trusted,
        )


def parse_label(data: dict) -> Label:
    """Build a Label from a mapping; raises ValueError on bad sensitivity."""
    sens = data.get("sensitivity")
    if not isinstance(sens, str) or sens not in _SENS_RANK:
        raise ValueError(f"unknown sensitivity: {sens!r}")
    cats = data.get("categories") or []
    return Label(
        sensitivity=sens,
        categories=frozenset(str(c) for c in cats),
        trusted=bool(data.get("trusted", True)),
    )


@dataclass(frozen=True)
class FlowRule:
    """Edge rule: source/dest node predicates with optional label predicate."""

    name: str
    source_pred: str
    dest_pred: str
    effect: str  # "allow" | "deny"
    label_pred: str = ""


@dataclass(frozen=True)
class PathRule:
    """Trace rule evaluated over an ordered list of event names."""

    name: str
    op: str  # "sequence" | "eventually" | "repeat_max"
    pattern: tuple[str, ...]
    max_repeat: int = 0


def _matches(pred: str, name: str) -> bool:
    return pred in name


def _label_matches(pred: str, *labels: Label) -> bool:
    return any(
        pred in cat or any(pred in part for part in cat.split(".")) or pred in cat
        for lab in labels
        for cat in lab.categories
    ) or any(pred in lab.sensitivity.lower() or pred in lab.sensitivity for lab in labels)


def evaluate_flow(rules: list[FlowRule], edge: dict) -> str:
    """Evaluate flow rules against an edge; default deny, deny beats allow."""
    src_name = edge["node_names"][0]
    dst_name = edge["node_names"][-1]
    allowed = False
    for raw in rules:
        rule = FlowRule(
            name=str(raw["name"]),
            source_pred=str(raw.get("source_pred", "")),
            dest_pred=str(raw.get("dest_pred", "")),
            effect=raw["effect"],
            label_pred=str(raw.get("label_pred", "")),
        ) if isinstance(raw, dict) else raw
        if not _matches(rule.source_pred, src_name):
            continue
        if not _matches(rule.dest_pred, dst_name):
            continue
        if rule.label_pred and not _label_matches(
            rule.label_pred, edge["source_label"], edge["dest_label"]
        ):
            continue
        if rule.effect == "deny":
            return "deny"
        allowed = True
    return "allow" if allowed else "deny"


def _seq_at(trace: list[str], pattern: tuple[str, ...], start: int) -> bool:
    return all(_matches(p, trace[start + i]) for i, p in enumerate(pattern))


def check_path(rule: dict, trace: list[str]) -> bool:
    """Return True when the rule is violated on ``trace``."""
    op = rule["op"]
    pattern = tuple(rule.get("pattern", ()))

    if op == "sequence":
        n = len(pattern)
        if n == 0:
            return False
        return any(_seq_at(trace, pattern, i) for i in range(len(trace) - n + 1))

    if op == "eventually":
        idx = 0
        for event in trace:
            if idx < len(pattern) and _matches(pattern[idx], event):
                idx += 1
        return idx == len(pattern)

    if op == "repeat_max":
        max_repeat = int(rule["max_repeat"])
        n = len(pattern)
        if n == 0:
            return False
        count = sum(1 for i in range(len(trace) - n + 1) if _seq_at(trace, pattern, i))
        return count > max_repeat

    raise ValueError(f"unknown op: {op!r}")


def load_flow_policy(doc: dict) -> tuple[list[FlowRule], list[PathRule]]:
    """Load policy from a parsed YAML dict; ValueError on unknown fields."""
    rules: list[FlowRule] = []
    for raw in doc.get("flow_rules", ()):
        effect = raw.get("effect", "")
        if effect not in _EFFECTS:
            raise ValueError(f"unknown effect: {effect!r}")
        rules.append(
            FlowRule(
                name=str(raw.get("name", "")),
                source_pred=str(raw.get("source_pred", "")),
                dest_pred=str(raw.get("dest_pred", "")),
                effect=effect,
                label_pred=str(raw.get("label_pred", "")),
            )
        )

    path_rules: list[PathRule] = []
    for raw in doc.get("path_rules", ()):
        op = raw.get("op", "")
        if op not in _OPS:
            raise ValueError(f"unknown op: {op!r}")
        sens = raw.get("sensitivity")
        if sens is not None and sens not in _SENS_RANK:
            raise ValueError(f"unknown sensitivity: {sens!r}")
        path_rules.append(
            PathRule(
                name=str(raw.get("name", "")),
                op=op,
                pattern=tuple(str(p) for p in raw.get("pattern", ())),
                max_repeat=int(raw.get("max_repeat", 0)),
            )
        )
    return rules, path_rules
