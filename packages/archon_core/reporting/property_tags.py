"""Property-tagged security metrics (Sprint E3-68).

Source: arXiv:2607.22024 (ICML 2026 position, Dawn Song group) — agent
security is evaluated continuously against four *joint* properties rather
than per-attack pass/fail:

- **Source Authorization (SA)** — is this input from an authorized source?
  Classical lineage: the confused deputy problem and authentication.
- **Task Alignment (TA)** — does the action serve the user's actual task?
  Classical lineage: least privilege and authorization policy.
- **Action Alignment (AA)** — is the specific action itself permitted?
  Classical lineage: the reference monitor and control-flow integrity.
- **Data Isolation (DI)** — is data flowing only between permitted domains?
  Classical lineage: information-flow control (IFC) and noninterference.

GUARDEDJOINT quadrants record *outcomes*; tagging each finding by property
lets battle reports decompose a compromise into which of the four joint
properties was actually violated.
"""

from __future__ import annotations

from collections import Counter
from enum import Enum

__all__ = [
    "PropertyTag",
    "CLASSIFIER_RULES",
    "classify_property",
    "tag_findings",
    "summarize_by_property",
    "render_property_breakdown",
]


class PropertyTag(str, Enum):
    """The four joint properties of arXiv:2607.22024, with classical lineage.

    SA — Source Authorization (confused deputy / authentication): the request
    originates from a source not authorized to make it.
    TA — Task Alignment (least privilege / authorization policy): the action
    drifts beyond what the user's task authorizes.
    AA — Action Alignment (reference monitor / control-flow integrity): the
    individual action violates the enforced policy at mediation time.
    DI — Data Isolation (IFC / noninterference): untrusted data influences
    trusted outputs across a forbidden flow.
    """

    SA = "SA"
    TA = "TA"
    AA = "AA"
    DI = "DI"


# Deterministic category→property mapping (longest pattern first so that
# e.g. 'indirect_injection' is never shadowed by a shorter injection-family
# pattern). Matching is substring-based and case-insensitive.
CLASSIFIER_RULES: list[tuple[str, PropertyTag]] = sorted(
    [
        # SA — source of the input is unauthorized
        ("indirect_injection", PropertyTag.SA),
        ("latent_injection", PropertyTag.SA),
        ("mcp", PropertyTag.SA),
        ("tool_poisoning", PropertyTag.SA),
        ("supply_chain", PropertyTag.SA),
        # TA — action drifts from the user's task
        ("jailbreak_persona", PropertyTag.TA),
        ("goal_hijack", PropertyTag.TA),
        ("direct_injection", PropertyTag.TA),
        ("jailbreak", PropertyTag.TA),
        ("harmbench", PropertyTag.TA),
        # AA — the action itself is not permitted
        ("sandbox_escape", PropertyTag.AA),
        ("excessive_agency", PropertyTag.AA),
        ("code_exec", PropertyTag.AA),
        ("destructive", PropertyTag.AA),
        ("rce", PropertyTag.AA),
        # DI — untrusted data crosses isolation boundaries
        ("data_exfiltration", PropertyTag.DI),
        ("covert_channel", PropertyTag.DI),
        ("memory_poisoning", PropertyTag.DI),
        ("stego", PropertyTag.DI),
        ("exfil", PropertyTag.DI),
        ("session", PropertyTag.DI),
    ],
    key=lambda rule: len(rule[0]),
    reverse=True,
)


def classify_property(category: str) -> PropertyTag | None:
    """Map an Archon probe category to its violated property.

    Case-insensitive substring match over CLASSIFIER_RULES, longest pattern
    first ('-' normalized to '_' so probe spellings like 'sandbox-escape'
    match). Returns None for unknown categories.
    """
    lowered = category.lower().replace("-", "_")
    for pattern, tag in CLASSIFIER_RULES:
        if pattern in lowered:
            return tag
    return None


def tag_findings(findings: list[dict]) -> list[dict]:
    """Return copies of `findings`, each with a 'property' key added.

    The property comes from classify_property(finding['category']) and may be
    None when the category is unrecognized. The input list and its dicts are
    never mutated.
    """
    tagged = []
    for finding in findings:
        copy = dict(finding)
        copy["property"] = classify_property(copy.get("category", ""))
        tagged.append(copy)
    return tagged


def summarize_by_property(findings: list[dict]) -> dict:
    """Aggregate tagged findings into a per-property breakdown.

    Returns {'tagged': n, 'untagged': n, 'by_property': {...}} where
    by_property maps property name → count, sorted by count descending.
    """
    counts = Counter(
        f["property"] for f in findings if f.get("property") is not None
    )
    return {
        "tagged": sum(counts.values()),
        "untagged": sum(1 for f in findings if f.get("property") is None),
        "by_property": {
            tag.value: n
            for tag, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        },
    }


def render_property_breakdown(summary: dict) -> str:
    """Render a summarize_by_property summary as markdown table rows.

    Always shows all four properties (0 when absent) so the report makes the
    joint-property model explicit, plus an Untagged row.
    """
    lines = ["| Property | Findings |", "|---|---|"]
    by_property = summary.get("by_property", {})
    for prop, count in by_property.items():
        lines.append(f"| {prop} | {count} |")
    for tag in PropertyTag:
        if tag.value not in by_property:
            lines.append(f"| {tag.value} | 0 |")
    lines.append(f"| Untagged | {summary.get('untagged', 0)} |")
    return "\n".join(lines)
