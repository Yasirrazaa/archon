"""Certification conformance profiles: mapping Archon evidence to live
agentic-AI certification schemes.

Research grounding:

- AIUC-1: the first agentic-AI certification scheme, developed by AIUC
  (Agent Integrity Institute). First certifications expected April 2026;
  certified organizations carry a CSA STAR Level 2 designation, with
  evidence refreshed quarterly to keep pace with agent behaviour drift.
- CSA STAR for Agentic: launched by the Cloud Security Alliance at RSAC
  2026 as a dedicated agentic track within STAR. Level 2 (third-party
  attested) maps the AICM Agentic Supplement domains alongside existing
  frameworks — ISO/IEC 42001, the EU AI Act, and the NIST AI RMF — so
  Archon controls already mapped to those frameworks transfer directly.
- ETSI TS 104 158 (AICIE): standardized AI incident expression, referenced
  by the CSA agentic work for machine-readable incident reporting.

Honesty rule: a conformance profile states what *evidence supports*.
It never claims certification — that requires an accredited third-party
audit; every rendered profile carries that disclaimer verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Scheme = str

AIUC1_SCHEME: Scheme = "aiuc-1"
CSA_STAR_SCHEME: Scheme = "csa-star-agentic-l2"

# Scheme + requirement -> list of Archon control IDs or evidence predicates.
# Control IDs are matched against pack["controls"]; predicate strings of the
# form "pred:<key><op><value>" are evaluated against top-level pack fields
# (ops: >=, >, ==, !=, exists).
CONTROL_MAP: dict[str, list[str]] = {
    # --- AIUC-1 categories (6 of 12 represented) ---
    "aiuc-1::adversarial-evaluation": [
        "EU-AI-ACT-Art15",
        "NIST-MEASURE-2",
    ],
    "aiuc-1::mcp-security": [
        "ARCHON-MCP-SHIELD",
        "ARCHON-TOOL-CALL-GUARD",
    ],
    "aiuc-1::agent-permissions": [
        "NIST-MANAGE-2",
        "ARCHON-RBAC-BASELINE",
    ],
    "aiuc-1::third-party-risk": [
        "ARCHON-THIRD-PARTY-VETTING",
        "pred:agent_id.exists",
    ],
    "aiuc-1::secrets-management": [
        "EU-AI-ACT-Art9",
        "ARCHON-SECRETS-HYGIENE",
    ],
    "aiuc-1::audit-logging": [
        "ISO-42001-A.6.1.6",
    ],
    # --- CSA STAR Agentic L2 (AICM Agentic Supplement domains) ---
    "csa-star-agentic-l2::runtime-behavior-assessment": [
        "EU-AI-ACT-Art15",
        "NIST-MEASURE-2",
    ],
    # ETSI TS 104 158 AICIE incident expression readiness.
    "csa-star-agentic-l2::incident-expression": [
        "ARCHON-AICIE-INCIDENT",
        "EU-AI-ACT-Art9",
    ],
    "csa-star-agentic-l2::human-oversight": [
        "ARCHON-HUMAN-IN-THE-LOOP",
        "NIST-MANAGE-2",
    ],
    "csa-star-agentic-l2::supply-chain": [
        "ARCHON-SBOM-ATTESTATION",
    ],
    "csa-star-agentic-l2::continuous-monitoring": [
        "ISO-42001-A.6.1.6",
        "ARCHON-FLEET-TELEMETRY",
    ],
}

SCHEME_LABELS = {
    AIUC1_SCHEME: "AIUC-1",
    CSA_STAR_SCHEME: "CSA STAR for Agentic (Level 2)",
}

DISCLAIMER = (
    "This conformance profile is generated from Archon adversarial-testing "
    "evidence and indicates where evidence supports scheme requirements. "
    "Evidence supports but does not replace accredited third-party audit: "
    "certification under AIUC-1 (first certifications expected April 2026, "
    "with quarterly evidence refreshes) or CSA STAR Level 2 requires an "
    "independent assessment body."
)


@dataclass(frozen=True)
class ConformanceProfile:
    """Assessed conformance of one evidence pack against one scheme."""

    scheme: str
    requirements: list[dict[str, Any]] = field(default_factory=list)


def _scheme_key(scheme: str) -> str:
    normalized = scheme.strip().lower().replace(" ", "-")
    if normalized in SCHEME_LABELS:
        return normalized
    raise ValueError(
        f"Unknown certification scheme: {scheme!r}. "
        f"Expected one of {sorted(SCHEME_LABELS)}"
    )


def _eval_predicate(pack: dict, expr: str) -> bool:
    """Evaluate 'pred:<key><op><value>' against top-level pack fields."""
    body = expr.removeprefix("pred:")
    for op in (">=", "==", "!=", ">", "<", "exists"):
        if op in body:
            key, _, raw = body.partition(op)
            key, raw = key.strip(), raw.strip()
            if op == "exists":
                return key in pack and pack[key] is not None
            if key not in pack:
                return False
            actual, expected = pack[key], _coerce(raw)
            try:
                return {
                    ">=": actual >= expected,
                    ">": actual > expected,
                    "<": actual < expected,
                    "==": actual == expected,
                    "!=": actual != expected,
                }[op]
            except TypeError:
                return False
    return False


def _coerce(raw: str) -> Any:
    try:
        return float(raw) if "." in raw else int(raw)
    except ValueError:
        return raw


def assess(evidence_pack: dict, scheme: str) -> ConformanceProfile:
    """Assess an evidence pack against a certification scheme.

    Status per requirement: ``satisfied`` when every mapped control/predicate
    is present, ``partial`` when some are present, ``unmet`` when none are.
    """
    key = _scheme_key(scheme)
    pack_controls = {c.get("control_id") for c in evidence_pack.get("controls", [])}
    rows: list[dict[str, Any]] = []
    prefix = key + "::"
    for map_key, mapped in CONTROL_MAP.items():
        if not map_key.startswith(prefix):
            continue
        present: list[str] = []
        for entry in mapped:
            if entry.startswith("pred:"):
                ok = _eval_predicate(evidence_pack, entry)
            else:
                ok = entry in pack_controls
            if ok:
                present.append(entry)
        if len(present) == len(mapped):
            status = "satisfied"
        elif present:
            status = "partial"
        else:
            status = "unmet"
        rows.append({
            "requirement": map_key.removeprefix(prefix),
            "status": status,
            "evidence": present,
            "notes": _notes(map_key),
        })
    return ConformanceProfile(scheme=key, requirements=rows)


def _notes(map_key: str) -> str:
    notes = {
        "aiuc-1::adversarial-evaluation": (
            "Adversarial probe block-rate evidence maps to EU AI Act Art 15 /"
            " NIST MEASURE-2, the evaluation core of AIUC-1 category 1."
        ),
        "aiuc-1::mcp-security": (
            "MCP/tool-call surface hardening evidence from Archon MCP battles."
        ),
        "aiuc-1::agent-permissions": (
            "Permission gating evidenced via effectiveness control pass plus"
            " RBAC baseline."
        ),
        "aiuc-1::third-party-risk": (
            "Third-party vetting plus agent identity provenance."
        ),
        "aiuc-1::secrets-management": (
            "Secrets hygiene alongside Art 9 risk-management findings."
        ),
        "aiuc-1::audit-logging": (
            "ISO/IEC 42001 A.6.1.6 behavioural reconstruction logging."
        ),
        "csa-star-agentic-l2::runtime-behavior-assessment": (
            "Runtime behavioural probing per AICM Agentic Supplement;"
            " transfers from EU AI Act Art 15 / NIST RMF mappings."
        ),
        "csa-star-agentic-l2::incident-expression": (
            "Incident expression aligned to ETSI TS 104 158 (AICIE)."
        ),
        "csa-star-agentic-l2::human-oversight": (
            "Human-in-the-loop controls; EU AI Act Art 14 analogue."
        ),
        "csa-star-agentic-l2::supply-chain": (
            "SBOM/attestation coverage for the agentic supply chain."
        ),
        "csa-star-agentic-l2::continuous-monitoring": (
            "Continuous monitoring via reconstruction logging plus fleet"
            " telemetry (ISO 42001 A.6.1.6 lineage)."
        ),
    }
    return notes.get(map_key, "")


def render_profile_md(profile: ConformanceProfile) -> str:
    """Render a conformance profile as Markdown with honest framing."""
    label = SCHEME_LABELS.get(profile.scheme, profile.scheme)
    total = len(profile.requirements)
    satisfied = sum(1 for r in profile.requirements if r["status"] == "satisfied")
    pct = round(100.0 * satisfied / total, 1) if total else 0.0
    lines = [
        f"# Conformance Profile — {label}",
        "",
        f"**Readiness:** {pct}% ({satisfied}/{total} requirements fully evidenced)",
        "",
        "| Requirement | Status | Evidence | Notes |",
        "|---|---|---|---|",
    ]
    for row in profile.requirements:
        lines.append(
            f"| {row['requirement']} | {row['status']} | "
            f"{', '.join(row['evidence']) or '—'} | {row['notes']} |"
        )
    lines += ["", f"> {DISCLAIMER}", ""]
    return "\n".join(lines)


def certification_readiness(packs: list[dict]) -> dict[str, Any]:
    """Aggregate readiness across both schemes over a set of evidence packs.

    Controls are unioned across packs before assessment, so evidence spread
    across battles combines into one organizational view.
    """
    merged_controls: dict[str, dict] = {}
    merged_fields: dict[str, Any] = {}
    for pack in packs:
        for control in pack.get("controls", []):
            cid = control.get("control_id", "")
            if cid and cid not in merged_controls:
                merged_controls[cid] = control
        for k, v in pack.items():
            if k not in ("controls", "content_hash") and v is not None:
                merged_fields.setdefault(k, v)

    def _pct(scheme: str) -> tuple[float, list[str]]:
        merged = {"controls": list(merged_controls.values()), **merged_fields}
        profile = assess(merged, scheme)
        total = len(profile.requirements)
        sat = sum(1 for r in profile.requirements if r["status"] == "satisfied")
        gaps = [r["requirement"] for r in profile.requirements if r["status"] != "satisfied"]
        return round(100.0 * sat / total, 1) if total else 0.0, gaps

    aiuc1_pct, aiuc_gaps = _pct(AIUC1_SCHEME)
    csa_pct, csa_gaps = _pct(CSA_STAR_SCHEME)
    return {
        "aiuc1_pct": aiuc1_pct,
        "csa_star_pct": csa_pct,
        "gaps": sorted(set(aiuc_gaps) | set(csa_gaps)),
    }
