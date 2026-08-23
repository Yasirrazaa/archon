"""TDD Sprint E2.5-15: certification conformance profiles.

Maps Archon evidence packs onto live agentic certification schemes:
- AIUC-1 (first certifications expected April 2026; CSA STAR Level 2
  designation; quarterly refreshes of certified evidence).
- CSA STAR for Agentic (launched at RSAC 2026; Level 2 maps the AICM
  Agentic Supplement alongside ISO/IEC 42001, EU AI Act, and NIST RMF).

Covers assessment status logic (satisfied/partial/unmet), markdown
rendering with honest audit disclaimers, aggregate readiness, gap
reporting, unknown-scheme rejection, and determinism.
"""

import dataclasses

import pytest
from archon_core.reporting.certification import (
    ConformanceProfile,
    assess,
    certification_readiness,
    render_profile_md,
)
from archon_core.reporting.evidence import build_evidence_pack

RICH_REPORT = {
    "agent_id": "support-agent",
    "total_probes": 8,
    "blocked": 7,
    "block_rate": 0.875,
    "control_passed": True,
    "severity": {
        "findings": [
            {"probe_name": "p", "category": "owasp_llm_07", "score": 8.5, "band": "high"}
        ],
        "bands": {"high": 1},
    },
}

EXTRA_CONTROLS = [
    {"control_id": cid, "framework": "Archon", "description": cid, "evidence_ref": cid}
    for cid in (
        "ARCHON-MCP-SHIELD",
        "ARCHON-TOOL-CALL-GUARD",
        "ARCHON-RBAC-BASELINE",
        "ARCHON-AICIE-INCIDENT",
    )
]


def _rich_pack() -> dict:
    pack = build_evidence_pack(RICH_REPORT, policy_version="v2.1")
    pack["controls"] = pack["controls"] + EXTRA_CONTROLS
    return pack


class TestAssessAiuc1:
    def test_rich_pack_satisfies_at_least_four_aiuc1_requirements(self):
        profile = assess(_rich_pack(), "aiuc-1")
        satisfied = [r["requirement"] for r in profile.requirements if r["status"] == "satisfied"]
        assert len(satisfied) >= 4

    def test_sparse_pack_mostly_unmet(self):
        pack = build_evidence_pack({"agent_id": "a", "total_probes": 0})
        profile = assess(pack, "aiuc-1")
        statuses = [r["status"] for r in profile.requirements]
        assert statuses.count("unmet") > len(statuses) // 2

    def test_partial_when_some_controls_present(self):
        # ISO-42001 logging is always emitted; other audit-logging peers absent.
        pack = build_evidence_pack({"agent_id": "a"})
        profile = assess(pack, "aiuc-1")
        row = next(r for r in profile.requirements if r["requirement"] == "audit-logging")
        assert row["status"] == "satisfied"

    def test_partial_status_for_subset_of_controls(self):
        # adversarial-evaluation needs both Art15 and MEASURE-2; a pack with
        # only one of the pair must be 'partial'.
        pack = {"controls": [{"control_id": "EU-AI-ACT-Art15"}]}
        profile = assess(pack, "aiuc-1")
        row = next(
            r for r in profile.requirements if r["requirement"] == "adversarial-evaluation"
        )
        assert row["status"] == "partial"
        assert row["evidence"] == ["EU-AI-ACT-Art15"]

    def test_satisfied_requires_all_mapped_controls(self):
        pack = {
            "controls": [
                {"control_id": "EU-AI-ACT-Art15"},
                {"control_id": "NIST-MEASURE-2"},
            ]
        }
        profile = assess(pack, "aiuc-1")
        row = next(
            r for r in profile.requirements if r["requirement"] == "adversarial-evaluation"
        )
        assert row["status"] == "satisfied"

    def test_all_six_represented_categories_present(self):
        profile = assess(_rich_pack(), "aiuc-1")
        reqs = {r["requirement"] for r in profile.requirements}
        assert {
            "adversarial-evaluation",
            "mcp-security",
            "agent-permissions",
            "third-party-risk",
            "secrets-management",
            "audit-logging",
        } <= reqs


class TestAssessCsaStar:
    def test_five_agentic_supplement_requirements_covered(self):
        profile = assess(_rich_pack(), "csa-star-agentic-l2")
        reqs = {r["requirement"] for r in profile.requirements}
        assert {
            "runtime-behavior-assessment",
            "incident-expression",
            "human-oversight",
            "supply-chain",
            "continuous-monitoring",
        } <= reqs

    def test_incident_expression_cites_aicie(self):
        profile = assess(_rich_pack(), "csa-star-agentic-l2")
        row = next(r for r in profile.requirements if r["requirement"] == "incident-expression")
        assert any("ETSI TS 104 158" in n for n in [row["notes"]])


class TestProfileShape:
    def test_frozen_dataclass(self):
        profile = assess({}, "aiuc-1")
        assert isinstance(profile, ConformanceProfile)
        assert dataclasses.is_dataclass(profile)
        try:
            profile.scheme = "tampered"  # type: ignore[misc]
        except Exception:
            return
        raise AssertionError("ConformanceProfile must be frozen")

    def test_unknown_scheme_raises_valueerror(self):
        with pytest.raises(ValueError):
            assess({}, "soc2")

    def test_determinism_same_input_same_profile(self):
        p1 = assess(_rich_pack(), "aiuc-1")
        p2 = assess(_rich_pack(), "aiuc-1")
        assert p1 == p2


class TestRenderProfileMd:
    def test_scheme_name_and_statuses_in_output(self):
        md = render_profile_md(assess(_rich_pack(), "aiuc-1"))
        assert "AIUC-1" in md
        assert "satisfied" in md
        assert "|" in md  # table rows

    def test_disclaimer_present(self):
        for scheme in ("aiuc-1", "csa-star-agentic-l2"):
            md = render_profile_md(assess(_rich_pack(), scheme))
            assert "accredited third-party audit" in md

    def test_table_rows_per_requirement(self):
        profile = assess(_rich_pack(), "csa-star-agentic-l2")
        md = render_profile_md(profile)
        for row in profile.requirements:
            assert row["requirement"] in md
            assert row["status"] in md


class TestCertificationReadiness:
    def test_percentages_bounded_and_keys_present(self):
        result = certification_readiness([_rich_pack()])
        assert {"aiuc1_pct", "csa_star_pct", "gaps"} <= set(result)
        for pct in (result["aiuc1_pct"], result["csa_star_pct"]):
            assert 0.0 <= pct <= 100.0

    def test_empty_packs_zero_ready_with_full_gaps(self):
        result = certification_readiness([])
        assert result["aiuc1_pct"] == 0.0
        assert result["csa_star_pct"] == 0.0
        assert len(result["gaps"]) > 0

    def test_gaps_list_unsatisfied_requirement_ids(self):
        sparse = build_evidence_pack({"agent_id": "a"})
        result = certification_readiness([sparse])
        aiuc = assess(sparse, "aiuc-1")
        unsatisfied = {
            r["requirement"] for r in aiuc.requirements if r["status"] != "satisfied"
        }
        assert unsatisfied & set(result["gaps"])

    def test_rich_pack_outperforms_sparse(self):
        rich = certification_readiness([_rich_pack()])
        sparse = certification_readiness(
            [build_evidence_pack({"agent_id": "a"})]
        )
        assert rich["aiuc1_pct"] > sparse["aiuc1_pct"]
