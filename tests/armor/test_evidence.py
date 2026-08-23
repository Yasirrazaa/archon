"""TDD Sprint E2.5-14: compliance evidence automation.

Covers tamper-evident artifacts (EU AI Act Art 12 automatic event logging;
ISO/IEC 42001 Annex A.6.1.6 behavioural reconstruction), evidence-pack
derivation from battle reports (Art 15 robustness; NIST AI RMF MEASURE-2 /
MANAGE-2), covenant-aligned rendering, and append-only hash chains.
"""

import hashlib
import json

from archon_core.reporting.evidence import (
    EvidenceArtifact,
    build_evidence_pack,
    chain_of_custody,
    render_evidence_md,
)

RICH_REPORT = {
    "agent_id": "support-agent",
    "battle_id": "b-123",
    "total_probes": 8,
    "blocked": 7,
    "block_rate": 0.875,
    "control_passed": True,
    "coverage": {
        "LLM01_prompt_injection": {"probes": 4, "blocked": 4},
        "LLM07_system_prompt_leakage": {"probes": 1, "blocked": 0},
        "benign": {"probes": 1, "blocked": 0},
    },
    "severity": {
        "findings": [
            {
                "probe_name": "llm07_first_message_recall",
                "category": "owasp_llm_07",
                "score": 8.5,
                "band": "high",
                "vector": "ARCHON:1/CAT:owasp_llm_07",
            }
        ],
        "max_score": 8.5,
        "bands": {"high": 1},
    },
}

SPARSE_REPORT = {
    "agent_id": "empty-agent",
    "battle_id": "b-0",
    "total_probes": 0,
    "blocked": 0,
    "block_rate": 0.0,
    "control_passed": False,
}


def _payload_sha(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()


class TestEvidenceArtifact:
    def test_content_hash_is_deterministic_sha256_of_payload(self):
        a1 = EvidenceArtifact("report", ["EU-AI-ACT-Art15"], "2026-01-01T00:00:00Z", {"k": 1})
        a2 = EvidenceArtifact("report", ["EU-AI-ACT-Art15"], "2026-01-01T00:00:00Z", {"k": 1})
        assert a1.content_hash == _payload_sha({"k": 1})
        assert a1 == a2  # frozen dataclass equality; same inputs → same hash

    def test_hash_changes_when_payload_changes(self):
        a1 = EvidenceArtifact("report", [], "t", {"k": 1})
        a2 = EvidenceArtifact("report", [], "t", {"k": 2})
        assert a1.content_hash != a2.content_hash

    def test_is_frozen(self):
        a = EvidenceArtifact("report", [], "t", {"k": 1})
        try:
            a.kind = "tampered"  # type: ignore[misc]
        except Exception:
            return
        raise AssertionError("EvidenceArtifact must be frozen")


class TestBuildEvidencePack:
    def test_rich_report_derives_all_controls(self):
        pack = build_evidence_pack(RICH_REPORT, policy_version="v2.1", agent_id="support-agent")
        assert pack["pack_version"] == "1"
        assert pack["agent_id"] == "support-agent"
        assert pack["policy_version"] == "v2.1"
        assert pack["generated_at"].endswith("+00:00") or pack["generated_at"].endswith("Z")

        ids = {c["control_id"] for c in pack["controls"]}
        # block_rate > 0 → Art15 robustness + MEASURE-2
        assert "EU-AI-ACT-Art15" in ids
        assert "NIST-MEASURE-2" in ids
        # control_passed → MANAGE-2
        assert "NIST-MANAGE-2" in ids
        # severity findings → Art9 risk management
        assert "EU-AI-ACT-Art9" in ids
        # any results → ISO logging reconstruction
        assert "ISO-42001-A.6.1.6" in ids

    def test_iso_control_evidence_ref_counts_probe_verdicts(self):
        pack = build_evidence_pack(RICH_REPORT)
        iso = next(c for c in pack["controls"] if c["control_id"] == "ISO-42001-A.6.1.6")
        assert "8" in iso["evidence_ref"]  # total_probes = 8

    def test_sparse_report_still_yields_iso_logging_control(self):
        pack = build_evidence_pack(SPARSE_REPORT)
        ids = {c["control_id"] for c in pack["controls"]}
        assert ids == {"ISO-42001-A.6.1.6"}

    def test_agent_id_falls_back_to_report(self):
        pack = build_evidence_pack(RICH_REPORT)
        assert pack["agent_id"] == "support-agent"

    def test_every_control_has_required_fields(self):
        pack = build_evidence_pack(RICH_REPORT)
        for c in pack["controls"]:
            assert set(c) == {"control_id", "framework", "description", "evidence_ref"}
            assert c["framework"]
            assert c["description"]
            assert c["evidence_ref"]


class TestRenderEvidenceMd:
    def test_header_contains_identity_and_hash(self):
        pack = build_evidence_pack(RICH_REPORT, policy_version="v2.1")
        md = render_evidence_md(pack)
        assert "support-agent" in md
        assert "v2.1" in md
        assert pack["generated_at"] in md
        assert pack["content_hash"] in md

    def test_controls_table_rows_present(self):
        pack = build_evidence_pack(RICH_REPORT)
        md = render_evidence_md(pack)
        assert "| Control | Framework | Evidence |" in md
        for c in pack["controls"]:
            assert c["control_id"] in md

    def test_covenant_lines_all_present(self):
        pack = build_evidence_pack(SPARSE_REPORT)
        md = render_evidence_md(pack)
        assert "Retention & covenant notes" in md
        assert "tamper-evident" in md.lower()
        assert "24-month" in md or "24 month" in md.lower()
        assert "552.239-7001" in md
        assert "90-day" in md or "90 day" in md.lower()
        assert "72" in md  # 72-hour incident reporting readiness


class TestChainOfCustody:
    def _artifact(self, n: int) -> EvidenceArtifact:
        return EvidenceArtifact("log", [], "t", {"seq": n})

    def test_returns_prefixed_hex_digest(self):
        chain = chain_of_custody([self._artifact(1), self._artifact(2)])
        assert chain.startswith("chain:")
        digest = chain.removeprefix("chain:")
        int(digest, 16)  # valid hex
        assert len(digest) == 64

    def test_order_sensitive(self):
        a, b = self._artifact(1), self._artifact(2)
        assert chain_of_custody([a, b]) != chain_of_custody([b, a])

    def test_stable_for_same_order(self):
        arts = [self._artifact(i) for i in range(3)]
        assert chain_of_custody(arts) == chain_of_custody(list(arts))

    def test_matches_manual_rolling_hash(self):
        arts = [self._artifact(i) for i in (10, 20)]
        h = ""
        for a in arts:
            h = hashlib.sha256(
                (json.dumps(a.payload, sort_keys=True) + h).encode("utf-8")
            ).hexdigest()
        assert chain_of_custody(arts) == "chain:" + h
