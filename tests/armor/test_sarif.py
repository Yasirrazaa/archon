"""Tests for SARIF 2.1.0 output (ROADMAP item 78).

Category-first: no competitor emits SARIF. Unblocked probes become SARIF
results so scans appear natively in GitHub Code Scanning.
"""

from __future__ import annotations

import json

from archon_core.reporting.sarif import battle_report_to_sarif, render_sarif


def _report(blocked_names: set[str], severity_findings: list[dict] | None = None):
    probes = [f"p{i}" for i in range(4)]
    results = [
        {
            "probe_name": name,
            "blocked": name in blocked_names,
            "category": "owasp_llm_01" if i % 2 == 0 else "encoding_evasion",
        }
        for i, name in enumerate(probes)
    ]
    summary: dict = {"total_probes": 4, "blocked": len(blocked_names), "block_rate": len(blocked_names) / 4}
    if severity_findings is not None:
        summary["severity"] = {"findings": severity_findings}
    return {"results": results, "summary": summary}


FINDINGS = [
    {"probe_name": "p0", "category": "owasp_llm_01", "score": 9.5, "band": "critical", "vector": "ARCHON:1"},
    {"probe_name": "p1", "category": "encoding_evasion", "score": 7.2, "band": "high", "vector": "ARCHON:1"},
]


class TestSarifShape:
    def test_top_level_schema_keys(self):
        out = battle_report_to_sarif(_report(set(), FINDINGS))
        assert out["version"] == "2.1.0"
        assert "sarif-2.1.0" in out["$schema"]
        assert len(out["runs"]) == 1
        run = out["runs"][0]
        assert run["tool"]["driver"]["name"] == "archon"

    def test_only_unblocked_probes_become_results(self):
        out = battle_report_to_sarif(_report({"p0", "p1"}, FINDINGS))
        results = out["runs"][0]["results"]
        assert {r["ruleId"] for r in results} == {"owasp_llm_01/p2", "encoding_evasion/p3"}
        # blocked probes excluded
        all_ids = json.dumps(out)
        assert "/p0\"" not in all_ids.replace("p10", "")

    def test_level_mapping_from_severity_bands(self):
        out = battle_report_to_sarif(_report(set(), FINDINGS))
        by_rule = {r["ruleId"]: r for r in out["runs"][0]["results"]}
        assert by_rule["owasp_llm_01/p0"]["level"] == "error"  # critical
        assert by_rule["encoding_evasion/p1"]["level"] == "error"  # high

    def test_medium_low_note_levels(self):
        findings = [
            {"probe_name": "p0", "category": "c", "score": 5.0, "band": "medium", "vector": "v"},
            {"probe_name": "p1", "category": "c", "score": 2.0, "band": "low", "vector": "v"},
        ]
        out = battle_report_to_sarif(_report(set(), findings))
        levels = {r["ruleId"]: r["level"] for r in out["runs"][0]["results"]}
        assert levels["owasp_llm_01/p0"] == "warning"
        assert levels["encoding_evasion/p1"] == "note"

    def test_missing_severity_falls_back_to_warning(self):
        out = battle_report_to_sarif(_report(set()))
        assert all(r["level"] == "warning" for r in out["runs"][0]["results"])

    def test_fingerprint_stable(self):
        a = battle_report_to_sarif(_report(set(), FINDINGS))
        b = battle_report_to_sarif(_report(set(), FINDINGS))
        fa = [r["properties"]["fingerprint"] for r in a["runs"][0]["results"]]
        fb = [r["properties"]["fingerprint"] for r in b["runs"][0]["results"]]
        assert fa == fb and all(len(f) == 16 for f in fa)

    def test_rules_deduped_per_category(self):
        out = battle_report_to_sarif(_report(set(), FINDINGS))
        rules = out["runs"][0]["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        assert len(ids) == len(set(ids))
        assert any(r["id"].startswith("owasp_llm_01") for r in rules)

    def test_empty_report_zero_results(self):
        out = battle_report_to_sarif({"results": [], "summary": {"total_probes": 0, "blocked": 0, "block_rate": 0}})
        assert out["runs"][0]["results"] == []

    def test_json_roundtrip(self):
        out = battle_report_to_sarif(_report(set(), FINDINGS))
        assert json.loads(json.dumps(out)) == out


class TestRender:
    def test_render_writes_file(self, tmp_path):
        path = tmp_path / "out.sarif"
        render_sarif(_report(set(), FINDINGS), str(path))
        data = json.loads(path.read_text())
        assert data["version"] == "2.1.0"

    def test_agent_id_in_run_properties(self):
        report = _report(set(), FINDINGS)
        report["agent_id"] = "agent-x"
        out = battle_report_to_sarif(report)
        assert out["runs"][0].get("properties", {}).get("agent_id") == "agent-x"
