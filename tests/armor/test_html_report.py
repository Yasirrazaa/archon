"""TDD Sprint 79: static self-contained HTML battle report."""

import pytest
from archon_armor.html_report import render_battle_html, write_battle_html

SAMPLE_REPORT = {
    "agent_id": "support-agent",
    "total_probes": 4,
    "blocked": 3,
    "block_rate": 0.75,
    "control_passed": True,
    "generated_at": "2026-08-24T12:00:00+00:00",
    "coverage": {
        "prompt_injection": {"probes": 3, "blocked": 3},
        "benign": {"probes": 1, "blocked": 0},
    },
    "results": [
        {
            "probe_name": "injection_basic",
            "category": "prompt_injection",
            "blocked": True,
            "block_reason": "threat_category",
        },
        {
            "probe_name": "<script>alert('x')</script>",
            "category": "benign",
            "blocked": False,
            "block_reason": None,
        },
    ],
}

SEVERITY = {
    "findings": [
        {
            "probe_name": "leak_probe",
            "category": "owasp_llm_07",
            "score": 8.5,
            "band": "high",
            "vector": "ARCHON:1/CAT:owasp_llm_07/EV:none",
        }
    ],
    "max_score": 8.5,
    "bands": {"high": 1},
}


class TestRenderBattleHtml:
    def test_doctype_and_style_present(self):
        out = render_battle_html(SAMPLE_REPORT)
        assert out.lstrip().lower().startswith("<!doctype html>")
        assert "<style>" in out

    def test_no_external_assets(self):
        out = render_battle_html(SAMPLE_REPORT)
        assert 'src="http' not in out
        assert "href='http" not in out
        assert 'href="http' not in out

    def test_dynamic_text_is_escaped(self):
        out = render_battle_html(SAMPLE_REPORT)
        assert "&lt;script&gt;" in out
        assert "<script>alert(" not in out

    def test_block_rate_rendered(self):
        out = render_battle_html(SAMPLE_REPORT)
        assert "75.0%" in out

    def test_header_fields(self):
        out = render_battle_html(SAMPLE_REPORT)
        assert "support-agent" in out
        assert "2026-08-24T12:00:00" in out
        assert "UTC" in out

    def test_agent_id_kwarg_overrides(self):
        out = render_battle_html(SAMPLE_REPORT, agent_id="other-agent")
        assert "other-agent" in out
        assert "support-agent" not in out

    def test_summary_cards_present(self):
        out = render_battle_html(SAMPLE_REPORT)
        assert ">4<" in out  # total
        assert ">3<" in out  # blocked

    def test_severity_rows_only_when_findings_exist(self):
        without = render_battle_html({**SAMPLE_REPORT, "severity": SEVERITY})
        assert "leak_probe" in without
        assert "high" in without.lower()
        empty_bands = render_battle_html(
            {**SAMPLE_REPORT, "severity": {"findings": [], "max_score": 0.0, "bands": {}}}
        )
        assert "leak_probe" not in empty_bands

    def test_per_category_table(self):
        out = render_battle_html(SAMPLE_REPORT)
        assert "prompt_injection" in out
        assert "benign" in out

    def test_full_verdict_table_with_checkmark(self):
        out = render_battle_html(SAMPLE_REPORT)
        assert "injection_basic" in out
        assert "&#10003;" in out or "\u2713" in out
        assert "threat_category" in out

    def test_empty_report_renders_gracefully(self):
        out = render_battle_html(
            {
                "agent_id": "empty-agent",
                "total_probes": 0,
                "blocked": 0,
                "block_rate": 0.0,
                "control_passed": True,
            }
        )
        assert "empty-agent" in out
        assert "0.0%" in out

    def test_deterministic_output(self):
        assert render_battle_html(SAMPLE_REPORT) == render_battle_html(SAMPLE_REPORT)


class TestWriteBattleHtml:
    def test_write_helper_creates_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = write_battle_html(SAMPLE_REPORT, tmp_path / "report.html")
        assert path == tmp_path / "report.html"
        assert path.exists()
        assert path.read_text() == render_battle_html(SAMPLE_REPORT)


@pytest.mark.parametrize(
    "report",
    [
        {},
        {"agent_id": None, "results": [{"probe_name": "x", "blocked": None}]},
    ],
    ids=["bare-empty", "missing-fields"],
)
def test_missing_optional_fields_render(report):
    out = render_battle_html(report)
    assert "<!DOCTYPE html>" in out.lower() or "<!doctype html>" in out.lower()


CARDS_COVERAGE = {
    "owasp_llm_01": {"probes": 4, "blocked": 4},
    "owasp_llm_07": {"probes": 2, "blocked": 1},
}

CARDS_REPORT = {
    **SAMPLE_REPORT,
    "coverage": CARDS_COVERAGE,
    "severity": SEVERITY,
}


class TestComplianceCardsSection:
    def test_cards_section_present_with_findings(self):
        out = render_battle_html(CARDS_REPORT)
        assert "<section id='compliance-cards'>" in out
        assert "</section>" in out
        assert "OWASP LLM Top 10" in out

    def test_owasp_bar_markup_present(self):
        out = render_battle_html(CARDS_REPORT)
        assert "width:100%;height:10px" in out
        assert ">50%</div>" in out  # owasp_llm_07 = 1/2 blocked

    def test_regulation_cards_when_findings(self):
        out = render_battle_html(CARDS_REPORT)
        assert "EU AI Act" in out
        assert "NIST AI RMF" in out

    def test_cards_section_absent_without_findings(self):
        empty_findings = {
            **SAMPLE_REPORT,
            "severity": {"findings": [], "max_score": 0.0, "bands": {}},
        }
        assert "<section id='compliance-cards'>" not in render_battle_html(empty_findings)

    def test_cards_section_absent_without_severity(self):
        assert "<section id='compliance-cards'>" not in render_battle_html(SAMPLE_REPORT)

    def test_cards_section_after_severity_table(self):
        out = render_battle_html(CARDS_REPORT)
        severity_pos = out.index("<h2>Severity</h2>")
        verdicts_pos = out.index("<h2>Probe verdicts</h2>")
        cards_pos = out.index("<section id='compliance-cards'>")
        assert severity_pos < cards_pos < verdicts_pos

    def test_agent_id_still_escaped_with_cards(self):
        hostile = {**CARDS_REPORT, "agent_id": "<script>alert('a')</script>"}
        out = render_battle_html(hostile)
        assert "&lt;script&gt;" in out
        assert "<script>alert('a')</script>" not in out
