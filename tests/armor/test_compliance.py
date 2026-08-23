"""TDD P1.3: compliance evidence reports (HTML + Markdown)."""

import json

import pytest

from archon_core.reporting.compliance import (
    OWASP_LLM_CONTROLS,
    render_html_report,
    render_markdown_report,
)


SAMPLE_SUMMARY = {
    "agent_id": "support-agent",
    "battle_id": "b-123",
    "total_probes": 8,
    "blocked": 7,
    "block_rate": 0.875,
    "control_passed": True,
    "coverage": {
        "LLM01_prompt_injection": {"probes": 4, "blocked": 4},
        "LLM02_sensitive_disclosure": {"probes": 2, "blocked": 2},
        "LLM07_system_prompt_leakage": {"probes": 1, "blocked": 0},
        "benign": {"probes": 1, "blocked": 0},
    },
}

SEVERITY_SUMMARY = {
    **SAMPLE_SUMMARY,
    "severity": {
        "findings": [
            {
                "probe_name": "llm07_first_message_recall",
                "category": "owasp_llm_07",
                "execution_mode": "standard",
                "score": 8.5,
                "band": "high",
                "vector": "ARCHON:1/CAT:owasp_llm_07/EXP:standard/EV:none",
            }
        ],
        "max_score": 8.5,
        "bands": {"high": 1},
    },
}


class TestHtmlReport:
    def test_contains_summary_and_coverage(self):
        html = render_html_report(SAMPLE_SUMMARY)
        assert "support-agent" in html
        assert "87.5%" in html or "0.875" in html
        assert "LLM01_prompt_injection" in html

    def test_maps_categories_to_owasp_controls(self):
        html = render_html_report(SAMPLE_SUMMARY)
        for category in ("LLM01_prompt_injection", "LLM07_system_prompt_leakage"):
            control_text = OWASP_LLM_CONTROLS[category]["control"]
            assert control_text[:40] in html

    def test_failed_category_is_flagged(self):
        html = render_html_report(SAMPLE_SUMMARY)
        # LLM07 blocked 0/1 → must be marked as failing/open
        assert "open" in html.lower() or "fail" in html.lower()

    def test_escapes_agent_supplied_strings(self):
        summary = {**SAMPLE_SUMMARY, "agent_id": "<script>x</script>"}
        html = render_html_report(summary)
        assert "<script>" not in html


class TestMarkdownReport:
    def test_renders_table_and_controls(self):
        md = render_markdown_report(SAMPLE_SUMMARY)
        assert "| LLM01_prompt_injection |" in md
        assert "OWASP" in md.upper()
        assert "support-agent" in md

    def test_control_map_covers_all_owasp_categories(self):
        for cat in ("LLM01_prompt_injection", "LLM02_sensitive_disclosure",
                    "LLM07_system_prompt_leakage"):
            assert cat in OWASP_LLM_CONTROLS
            assert OWASP_LLM_CONTROLS[cat]["control"]


class TestSeveritySection:
    def test_markdown_includes_severity_when_present(self):
        md = render_markdown_report(SEVERITY_SUMMARY)
        assert "Severity" in md
        assert "8.5" in md
        assert "ARCHON:1/CAT:owasp_llm_07/EXP:standard/EV:none" in md

    def test_html_includes_severity_when_present(self):
        html = render_html_report(SEVERITY_SUMMARY)
        assert "Severity" in html
        assert "high" in html.lower()
        assert "ARCHON:1/CAT:owasp_llm_07" in html

    def test_renders_gracefully_without_severity(self):
        # Older battle summaries predate the severity block.
        md = render_markdown_report(SAMPLE_SUMMARY)
        html = render_html_report(SAMPLE_SUMMARY)
        assert "Severity" not in md
        assert "Severity" not in html


def test_cli_report_writes_html_file(tmp_path):
    from archon_cli.main import main

    src = tmp_path / "summary.json"
    src.write_text(json.dumps(SAMPLE_SUMMARY))
    out = tmp_path / "report.html"
    rc = main(["report", "--battle-json", str(src), "--format", "html",
               "--out", str(out)])
    assert rc == 0
    html = out.read_text()
    assert "Archon Security Evidence Report" in html
    assert "LLM01_prompt_injection" in html
