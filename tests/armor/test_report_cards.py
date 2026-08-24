"""Tests for compliance-card rendering (ROADMAP item 89).

promptfoo FrameworkCompliance pattern: per-framework cards with pass-rate
bars, rendered as an HTML fragment for the Web UI.
"""

from __future__ import annotations

from archon_armor.report_cards import render_cards_page, render_compliance_cards


def _report(coverage: dict | None = None, severity: dict | None = None) -> dict:
    summary: dict = {"block_rate": 0.8}
    if coverage is not None:
        summary["coverage"] = coverage
    if severity is not None:
        summary["severity"] = severity
    return {"results": [], "summary": summary}


COVERAGE = {
    "owasp_llm_01": {"probes": 10, "blocked": 9},
    "owasp_llm_02": {"probes": 10, "blocked": 5},
}


class TestComplianceCards:
    def test_fragment_renders_owasp_card(self):
        html = render_compliance_cards(_report(COVERAGE))
        assert "OWASP" in html
        assert "90%" in html  # llm_01 pass rate
        assert "50%" in html  # llm_02 pass rate

    def test_pass_rate_math(self):
        html = render_compliance_cards(
            _report({"owasp_llm_01": {"probes": 3, "blocked": 1}})
        )
        assert "33%" in html

    def test_bar_color_thresholds(self):
        good = render_compliance_cards(_report({"owasp_llm_01": {"probes": 10, "blocked": 10}}))
        mid = render_compliance_cards(_report({"owasp_llm_01": {"probes": 10, "blocked": 8}}))
        bad = render_compliance_cards(_report({"owasp_llm_01": {"probes": 10, "blocked": 2}}))
        assert "#22c55e" in good  # >=90 green
        assert "#eab308" in mid  # >=70 yellow
        assert "#ef4444" in bad  # below red

    def test_regulation_cards_present_when_evidence_signals(self):
        sev = {"findings": [{"probe_name": "x", "category": "c", "score": 9.0, "band": "critical", "vector": "v"}]}
        html = render_compliance_cards(_report(COVERAGE, severity=sev))
        assert "EU AI Act" in html
        assert "NIST" in html

    def test_no_severity_means_no_regulation_cards(self):
        html = render_compliance_cards(_report(COVERAGE))
        assert "EU AI Act" not in html

    def test_dynamic_text_escaped(self):
        cov = {"owasp_llm_01<script>alert(1)</script>": {"probes": 1, "blocked": 1}}
        html = render_compliance_cards(_report(cov))
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_empty_coverage_zero_state(self):
        html = render_compliance_cards(_report({}))
        assert "No coverage data" in html or "OWASP" not in html.split("</div>")[0]

    def test_deterministic(self):
        a = render_compliance_cards(_report(COVERAGE))
        b = render_compliance_cards(_report(COVERAGE))
        assert a == b

    def test_page_wrapper_contains_fragment(self):
        page = render_cards_page(_report(COVERAGE))
        frag = render_compliance_cards(_report(COVERAGE))
        assert "<html" in page.lower()
        assert frag in page
