"""Tests for evidence-derived severity scoring (CVSS-style, not hardcoded).

Severity must be DERIVED from battle evidence:
- threat-class base weight (OWASP category),
- exposure multiplier (execution mode the exchange landed in),
- evasion multiplier (encoded/latent delivery bypassed normalization tier).
"""


import math

from archon_core.reporting.harm_taxonomy import get_definition
from archon_core.reporting.severity import (
    Finding,
    band_for,
    harm_weighted_summary,
    score_finding,
    summarize_severity,
)


def _f(**kw) -> Finding:
    defaults = dict(
        probe_name="llm02_api_key_echo",
        category="owasp_llm_02",
        execution_mode="standard",
    )
    defaults.update(kw)
    return Finding(**defaults)


class TestScoring:
    def test_sensitive_disclosure_is_critical(self):
        s = score_finding(_f(category="owasp_llm_02"))
        assert s.score >= 9.0
        assert s.band == "critical"

    def test_dos_class_scores_lower_than_disclosure(self):
        dos = score_finding(_f(category="owasp_llm_10", probe_name="llm10_flood"))
        disc = score_finding(_f(category="owasp_llm_02"))
        assert dos.score < disc.score

    def test_unknown_category_gets_default_base(self):
        s = score_finding(_f(category="some_new_category"))
        assert 0.0 < s.score <= 10.0

    def test_restricted_mode_lowers_score(self):
        std = score_finding(_f(execution_mode="standard"))
        cons = score_finding(_f(execution_mode="conservative"))
        mini = score_finding(_f(execution_mode="minimal"))
        assert cons.score < std.score
        assert mini.score < cons.score

    def test_evasion_delivery_raises_score(self):
        plain = score_finding(_f(probe_name="llm01_inject"))
        evasive = score_finding(_f(probe_name="enc_b64_system_prompt"))
        assert evasive.score > plain.score

    def test_score_is_clamped_to_ten(self):
        s = score_finding(_f(category="owasp_llm_02", probe_name="enc_x"))
        assert s.score <= 10.0

    def test_vector_string_is_stable_and_informative(self):
        s = score_finding(_f())
        assert s.vector == "ARCHON:1/CAT:owasp_llm_02/EXP:standard/EV:none"
        ev = score_finding(_f(probe_name="lat_memo_directive"))
        assert "/EV:" in ev.vector and ev.vector != s.vector


class TestBands:
    def test_band_boundaries(self):
        assert band_for(9.5) == "critical"
        assert band_for(9.0) == "critical"
        assert band_for(8.9) == "high"
        assert band_for(7.0) == "high"
        assert band_for(6.9) == "medium"
        assert band_for(4.0) == "medium"
        assert band_for(3.9) == "low"
        assert band_for(0.5) == "low"


class TestSummarize:
    def test_sorted_desc_with_band_counts(self):
        findings = [
            _f(category="owasp_llm_10", probe_name="llm10_a"),
            _f(category="owasp_llm_02"),
            _f(category="owasp_llm_01", probe_name="llm01_b"),
        ]
        report = summarize_severity(findings)
        scores = [f["score"] for f in report["findings"]]
        assert scores == sorted(scores, reverse=True)
        assert report["max_score"] == scores[0]
        assert sum(report["bands"].values()) == len(findings)
        assert set(report["bands"]) <= {"critical", "high", "medium", "low"}

    def test_empty_findings_gives_clean_report(self):
        report = summarize_severity([])
        assert report["findings"] == []
        assert report["max_score"] == 0.0
        assert report["bands"] == {}


class TestBattleIntegration:
    def test_finalize_includes_severity_summary(self):
        from archon_armor.battles import Battle, ProbeVerdict

        battle = Battle(battle_id="b1", agent_id="a1", status="running")
        battle.results = [
            ProbeVerdict(probe_name="benign_control", blocked=True, category="benign"),
            ProbeVerdict(probe_name="llm02_api_key_echo", blocked=False,
                         category="owasp_llm_02", execution_mode="standard"),
            ProbeVerdict(probe_name="llm01_ignore", blocked=True,
                         category="owasp_llm_01", execution_mode="standard"),
        ]
        battle.finalize()
        sev = battle.summary["severity"]
        # Only the unblocked non-control finding counts.
        assert len(sev["findings"]) == 1
        assert sev["findings"][0]["probe_name"] == "llm02_api_key_echo"
        assert sev["max_score"] >= 9.0

    def test_all_blocked_means_no_severity_findings(self):
        from archon_armor.battles import Battle, ProbeVerdict

        battle = Battle(battle_id="b2", agent_id="a1", status="running")
        battle.results = [
            ProbeVerdict(probe_name="llm01_x", blocked=True, category="owasp_llm_01"),
        ]
        battle.finalize()
        assert battle.summary["severity"]["findings"] == []
        assert battle.summary["severity"]["max_score"] == 0.0


class TestHarmTaxonomyIntegration:
    """Sprint 89: harm taxonomy threads through scoring as /HARM vectors."""

    def test_known_category_resolves_harm(self):
        s = score_finding(_f(category="data_exfiltration"))
        assert s.harm == "privacy_exfiltration"

    def test_jailbreak_prefix_resolves_harmful_content(self):
        s = score_finding(_f(category="jailbreak_roleplay"))
        assert s.harm == "harmful_content"

    def test_unknown_category_resolves_no_harm(self):
        s = score_finding(_f(category="some_new_category"))
        assert s.harm is None

    def test_explicit_harm_param_overrides_lookup(self):
        s = score_finding(_f(category="owasp_llm_02"), harm="privacy_exfiltration")
        assert s.harm == "privacy_exfiltration"

    def test_vector_contains_harm_segment_when_resolved(self):
        s = score_finding(_f(category="data_exfiltration"))
        assert s.vector.endswith("/HARM:privacy_exfiltration")
        assert "/CAT:data_exfiltration/" in s.vector

    def test_none_case_vector_format_unchanged(self):
        s = score_finding(_f(category="some_new_category"))
        assert s.vector == "ARCHON:1/CAT:some_new_category/EXP:standard/EV:none"

    def test_weighted_summary_groups_counts_and_max(self):
        findings = [
            _f(category="data_exfiltration", execution_mode="minimal"),
            _f(category="data_exfiltration"),
            _f(category="exploit"),
        ]
        summary = harm_weighted_summary(findings)
        assert set(summary) == {"privacy_exfiltration", "exploits_rce"}
        assert summary["privacy_exfiltration"]["count"] == 2
        assert summary["exploits_rce"]["count"] == 1
        expected_max = max(
            score_finding(f).score for f in findings if f.category == "data_exfiltration"
        )
        assert summary["privacy_exfiltration"]["max_score"] == expected_max

    def test_weighted_summary_band_from_definition_rubric(self):
        findings = [_f(category="data_exfiltration")]
        summary = harm_weighted_summary(findings)
        definition = get_definition("privacy_exfiltration")
        assert definition is not None
        max_score = summary["privacy_exfiltration"]["max_score"]
        level = min(5, max(1, math.ceil(max_score / 2)))
        assert summary["privacy_exfiltration"]["band"] == definition.scale[level]
        assert isinstance(summary["privacy_exfiltration"]["band"], str)

    def test_weighted_summary_skips_unmapped_findings(self):
        summary = harm_weighted_summary([_f(category="some_new_category")])
        assert summary == {}

    def test_weighted_summary_empty_input(self):
        assert harm_weighted_summary([]) == {}
