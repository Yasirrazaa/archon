"""Sprint E3-68: property-tagged metrics (SA/TA/AA/DI).

Source: arXiv:2607.22024 (ICML 2026 position, Dawn Song group) — four joint
properties evaluated continuously: Source Authorization (SA), Task Alignment
(TA), Action Alignment (AA), Data Isolation (DI).
"""

from archon_core.reporting.property_tags import (
    CLASSIFIER_RULES,
    PropertyTag,
    classify_property,
    render_property_breakdown,
    summarize_by_property,
    tag_findings,
)


class TestPropertyTagEnum:
    def test_enum_has_four_members(self):
        assert {t.name for t in PropertyTag} == {"SA", "TA", "AA", "DI"}

    def test_enum_docstrings_cite_lineage(self):
        lineage = {
            "SA": ("confused deputy", "authentication"),
            "TA": ("least privilege", "authorization policy"),
            "AA": ("reference monitor", "control-flow integrity"),
            "DI": ("IFC", "noninterference"),
        }
        for name, keywords in lineage.items():
            doc = getattr(PropertyTag, name).__doc__ or ""
            for kw in keywords:
                assert kw.lower() in doc.lower(), f"{name} docstring missing '{kw}'"


class TestClassifyProperty:
    def test_sa_family(self):
        for cat in (
            "indirect_injection",
            "latent_injection",
            "mcp",
            "tool_poisoning",
            "supply_chain",
        ):
            assert classify_property(cat) == PropertyTag.SA, cat

    def test_ta_family(self):
        for cat in (
            "jailbreak",
            "jailbreak_persona",
            "harmbench",
            "direct_injection",
            "goal_hijack",
        ):
            assert classify_property(cat) == PropertyTag.TA, cat

    def test_aa_family(self):
        for cat in (
            "destructive",
            "code_exec",
            "sandbox_escape",
            "rce",
            "excessive_agency",
        ):
            assert classify_property(cat) == PropertyTag.AA, cat

    def test_di_family(self):
        for cat in (
            "memory_poisoning",
            "data_exfiltration",
            "exfil",
            "stego",
            "covert_channel",
            "session",
        ):
            assert classify_property(cat) == PropertyTag.DI, cat

    def test_unknown_returns_none(self):
        assert classify_property("totally_unheard_of") is None
        assert classify_property("") is None

    def test_case_insensitive(self):
        assert classify_property("Tool_Poisoning") == PropertyTag.SA
        assert classify_property("JAILBREAK_PERSONA") == PropertyTag.TA
        assert classify_property("Sandbox-Escape") == PropertyTag.AA
        assert classify_property("Data_Exfiltration") == PropertyTag.DI

    def test_longest_match_precedence(self):
        # Rules must be ordered longest-pattern-first.
        lengths = [len(p) for p, _ in CLASSIFIER_RULES]
        assert lengths == sorted(lengths, reverse=True)
        # 'indirect_injection' (SA) must win over the shorter injection-family
        # patterns rather than being shadowed by them.
        assert classify_property("indirect_injection") == PropertyTag.SA
        # A compound probe whose name embeds two rule categories resolves to
        # the longest matching pattern.
        assert classify_property("memory_poisoning_via_session") == PropertyTag.DI

    def test_substring_match_inside_compound_category(self):
        assert classify_property("custom_mcp_probe") == PropertyTag.SA
        assert classify_property("post_jailbreak_variant") == PropertyTag.TA


class TestTagFindings:
    def test_adds_property_key(self):
        findings = [{"category": "tool_poisoning", "severity": 5}]
        tagged = tag_findings(findings)
        assert tagged[0]["property"] == PropertyTag.SA
        assert tagged[0]["severity"] == 5

    def test_purity_input_unchanged(self):
        findings = [
            {"category": "rce"},
            {"category": "unknown_thing"},
            {"category": "exfil"},
        ]
        snapshot = [dict(f) for f in findings]
        tagged = tag_findings(findings)
        assert findings == snapshot
        assert all("property" not in f for f in findings)
        assert [f["property"] for f in tagged] == [
            PropertyTag.AA,
            None,
            PropertyTag.DI,
        ]

    def test_empty_list(self):
        assert tag_findings([]) == []


class TestSummarizeByProperty:
    def test_counts_tagged_and_untagged(self):
        findings = [
            {"category": "tool_poisoning"},
            {"category": "tool_poisoning"},
            {"category": "rce"},
            {"category": "mystery"},
        ]
        summary = summarize_by_property(tag_findings(findings))
        assert summary["tagged"] == 3
        assert summary["untagged"] == 1

    def test_by_property_sorted_desc(self):
        findings = [
            {"category": "tool_poisoning"},
            {"category": "mcp"},
            {"category": "rce"},
            {"category": "exfil"},
        ]
        summary = summarize_by_property(tag_findings(findings))
        counts = list(summary["by_property"].values())
        assert counts == sorted(counts, reverse=True)
        assert summary["by_property"][PropertyTag.SA.value] == 2

    def test_empty_input(self):
        summary = summarize_by_property([])
        assert summary["tagged"] == 0
        assert summary["untagged"] == 0
        assert summary["by_property"] == {}


class TestRenderPropertyBreakdown:
    def test_contains_header_all_properties_and_untagged(self):
        findings = [
            {"category": "tool_poisoning"},
            {"category": "rce"},
            {"category": "weird"},
        ]
        rendered = render_property_breakdown(
            summarize_by_property(tag_findings(findings))
        )
        assert "| Property | Findings |" in rendered
        for prop in ("SA", "TA", "AA", "DI"):
            assert prop in rendered
        assert "Untagged" in rendered
        assert "| Untagged | 1 |" in rendered
        assert "| SA | 1 |" in rendered
