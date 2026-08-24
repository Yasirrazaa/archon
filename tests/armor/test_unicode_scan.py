"""Tests for hidden-Unicode tag-char scanner (W021)."""

from archon_core.security.unicode_scan import (
    UnicodeFinding,
    decode_tag_sequence,
    decode_zero_width_binary,
    scan_content,
    scan_unicode,
    severity,
)


class TestCleanText:
    def test_clean_text_has_no_findings(self):
        result = scan_content("Hello, world! Plain ASCII text.")
        assert result["clean"] is True
        assert result["findings"] == []
        assert result["max_severity"] is None
        assert result["decoded_hidden"] is None


class TestCategoryDetection:
    def test_zero_width_space_detected(self):
        findings = scan_unicode("a\u200bb")
        assert len(findings) == 1
        assert findings[0].category == "zero_width"
        assert findings[0].codepoint == "200B"
        assert findings[0].position == 1

    def test_bidi_override_detected(self):
        findings = scan_unicode("\u202esneaky")
        assert len(findings) == 1
        assert findings[0].category == "bidi"
        assert findings[0].codepoint == "202E"

    def test_tag_char_detected(self):
        findings = scan_unicode("\U000E0041")
        assert len(findings) == 1
        assert findings[0].category == "tag"
        assert findings[0].codepoint == "E0041"

    def test_variation_selector_detected(self):
        findings = scan_unicode("e\uFE0F")
        assert len(findings) == 1
        assert findings[0].category == "variation_selector"

    def test_soft_hyphen_detected(self):
        findings = scan_unicode("invis\u00ADible")
        assert len(findings) == 1
        assert findings[0].category == "format"
        assert findings[0].codepoint == "00AD"

    def test_control_char_detected_but_tab_newline_cr_allowed(self):
        findings = scan_unicode("a\x00b\tc\nd\r e")
        assert len(findings) == 1
        assert findings[0].category == "control"
        assert findings[0].char == "\x00"


class TestDecoding:
    def test_tag_sequence_decodes_archon(self):
        text = "".join(chr(0xE0000 + ord(c)) for c in "ARCHON")
        assert decode_tag_sequence(f"x{text}y") == "ARCHON"

    def test_decode_tag_sequence_none_when_absent(self):
        assert decode_tag_sequence("no tags here") is None

    def test_zero_width_binary_decodes_known_byte(self):
        # 01000001 = 'A': ZWSP=0, ZWNJ=1
        bits = "\u200b\u200c\u200b\u200b\u200b\u200b\u200b\u200c"
        assert decode_zero_width_binary(bits) == "A"

    def test_decode_zero_width_binary_none_when_too_few_chars(self):
        assert decode_zero_width_binary("\u200b\u200c\u200b") is None


class TestSeverity:
    def test_severity_mapping(self):
        def make(category: str) -> UnicodeFinding:
            return UnicodeFinding(
                char="\u200b", codepoint="200B", category=category, position=0, decoded=None
            )

        assert severity(make("tag")) == "high"
        assert severity(make("bidi")) == "high"
        assert severity(make("zero_width")) == "medium"
        assert severity(make("variation_selector")) == "medium"
        assert severity(make("control")) == "low"
        assert severity(make("format")) == "low"


class TestScanContent:
    def test_max_severity_aggregation_takes_highest(self):
        result = scan_content("a\u00ADb\u200bc")
        assert result["clean"] is False
        severities = [severity(f) for f in result["findings"]]
        assert "medium" in severities and "low" in severities
        assert result["max_severity"] == "medium"

    def test_findings_sorted_by_position(self):
        result = scan_content("\uFE0Fa\u202eb\u200bc")
        positions = [f.position for f in result["findings"]]
        assert positions == sorted(positions)
        assert [f.codepoint for f in result["findings"]] == ["FE0F", "202E", "200B"]

    def test_scan_content_shape_with_decoded_hidden(self):
        tag_msg = "".join(chr(0xE0000 + ord(c)) for c in "ARCHON")
        result = scan_content(f"prefix {tag_msg}")
        assert result["clean"] is False
        assert result["max_severity"] == "high"
        assert result["decoded_hidden"] == "ARCHON"
        assert all(isinstance(f, UnicodeFinding) for f in result["findings"])

    def test_decoded_hidden_prefers_tag_over_zero_width(self):
        tag_msg = "".join(chr(0xE0000 + ord(c)) for c in "TAG")
        zw_bits = "\u200b\u200c\u200b\u200b\u200b\u200b\u200b\u200c"
        result = scan_content(tag_msg + zw_bits)
        assert result["decoded_hidden"] == "TAG"
